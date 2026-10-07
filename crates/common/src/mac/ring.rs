//! A generic SPDZ-style engine for arithmetic MACs, instantiated by
//! [`super::z2k`] (SPDZ2k over Z_2^k) and [`super::fp`] (SPDZ over F_p).
//!
//! Each party holds a MAC-key share `α_b`. An authenticated value `[x]` is
//! `(x_b, m_b)` with `Σ m_b = x·α` in the MAC ring R (Z_2^{k+s} or F_p).
//!
//! * [`ArithMacParty::authenticate`] turns additive shares into
//!   authenticated shares with an OT-based VOLE: the cross terms `x_b·α_{1−b}` are
//!   Gilboa products, one KOS-checked COT per bit of `x_b`. An extra random value
//!   is authenticated in the same batch, and a random linear combination of the
//!   batch is opened and recorded for the MAC check (the MASCOT/SPDZ2k
//!   consistency check against a sender that uses inconsistent α's).
//! * [`ArithMacParty::open`] opens without checking and records the opening;
//!   [`ArithMacParty::check`] verifies every recorded opening at once.
//!
//! For SPDZ2k, `open` reveals only the low k bits, and the check masks the
//! combined value with `2^k·[r]`, as in Cramer et al. (CRYPTO'18), Fig. 9/10.

use crate::block::Block;
use crate::coin::{coin_block, commit_and_open, Abort};
use crate::hash::{cot_hash, CtrPrg};
use crate::net::Channel;
use crate::ot::CotPair;
use rand::{CryptoRng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;

/// The algebra behind an arithmetic MAC scheme.
pub trait MacRing: Copy + Eq + std::fmt::Debug + Default + Send + Sync + 'static {
    /// Reduces a 128-bit integer into the ring.
    fn from_u128(x: u128) -> Self;
    /// Canonical representative.
    fn to_u128(self) -> u128;
    fn add(self, o: Self) -> Self;
    fn sub(self, o: Self) -> Self;
    fn mul(self, o: Self) -> Self;
    fn neg(self) -> Self {
        Self::from_u128(0).sub(self)
    }
    /// Uniform element.
    fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let mut b = [0u8; 16];
        rng.fill_bytes(&mut b);
        Self::from_u128(u128::from_le_bytes(b))
    }
    /// A MAC-key share (`α_b ∈ Z_2^s` for SPDZ2k, F_p for SPDZ).
    fn random_key<R: RngCore + CryptoRng>(rng: &mut R) -> Self;
    /// A check coefficient from 128 random bits (`Z_2^s` / F_p).
    fn chi(x: u128) -> Self;
    /// Bits needed to write a share as `Σ x_i 2^i` for the VOLE.
    fn share_bits() -> usize;
    /// What `open` reveals of a value (the low k bits for SPDZ2k).
    fn opened(x: Self) -> Self;
    /// The masking weight `2^k` of the SPDZ2k check, `None` for fields.
    fn check_mask() -> Option<Self>;
    fn pow2(i: usize) -> Self {
        Self::from_u128(1u128 << i)
    }
}

/// An authenticated share `(x_b, m_b)`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Auth<R: MacRing> {
    pub x: R,
    pub m: R,
}

impl<R: MacRing> Auth<R> {
    pub fn add(&self, o: &Self) -> Self {
        Auth { x: self.x.add(o.x), m: self.m.add(o.m) }
    }
    pub fn sub(&self, o: &Self) -> Self {
        Auth { x: self.x.sub(o.x), m: self.m.sub(o.m) }
    }
    /// `c·[x]` for a public `c`.
    pub fn scale(&self, c: R) -> Self {
        Auth { x: c.mul(self.x), m: c.mul(self.m) }
    }
    /// `[x] + c` for a public `c`: party 0 adds `c` to its share, both add `c·α_b`.
    pub fn add_const(&self, c: R, party: usize, key: R) -> Self {
        Auth { x: if party == 0 { self.x.add(c) } else { self.x }, m: self.m.add(c.mul(key)) }
    }
}

fn ring_bytes<R: MacRing>(v: &[R]) -> Vec<u8> {
    v.iter().flat_map(|x| x.to_u128().to_le_bytes()).collect()
}

fn ring_from_bytes<R: MacRing>(b: &[u8], n: usize) -> Result<Vec<R>, Abort> {
    if b.len() != 16 * n {
        return Err(Abort("malformed ring message"));
    }
    Ok(b.chunks_exact(16).map(|c| R::from_u128(u128::from_le_bytes(c.try_into().unwrap()))).collect())
}

/// One party's arithmetic-MAC engine.
pub struct ArithMacParty<R: MacRing> {
    pub party: usize,
    key: R,
    pub cot: CotPair,
    opened: Vec<(Auth<R>, R)>,
    tweak: u64,
    rng: ChaCha20Rng,
}

impl<R: MacRing> ArithMacParty<R> {
    /// Samples `α_b` and sets up KOS-checked COT in both directions.
    pub fn setup(ch: &mut Channel, seed: [u8; 32]) -> Self {
        let mut rng = ChaCha20Rng::from_seed(seed);
        let key = R::random_key(&mut rng);
        let cot_delta = Block::random(&mut rng);
        let cot = CotPair::setup(ch, &mut rng, cot_delta, true);
        ArithMacParty { party: ch.party(), key, cot, opened: Vec::new(), tweak: 0, rng }
    }

    /// `α_b`, this party's MAC-key share.
    pub fn key(&self) -> R {
        self.key
    }

    pub fn pending(&self) -> usize {
        self.opened.len()
    }

    /// Gilboa VOLE for the cross terms: returns this party's additive shares
    /// of `x_b·α_{1−b} + x_{1−b}·α_b` for every element. Two flights + KOS.
    fn vole(&mut self, ch: &mut Channel, mine: &[R]) -> Result<Vec<R>, Abort> {
        let nb = R::share_bits();
        let n = mine.len();
        let bits: Vec<bool> = mine.iter().flat_map(|x| (0..nb).map(move |i| (x.to_u128() >> i) & 1 == 1)).collect();
        let (k, m) = self.cot.extend(ch, &bits, n * nb, &mut self.rng)?;
        let delta = self.cot.delta();
        let h = cot_hash();
        let base = self.tweak;
        self.tweak += (n * nb) as u64;
        let pad = |x: Block, j: usize| R::from_u128(h.h(x, base + j as u64).0);

        // Sender for the peer's bits: d = H(K) − H(K⊕Δ) + α_b·2^i, own share −H(K).
        let mut out = vec![R::from_u128(0); n];
        let mut d = Vec::with_capacity(n * nb);
        for e in 0..n {
            for i in 0..nb {
                let j = e * nb + i;
                let m0 = pad(k[j], j);
                let m1 = pad(k[j] ^ delta, j);
                d.push(m0.sub(m1).add(self.key.mul(R::pow2(i))));
                out[e] = out[e].sub(m0);
            }
        }
        ch.send(ring_bytes(&d));
        // Receiver for own bits: H(M) + x_i·d_i.
        let theirs: Vec<R> = ring_from_bytes(&ch.recv(), n * nb)?;
        for e in 0..n {
            for i in 0..nb {
                let j = e * nb + i;
                let mut u = pad(m[j], j);
                if bits[j] {
                    u = u.add(theirs[j]);
                }
                out[e] = out[e].add(u);
            }
        }
        Ok(out)
    }

    /// Authenticates additively shared values. Both parties pass their shares;
    /// a value known to one party is shared as `(x, 0)`.
    pub fn authenticate(&mut self, ch: &mut Channel, mine: &[R]) -> Result<Vec<Auth<R>>, Abort> {
        let mut all = mine.to_vec();
        all.push(R::random(&mut self.rng));
        let cross = self.vole(ch, &all)?;
        let auth: Vec<Auth<R>> = all.iter().zip(&cross).map(|(x, c)| Auth { x: *x, m: x.mul(self.key).add(*c) }).collect();
        // Consistency: open Σ χ_j [x_j] + [x_extra] and record it for the check.
        let seed = coin_block(ch, &mut self.rng)?;
        let chi: Vec<R> = CtrPrg::new(seed).next_words(mine.len()).into_iter().map(R::chi).collect();
        let mut comb = *auth.last().unwrap();
        for (a, c) in auth.iter().zip(&chi) {
            comb = comb.add(&a.scale(*c));
        }
        self.open(ch, &[comb])?;
        Ok(auth[..mine.len()].to_vec())
    }

    /// `n` random authenticated values.
    pub fn rand(&mut self, ch: &mut Channel, n: usize) -> Result<Vec<Auth<R>>, Abort> {
        let mine: Vec<R> = (0..n).map(|_| R::random(&mut self.rng)).collect();
        self.authenticate(ch, &mine)
    }

    /// Opens without checking (for SPDZ2k, only the low k bits) and records each
    /// opening for [`check`](Self::check). One flight.
    pub fn open(&mut self, ch: &mut Channel, vals: &[Auth<R>]) -> Result<Vec<R>, Abort> {
        let mine: Vec<R> = vals.iter().map(|v| R::opened(v.x)).collect();
        ch.send(ring_bytes(&mine));
        let theirs: Vec<R> = ring_from_bytes(&ch.recv(), vals.len())?;
        let out: Vec<R> = mine.iter().zip(&theirs).map(|(a, b)| R::opened(a.add(*b))).collect();
        self.opened.extend(vals.iter().copied().zip(out.iter().copied()));
        Ok(out)
    }

    /// Batch MAC check over every recorded opening (ΠMACCheck). Clears the
    /// record.
    pub fn check(&mut self, ch: &mut Channel) -> Result<(), Abort> {
        let items = std::mem::take(&mut self.opened);
        let seed = coin_block(ch, &mut self.rng)?;
        let chi: Vec<R> = CtrPrg::new(seed).next_words(items.len()).into_iter().map(R::chi).collect();
        let zero = R::from_u128(0);
        let (mut y_pub, mut y, mut my) = (zero, zero, zero);
        for ((a, v), c) in items.iter().zip(&chi) {
            y_pub = y_pub.add(c.mul(*v));
            y = y.add(c.mul(a.x));
            my = my.add(c.mul(a.m));
        }
        let public = match R::check_mask() {
            None => y_pub,
            Some(w) => {
                // SPDZ2k: open y + 2^k·r in full and compare its low k bits.
                let r = self.rand_unchecked(ch)?;
                let mine = y.add(w.mul(r.x));
                ch.send(ring_bytes(&[mine]));
                let theirs: Vec<R> = ring_from_bytes(&ch.recv(), 1)?;
                let full = mine.add(theirs[0]);
                if R::opened(full) != R::opened(y_pub) {
                    return Err(Abort("MAC check failed"));
                }
                my = my.add(w.mul(r.m));
                full
            }
        };
        let z = my.sub(public.mul(self.key));
        let theirs = commit_and_open(ch, &z.to_u128().to_le_bytes(), &mut self.rng)?;
        let theirs = R::from_u128(u128::from_le_bytes(theirs.try_into().map_err(|_| Abort("malformed MAC share"))?));
        if z.add(theirs) != zero {
            return Err(Abort("MAC check failed"));
        }
        Ok(())
    }

    /// One random authenticated value whose own consistency opening is not
    /// recorded (it is the mask of the check itself).
    fn rand_unchecked(&mut self, ch: &mut Channel) -> Result<Auth<R>, Abort> {
        let x = R::random(&mut self.rng);
        let c = self.vole(ch, &[x])?;
        Ok(Auth { x, m: x.mul(self.key).add(c[0]) })
    }
}

/// Trusted-dealer helpers for tests and benchmarks.
pub mod dealer {
    use super::*;

    /// MAC-key shares `[α_0, α_1]`.
    pub fn keys<R: MacRing, G: RngCore + CryptoRng>(rng: &mut G) -> [R; 2] {
        [R::random_key(rng), R::random_key(rng)]
    }

    pub fn share<R: MacRing, G: RngCore + CryptoRng>(rng: &mut G, x: R, keys: [R; 2]) -> [Auth<R>; 2] {
        let x0 = R::random(rng);
        let m0 = R::random(rng);
        let m1 = x.mul(keys[0].add(keys[1])).sub(m0);
        [Auth { x: x0, m: m0 }, Auth { x: x.sub(x0), m: m1 }]
    }

    /// Reconstructs and checks the MAC.
    pub fn open<R: MacRing>(s: &[Auth<R>; 2], keys: [R; 2]) -> Option<R> {
        let x = s[0].x.add(s[1].x);
        (s[0].m.add(s[1].m) == x.mul(keys[0].add(keys[1]))).then_some(x)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::net::run_two_party;
    use rand::Rng;

    fn session<R: MacRing>(c: &mut Channel, seed: u8, xs: Vec<R>, tamper: bool) -> Result<Vec<R>, Abort> {
        let mut p = ArithMacParty::<R>::setup(c, [seed; 32]);
        let mut v = p.authenticate(c, &xs)?;
        let r = p.rand(c, 1)?[0];
        v.push(v[0].add(&r).scale(R::from_u128(5)).add_const(R::from_u128(3), p.party, p.key()));
        v.push(v[0].sub(&r));
        if tamper {
            v[0].x = v[0].x.add(R::from_u128(1));
        }
        let out = p.open(c, &v)?;
        p.check(c)?;
        Ok(out)
    }

    /// Honest runs open correctly and pass; a tampered share aborts both parties.
    pub(crate) fn engine_roundtrip<R: MacRing>() {
        let mut rng = ChaCha20Rng::seed_from_u64(3);
        let x: Vec<R> = (0..4).map(|_| R::opened(R::random(&mut rng))).collect();
        let x0: Vec<R> = (0..4).map(|_| R::random(&mut rng)).collect();
        let x1: Vec<R> = x.iter().zip(&x0).map(|(a, b)| a.sub(*b)).collect();
        let (a, b) = run_two_party(move |c| session(c, 1, x0, false), move |c| session(c, 2, x1, false));
        let (a, b) = (a.unwrap(), b.unwrap());
        assert_eq!(a, b);
        assert_eq!(&a[..4], &x[..]);

        let (a, b) = run_two_party(
            |c| session(c, 1, vec![R::from_u128(10)], true),
            |c| session(c, 2, vec![R::from_u128(20)], false),
        );
        assert_eq!(a, Err(Abort("MAC check failed")));
        assert_eq!(b, Err(Abort("MAC check failed")));
    }

    /// Dealer shares open and verify; linear operations keep MACs valid.
    pub(crate) fn dealer_algebra<R: MacRing>() {
        let mut rng = ChaCha20Rng::seed_from_u64(4);
        let keys = dealer::keys::<R, _>(&mut rng);
        for _ in 0..100 {
            let (x, y, c) = (R::random(&mut rng), R::random(&mut rng), R::random(&mut rng));
            let sx = dealer::share(&mut rng, x, keys);
            let sy = dealer::share(&mut rng, y, keys);
            let s = [0, 1].map(|b| sx[b].scale(c).add(&sy[b]).add_const(c, b, keys[b]));
            assert_eq!(dealer::open(&s, keys), Some(c.mul(x).add(y).add(c)));
            let mut bad = s;
            bad[rng.gen_range(0..2)].x = bad[0].x.add(R::from_u128(1));
            assert_eq!(dealer::open(&bad, keys), None);
        }
    }
}
