//! Authenticated secret sharing over F_2 and F_2^128 (ZGY+24 §3.3).
//!
//! Every party `P_b` holds a global MAC key `Δ_b` with `lsb(Δ_b) = b`, so
//! `Δ = Δ_0 ⊕ Δ_1` has lsb 1 (the DPF uses Δ as the root offset).
//!
//! * [`AuthBit`] (BDOZ): `P_b` holds `(x_b, K_b[x_{1−b}], M_b[x_b])` with
//!   `M_b[x_b] = K_{1−b}[x_b] ⊕ x_b·Δ_{1−b}`. These are F_aBit outputs, i.e. COTs.
//! * [`AuthGf`] (SPDZ): `P_b` holds `(x_b, M_b)` with
//!   `M_0 ⊕ M_1 = (x_0 ⊕ x_1)·(Δ_0 ⊕ Δ_1)` in GF(2^128).
//!
//! Both are linear. [`AuthBit::to_gf`] is the local BDOZ→SPDZ conversion of
//! BLN+21 and [`b2f`] packs 128 authenticated bits into one field element.
//! [`MacParty::open`] opens without checking and records the opening;
//! [`MacParty::check`] verifies every recorded opening at once (ΠBatchCheck),
//! which is the single point where a cheating party can learn one bit.

use crate::block::Block;
use crate::coin::{coin_block, coin_blocks, commit_and_open_blocks, Abort};
use crate::gf128;
use crate::net::Channel;
use crate::ot::CotPair;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;

/// COTs sacrificed per direction by the `lsb(Δ_b) = b` check: λ = 128, as
/// ZGY+24 §3.3 prescribes ("λ random authenticated sharings need to be
/// sacrificed").
pub const LSB_CHECK_COTS: usize = 128;

/// A BDOZ-authenticated bit, this party's view.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AuthBit {
    /// `x_b`.
    pub x: bool,
    /// `K_b[x_{1−b}]`, the key on the peer's share.
    pub k: Block,
    /// `M_b[x_b]`, the MAC on this party's share.
    pub m: Block,
}

/// A SPDZ-authenticated element of GF(2^128), this party's view.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AuthGf {
    pub x: Block,
    pub m: Block,
}

impl AuthBit {
    /// `⟨x⟩ ⊕ ⟨y⟩`.
    #[inline]
    pub fn xor(&self, o: &AuthBit) -> AuthBit {
        AuthBit { x: self.x ^ o.x, k: self.k ^ o.k, m: self.m ^ o.m }
    }

    /// `⟨x⟩ ⊕ c` for a public bit `c`: party 0 flips its share, party 1 adjusts
    /// its key on party 0's share.
    #[inline]
    pub fn xor_const(&self, c: bool, party: usize, delta: Block) -> AuthBit {
        if party == 0 {
            AuthBit { x: self.x ^ c, ..*self }
        } else {
            AuthBit { k: self.k ^ delta.and_bit(c), ..*self }
        }
    }

    /// Local BDOZ → SPDZ conversion (`Convert` of ZGY+24 §3.3): the bit as the
    /// field element 0 or 1 with MAC `K_b[x_{1−b}] ⊕ M_b[x_b] ⊕ x_b·Δ_b`.
    #[inline]
    pub fn to_gf(&self, delta: Block) -> AuthGf {
        AuthGf { x: Block(self.x as u128), m: self.k ^ self.m ^ delta.and_bit(self.x) }
    }
}

impl AuthGf {
    pub const ZERO: AuthGf = AuthGf { x: Block::ZERO, m: Block::ZERO };

    #[inline]
    pub fn add(&self, o: &AuthGf) -> AuthGf {
        AuthGf { x: self.x ^ o.x, m: self.m ^ o.m }
    }

    /// `c·⟨x⟩` for a public `c`.
    #[inline]
    pub fn scale(&self, c: Block) -> AuthGf {
        AuthGf { x: gf128::mul(c, self.x), m: gf128::mul(c, self.m) }
    }

    /// `⟨x⟩ + c` for a public `c`.
    #[inline]
    pub fn add_const(&self, c: Block, party: usize, delta: Block) -> AuthGf {
        AuthGf { x: if party == 0 { self.x ^ c } else { self.x }, m: self.m ^ gf128::mul(c, delta) }
    }

    /// The public constant `c` as a sharing.
    pub fn constant(c: Block, party: usize, delta: Block) -> AuthGf {
        AuthGf::ZERO.add_const(c, party, delta)
    }
}

/// `⟨Σ_i x_i·X^i⟩` from up to 128 authenticated bits (`B2F` + `Convert`).
pub fn b2f(bits: &[AuthBit], delta: Block) -> AuthGf {
    assert!(bits.len() <= 128);
    bits.iter().enumerate().fold(AuthGf::ZERO, |acc, (i, b)| {
        let g = b.to_gf(delta);
        AuthGf { x: acc.x ^ Block((g.x.0) << i), m: acc.m ^ gf128::mul(gf128::x_pow(i), g.m) }
    })
}

/// Openings recorded for the deferred batch check.
#[derive(Default)]
pub struct MacChecker {
    items: Vec<(AuthGf, Block)>,
}

impl MacChecker {
    /// Records that `share` was opened to `value`.
    pub fn record(&mut self, share: AuthGf, value: Block) {
        self.items.push((share, value));
    }

    pub fn pending(&self) -> usize {
        self.items.len()
    }
}

/// One party's authenticated-sharing engine: its MAC key, the KOS-checked COTs
/// that implement F_aBit, and the openings awaiting the batch check.
pub struct MacParty {
    pub party: usize,
    pub cot: CotPair,
    pub checker: MacChecker,
    rng: ChaCha20Rng,
}

impl MacParty {
    /// Picks `Δ_b` with `lsb(Δ_b) = b`, sets up both COT directions with the KOS
    /// check, and proves `lsb(Δ_b) = b` to the peer.
    ///
    /// The proof (in the spirit of CWYY23): for [`LSB_CHECK_COTS`] COTs on
    /// random choices `r_j` of the peer, `P_b` reveals `lsb(K_j)`. The peer checks
    /// `lsb(M_j) ⊕ lsb(K_j) = r_j·(1 − peer)`. A party whose `lsb(Δ)` is wrong
    /// must guess every `r_j`. The sacrificed COTs are discarded.
    pub fn setup(ch: &mut Channel, seed: [u8; 32]) -> Result<Self, Abort> {
        let party = ch.party();
        let mut rng = ChaCha20Rng::from_seed(seed);
        let mut delta = Block::random(&mut rng);
        delta.0 = (delta.0 & !1) | party as u128;
        let mut cot = CotPair::setup(ch, &mut rng, delta, true)?;
        let r: Vec<bool> = (0..LSB_CHECK_COTS).map(|_| rng.gen()).collect();
        let (k, m) = cot.extend(ch, &r, LSB_CHECK_COTS, &mut rng)?;
        let lsbs: Vec<bool> = k.iter().map(|x| x.lsb()).collect();
        ch.send_bits(&lsbs);
        let theirs = ch.recv_bits(LSB_CHECK_COTS);
        let peer_lsb = 1 - party == 1;
        for j in 0..LSB_CHECK_COTS {
            if m[j].lsb() ^ theirs[j] != (r[j] && peer_lsb) {
                return Err(Abort("lsb(Δ) check failed"));
            }
        }
        Ok(MacParty { party, cot, checker: MacChecker::default(), rng })
    }

    /// `Δ_b`.
    pub fn delta(&self) -> Block {
        self.cot.delta()
    }

    pub fn rng(&mut self) -> &mut ChaCha20Rng {
        &mut self.rng
    }

    /// Authenticates an XOR-shared bit vector: both parties pass their share
    /// bits (a value known to one party is shared with zeros on the other side).
    pub fn share_bits(&mut self, ch: &mut Channel, mine: &[bool]) -> Result<Vec<AuthBit>, Abort> {
        let (k, m) = self.cot.extend(ch, mine, mine.len(), &mut self.rng)?;
        Ok(mine.iter().zip(k).zip(m).map(|((&x, k), m)| AuthBit { x, k, m }).collect())
    }

    /// Authenticates XOR-shared field elements (128 aBits each).
    pub fn share_gf(&mut self, ch: &mut Channel, mine: &[Block]) -> Result<Vec<AuthGf>, Abort> {
        let bits: Vec<bool> = mine.iter().flat_map(|x| x.to_bits()).collect();
        let ab = self.share_bits(ch, &bits)?;
        let d = self.delta();
        Ok(ab.chunks(128).map(|c| b2f(c, d)).collect())
    }

    /// `n` uniformly random authenticated field elements (Rand of ZGY+24).
    pub fn rand_gf(&mut self, ch: &mut Channel, n: usize) -> Result<Vec<AuthGf>, Abort> {
        let mine: Vec<Block> = (0..n).map(|_| Block::random(&mut self.rng)).collect();
        self.share_gf(ch, &mine)
    }

    /// Opens values without checking them and records each opening for
    /// [`check`](Self::check). One flight.
    pub fn open(&mut self, ch: &mut Channel, vals: &[AuthGf]) -> Vec<Block> {
        let mine: Vec<Block> = vals.iter().map(|v| v.x).collect();
        ch.send_blocks(&mine);
        let theirs = ch.recv_blocks(vals.len());
        let out: Vec<Block> = mine.iter().zip(&theirs).map(|(a, b)| *a ^ *b).collect();
        for (v, o) in vals.iter().zip(&out) {
            self.checker.record(*v, *o);
        }
        out
    }

    /// ΠBatchCheck over every recorded opening: random χ, `z = Σ χ^i y_i`,
    /// `V_b = M_b[z] ⊕ z·Δ_b`, commit-and-open, compare. Clears the record.
    pub fn check(&mut self, ch: &mut Channel) -> Result<(), Abort> {
        let items = std::mem::take(&mut self.checker.items);
        let chi = coin_block(ch, &mut self.rng)?;
        let mut c = gf128::ONE;
        let (mut z, mut mz) = (Block::ZERO, Block::ZERO);
        for (share, value) in &items {
            z ^= gf128::mul(c, *value);
            mz ^= gf128::mul(c, share.m);
            c = gf128::mul(c, chi);
        }
        let v = mz ^ gf128::mul(z, self.delta());
        let theirs = commit_and_open_blocks(ch, &[v], &mut self.rng)?;
        if theirs[0] != v {
            return Err(Abort("MAC check failed"));
        }
        Ok(())
    }

    /// A public random challenge (F_coin).
    pub fn coins(&mut self, ch: &mut Channel, n: usize) -> Result<Vec<Block>, Abort> {
        coin_blocks(ch, n, &mut self.rng)
    }
}

/// Trusted-dealer helpers for tests and benchmarks.
pub mod dealer {
    use super::*;
    use rand::{CryptoRng, RngCore};

    /// Random MAC keys with `lsb(Δ_b) = b`.
    pub fn deltas<R: RngCore + CryptoRng>(rng: &mut R) -> [Block; 2] {
        let d0 = Block(rng.gen::<u128>() & !1);
        let d1 = Block(rng.gen::<u128>() | 1);
        [d0, d1]
    }

    /// A random SPDZ sharing of `x` under `Δ_0 ⊕ Δ_1`.
    pub fn share_gf<R: RngCore + CryptoRng>(rng: &mut R, x: Block, deltas: [Block; 2]) -> [AuthGf; 2] {
        let x0 = Block::random(rng);
        let m0 = Block::random(rng);
        let m1 = m0 ^ gf128::mul(x, deltas[0] ^ deltas[1]);
        [AuthGf { x: x0, m: m0 }, AuthGf { x: x ^ x0, m: m1 }]
    }

    /// A random BDOZ sharing of the bit `x`.
    pub fn share_bit<R: RngCore + CryptoRng>(rng: &mut R, x: bool, deltas: [Block; 2]) -> [AuthBit; 2] {
        let x0: bool = rng.gen();
        let x1 = x ^ x0;
        let (k0, k1) = (Block::random(rng), Block::random(rng));
        // M_0[x_0] = K_1[x_0] ⊕ x_0·Δ_1, M_1[x_1] = K_0[x_1] ⊕ x_1·Δ_0.
        [
            AuthBit { x: x0, k: k0, m: k1 ^ deltas[1].and_bit(x0) },
            AuthBit { x: x1, k: k1, m: k0 ^ deltas[0].and_bit(x1) },
        ]
    }

    /// Reconstructs a SPDZ sharing and checks its MAC.
    pub fn open_gf(s: &[AuthGf; 2], deltas: [Block; 2]) -> Option<Block> {
        let x = s[0].x ^ s[1].x;
        (s[0].m ^ s[1].m == gf128::mul(x, deltas[0] ^ deltas[1])).then_some(x)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::run_two_party;

    #[test]
    fn local_algebra() {
        let mut rng = ChaCha20Rng::seed_from_u64(1);
        let d = dealer::deltas(&mut rng);
        for _ in 0..50 {
            let bits: Vec<bool> = (0..128).map(|_| rng.gen()).collect();
            let shared: Vec<[AuthBit; 2]> = bits.iter().map(|&b| dealer::share_bit(&mut rng, b, d)).collect();
            let g = [0, 1].map(|p| b2f(&shared.iter().map(|s| s[p]).collect::<Vec<_>>(), d[p]));
            assert_eq!(dealer::open_gf(&g, d), Some(Block::from_bits(&bits)));
            let c = Block::random(&mut rng);
            let s = [g[0].scale(c).add_const(c, 0, d[0]), g[1].scale(c).add_const(c, 1, d[1])];
            assert_eq!(dealer::open_gf(&s, d), Some(gf128::mul(c, Block::from_bits(&bits)) ^ c));
            let f = [shared[0][0].xor_const(true, 0, d[0]), shared[0][1].xor_const(true, 1, d[1])];
            assert_eq!(dealer::open_gf(&[f[0].to_gf(d[0]), f[1].to_gf(d[1])], d), Some(Block((!bits[0]) as u128)));
        }
    }

    fn session(c: &mut Channel, seed: u8, xs: Vec<Block>, tamper: bool) -> Result<Vec<Block>, Abort> {
        let mut p = MacParty::setup(c, [seed; 32])?;
        let mut v = p.share_gf(c, &xs)?;
        let r = p.rand_gf(c, 2)?;
        v.push(v[0].add(&r[0]).scale(Block(7)));
        if tamper {
            v[1].x ^= Block(1 << 9);
        }
        let out = p.open(c, &v);
        p.check(c)?;
        Ok(out)
    }

    #[test]
    fn share_open_check() {
        let mut rng = ChaCha20Rng::seed_from_u64(2);
        let x: Vec<Block> = (0..3).map(|_| Block::random(&mut rng)).collect();
        let x0: Vec<Block> = (0..3).map(|_| Block::random(&mut rng)).collect();
        let x1: Vec<Block> = x.iter().zip(&x0).map(|(a, b)| *a ^ *b).collect();
        let (a, b) = run_two_party(move |c| session(c, 1, x0, false), move |c| session(c, 2, x1, false));
        let (a, b) = (a.unwrap(), b.unwrap());
        assert_eq!(a, b);
        assert_eq!(&a[..3], &x[..]);

        let (a, b) = run_two_party(|c| session(c, 1, vec![Block(1)], true), |c| session(c, 2, vec![Block(2)], false));
        assert_eq!(a, Err(Abort("MAC check failed")));
        assert_eq!(b, Err(Abort("MAC check failed")));
    }
}
