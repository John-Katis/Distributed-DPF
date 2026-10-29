//! Authenticated F4 arithmetic for malicious 2PC on bits: SPDZ bit MACs in
//! GF(2^128), F4 Beaver triples without a dealer (leaky triples + bucketing),
//! and an [`AuthF4`] backend that runs [`crate::aes_tower`] with abort.
//!
//! **Sharing.** [`ABit`]: party b holds `(x_b, m_b)` with
//! `m_0 ⊕ m_1 = (x_0 ⊕ x_1)·Δ`, `Δ = Δ_0 ⊕ Δ_1` the MAC key of
//! [`MacParty`] (the SPDZ form of its BDOZ bits, [`AuthBit::to_gf`]). An F4
//! element is two such bits, so every F2-linear map (the AES layers, `x ↦ c·x`
//! for public `c ∈ F4`, squaring) is local. Every opening is checked by
//! [`OpenChecker`]: party b hashes `z_b = m_b ⊕ v·Δ_b` of every opened bit v,
//! and the two digests are compared through a commitment; `z_0 = z_1` exactly
//! when `m_0 ⊕ m_1 = vΔ`, and a party that shifted v by e would need `e·Δ_peer`.
//!
//! **Leaky triples** (F4 version of Π_LaAND, WRK17 Fig. 8 / KRRW18 Fig. 4).
//! From random aBits `⟨x⟩, ⟨y⟩, ⟨r⟩ ∈ F4`:
//!
//! 1. Half products, keyed on x: party A sends, for each bit `x_{B,j}` of the
//!    peer, `H(K_A[x_{B,j}]) ⊕ H(K_A[x_{B,j}] ⊕ Δ_A) ⊕ c_j·y_A` (`c_h = ω`,
//!    `c_l = 1`), giving XOR shares of `x_B·y_A`; symmetrically for `x_A·y_B`.
//!    `z'_b = x_b y_b ⊕ (half products)`, and `d = z' ⊕ r` is opened to set
//!    `⟨z⟩ = ⟨r⟩ ⊕ d`.
//! 2. Check, with `ι: F4 → GF(2^128)`, `ι(ω) = w` a cube root of unity: the
//!    shares `Φ_b(y) = w·M_b(y_h) ⊕ M_b(y_l)` of `ι(y)Δ` are multiplied by `x`
//!    with the same hash-OT keyed on the bits of x (two σ-bit messages per
//!    direction), and `C_b = trunc(ι(x_b)Φ_b(y)) ⊕ (cross shares) ⊕
//!    trunc(Φ_b(z))` must agree: `C_0 ⊕ C_1 = trunc(ι(z ⊕ xy)·Δ)`. A wrong z
//!    passes only by guessing σ = 64 bits of `ι(e)·Δ_peer`;
//!    a party that tampers with a hash-OT message changes the result by a
//!    multiple of the peer's x bits, so the abort leaks bits of x (only x).
//!
//! **Bucketing** (WRK17 Fig. 9): `B·N` leaky triples, permuted by a coin
//! toss, buckets of B combined as `(x_1 ⊕ x_k, y_1, z_1 ⊕ z_k ⊕ x_k·d_k)` with
//! `d_k = y_1 ⊕ y_k` opened: x of the result is hidden unless every x_k of the
//! bucket leaked. [`bucket_size`] follows WRK17 (`B ≥ 1 + ρ/log₂ N`, ρ = 40).

use super::binary::{AuthBit, MacParty};
use crate::aes_tower::{sbox_f4, F4Products, F4Sh, ShareBit, TowerBackend};
use crate::block::{pack_bits, unpack_bits, Block};
use crate::coin::{coin_block, commit_and_open, Abort};
use crate::f4;
use crate::gf128;
use crate::hash::FixedKeyHash;
use crate::net::Channel;
use crate::ot::RandomCots;
use rand::seq::SliceRandom;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use sha2::{Digest, Sha256};
use std::ops::BitXor;
use std::sync::OnceLock;

/// Statistical security of the bucketing.
pub const RHO: usize = 40;

/// A SPDZ-authenticated bit: `(x_b, m_b)` with `m_0 ⊕ m_1 = xΔ`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ABit {
    pub x: bool,
    pub m: Block,
}

impl BitXor for ABit {
    type Output = ABit;
    #[inline]
    fn bitxor(self, o: ABit) -> ABit {
        ABit { x: self.x ^ o.x, m: self.m ^ o.m }
    }
}

impl ShareBit for ABit {}

impl ABit {
    /// From a BDOZ bit.
    #[inline]
    pub fn from_bdoz(a: &AuthBit, delta: Block) -> ABit {
        let g = a.to_gf(delta);
        ABit { x: a.x, m: g.m }
    }

    /// The public bit c: party 0 holds c, both add `c·Δ_b` to the MAC.
    #[inline]
    pub fn constant(c: bool, party: usize, delta: Block) -> ABit {
        ABit { x: c && party == 0, m: delta.and_bit(c) }
    }

    /// `c·x` for a public bit c.
    #[inline]
    pub fn and_const(self, c: bool) -> ABit {
        ABit { x: self.x && c, m: self.m.and_bit(c) }
    }
}

/// The deferred check of every authenticated opening (see the module docs).
pub struct OpenChecker {
    delta: Block,
    hasher: Sha256,
    /// Bits opened since the last check.
    pub pending: usize,
}

impl OpenChecker {
    pub fn new(delta: Block) -> Self {
        OpenChecker { delta, hasher: Sha256::new(), pending: 0 }
    }

    /// Records that `share` opened to `value`.
    #[inline]
    pub fn record(&mut self, share: ABit, value: bool) {
        self.hasher.update((share.m ^ self.delta.and_bit(value)).to_bytes());
        self.pending += 1;
    }

    /// Opens bits (one round) and records them.
    pub fn open(&mut self, ch: &mut Channel, shares: &[ABit]) -> Result<Vec<bool>, Abort> {
        let mine: Vec<bool> = shares.iter().map(|s| s.x).collect();
        ch.send_bits(&mine);
        let theirs = ch.recv();
        if theirs.len() != mine.len().div_ceil(8) {
            return Err(Abort("malformed opening"));
        }
        let out: Vec<bool> = mine.iter().zip(unpack_bits(&theirs, mine.len())).map(|(a, b)| a ^ b).collect();
        for (s, &v) in shares.iter().zip(&out) {
            self.record(*s, v);
        }
        Ok(out)
    }

    /// Compares the digests through a commitment (two rounds) and resets.
    pub fn check<R: rand::RngCore + rand::CryptoRng>(&mut self, ch: &mut Channel, rng: &mut R) -> Result<(), Abort> {
        let digest: [u8; 32] = std::mem::take(&mut self.hasher).finalize().into();
        self.pending = 0;
        let theirs = commit_and_open(ch, &digest, rng)?;
        if theirs != digest {
            return Err(Abort("MAC check failed"));
        }
        Ok(())
    }
}

/// An authenticated F4 Beaver triple, one party's shares.
#[derive(Clone, Copy, Debug, Default)]
pub struct AuthTriple {
    pub a: F4Sh<ABit>,
    pub b: F4Sh<ABit>,
    pub c: F4Sh<ABit>,
}

/// `ι(ω)`: an element of order 3 in GF(2^128).
pub fn cube_root() -> Block {
    static W: OnceLock<Block> = OnceLock::new();
    *W.get_or_init(|| {
        let e = u128::MAX / 3;
        let w = gf128::pow(Block(2), e);
        assert!(w != gf128::ONE && gf128::mul(w, w) ^ w == gf128::ONE, "X^{{(2^128−1)/3}} has order 3");
        w
    })
}

/// `ι(c)` for `c ∈ F4`.
#[inline]
fn iota(c: u8) -> Block {
    cube_root().and_bit(c & 2 == 2) ^ Block((c & 1) as u128)
}

fn pad_hash() -> &'static FixedKeyHash {
    static H: OnceLock<FixedKeyHash> = OnceLock::new();
    H.get_or_init(|| FixedKeyHash::new(b"af4/leaky-triple"))
}

#[inline]
fn h2(k: Block, i: usize) -> u8 {
    pad_hash().h(k, (i as u64) << 1).0 as u8 & 3
}

#[inline]
fn h64(k: Block, i: usize) -> u64 {
    pad_hash().h(k, (i as u64) << 1 | 1).0 as u64
}

#[inline]
fn trunc(v: Block) -> u64 {
    (v.0 >> 64) as u64
}

/// The SPDZ MAC share of a BDOZ bit.
#[inline]
fn mgf(a: &AuthBit, delta: Block) -> Block {
    a.to_gf(delta).m
}

/// WRK17's bucket size for `n` triples at [`RHO`] = 40.
pub fn bucket_size(n: usize) -> usize {
    let lg = (n.max(2) as f64).log2();
    1 + (RHO as f64 / lg).ceil() as usize
}

/// `L` leaky authenticated F4 triples (BDOZ) from `6L` random aBits per party.
/// Four rounds plus the COT refills.
fn leaky_triples(ch: &mut Channel, mac: &mut MacParty, l: usize) -> Result<Vec<[AuthBit; 6]>, Abort> {
    let me = ch.party();
    let delta = mac.delta();
    let mut rng = mac.rng().clone();
    let nb = 6 * l;
    let (mut bits, mut keys) = (Vec::new(), Vec::new());
    for s in 0..2 {
        match mac.cot.random_cots(ch, s, nb, &mut rng)? {
            RandomCots::Sender(k) => keys = k,
            RandomCots::Receiver(r, m) => bits = r.into_iter().zip(m).collect::<Vec<_>>(),
        }
    }
    let ab: Vec<AuthBit> = (0..nb).map(|j| AuthBit { x: bits[j].0, m: bits[j].1, k: keys[j] }).collect();
    let val = |i: usize, o: usize| (ab[6 * i + o].x as u8) << 1 | ab[6 * i + o + 1].x as u8;
    let w = cube_root();

    // Round 1: half products and the check messages, both keyed on the peer's x.
    let mut v = vec![0u8; l];
    let mut cross = vec![0u64; l];
    let mut half = Vec::with_capacity(l);
    let mut chk = Vec::with_capacity(16 * l);
    let mut t_me = Vec::with_capacity(l);
    for i in 0..l {
        let y = val(i, 2);
        let t = gf128::mul(w, mgf(&ab[6 * i + 2], delta)) ^ mgf(&ab[6 * i + 3], delta);
        t_me.push(t);
        let mut byte = 0u8;
        for (j, (cy, ct)) in [(f4::mul(f4::OMEGA, y), gf128::mul(w, t)), (y, t)].into_iter().enumerate() {
            let k = ab[6 * i + j].k;
            let idx = 6 * i + j;
            let (p0, p1) = (h2(k, idx), h2(k ^ delta, idx));
            v[i] ^= p0;
            byte |= (p0 ^ p1 ^ cy) << (2 * j);
            let (q0, q1) = (h64(k, idx), h64(k ^ delta, idx));
            cross[i] ^= q0;
            chk.extend_from_slice(&(q0 ^ q1 ^ trunc(ct)).to_le_bytes());
        }
        half.push(byte);
    }
    let mut msg = half;
    msg.extend_from_slice(&chk);
    ch.send(msg);
    let theirs = ch.recv();
    if theirs.len() != 17 * l {
        return Err(Abort("malformed leaky-triple message"));
    }
    let (th, tc) = theirs.split_at(l);
    for i in 0..l {
        for j in 0..2 {
            let a = &ab[6 * i + j];
            let idx = 6 * i + j;
            let u = th[i] >> (2 * j) & 3;
            v[i] ^= h2(a.m, idx) ^ if a.x { u } else { 0 };
            let uc = u64::from_le_bytes(tc[8 * (2 * i + j)..8 * (2 * i + j + 1)].try_into().unwrap());
            cross[i] ^= h64(a.m, idx) ^ if a.x { uc } else { 0 };
        }
    }

    // Round 2: d = z' ⊕ r, ⟨z⟩ = ⟨r⟩ ⊕ d.
    let zp: Vec<u8> = (0..l).map(|i| f4::mul(val(i, 0), val(i, 2)) ^ v[i]).collect();
    let d_me: Vec<bool> = (0..l).flat_map(|i| {
        let d = zp[i] ^ val(i, 4);
        [d & 2 == 2, d & 1 == 1]
    }).collect();
    ch.send(pack_bits(&d_me));
    let dt = ch.recv();
    if dt.len() != (2 * l).div_ceil(8) {
        return Err(Abort("malformed leaky-triple opening"));
    }
    let d: Vec<bool> = d_me.iter().zip(unpack_bits(&dt, 2 * l)).map(|(a, b)| a ^ b).collect();
    let mut out: Vec<[AuthBit; 6]> = (0..l).map(|i| std::array::from_fn(|o| ab[6 * i + o])).collect();
    for (i, t) in out.iter_mut().enumerate() {
        t[4] = t[4].xor_const(d[2 * i], me, delta);
        t[5] = t[5].xor_const(d[2 * i + 1], me, delta);
    }

    // Rounds 3–4: compare the check values through a commitment.
    let mut hsh = Sha256::new();
    for (i, t) in out.iter().enumerate() {
        let x = (t[0].x as u8) << 1 | t[1].x as u8;
        let phi_z = gf128::mul(w, mgf(&t[4], delta)) ^ mgf(&t[5], delta);
        let c = trunc(gf128::mul(iota(x), t_me[i])) ^ cross[i] ^ trunc(phi_z);
        hsh.update(c.to_le_bytes());
    }
    let digest: [u8; 32] = hsh.finalize().into();
    let theirs = commit_and_open(ch, &digest, &mut rng)?;
    *mac.rng() = rng;
    if theirs != digest {
        return Err(Abort("leaky triple check failed"));
    }
    Ok(out)
}

/// `n` authenticated F4 triples: `bucket_size(n)·n` leaky ones, bucketed. The
/// openings of the combination are recorded in `checker`.
pub fn auth_triples(ch: &mut Channel, mac: &mut MacParty, checker: &mut OpenChecker, n: usize) -> Result<Vec<AuthTriple>, Abort> {
    let b = bucket_size(n);
    let delta = mac.delta();
    let leaky = leaky_triples(ch, mac, b * n)?;
    let spdz = |a: &AuthBit| ABit::from_bdoz(a, delta);
    let f4sh = |t: &[AuthBit; 6], o: usize| F4Sh { h: spdz(&t[o]), l: spdz(&t[o + 1]) };
    let mut ts: Vec<AuthTriple> = leaky.iter().map(|t| AuthTriple { a: f4sh(t, 0), b: f4sh(t, 2), c: f4sh(t, 4) }).collect();
    drop(leaky);
    let mut rng = mac.rng().clone();
    let seed = coin_block(ch, &mut rng)?;
    *mac.rng() = rng;
    let mut perm_rng = ChaCha20Rng::from_seed(std::array::from_fn(|i| seed.to_bytes()[i % 16]));
    ts.shuffle(&mut perm_rng);
    // d_k = y_1 ⊕ y_k for every bucket, in one round.
    let mut ds = Vec::with_capacity(2 * (b - 1) * n);
    for q in 0..n {
        let first = ts[q * b].b;
        for k in 1..b {
            let y = first.add(ts[q * b + k].b);
            ds.extend([y.h, y.l]);
        }
    }
    let d = checker.open(ch, &ds)?;
    Ok((0..n)
        .map(|q| {
            let mut t = ts[q * b];
            for k in 1..b {
                let o = ts[q * b + k];
                let dk = (d[2 * ((b - 1) * q + k - 1)] as u8) << 1 | d[2 * ((b - 1) * q + k - 1) + 1] as u8;
                t = AuthTriple { a: t.a.add(o.a), b: t.b, c: t.c.add(o.c).add(o.a.scale(dk)) };
            }
            t
        })
        .collect())
}

/// [`TowerBackend`] on authenticated bits: Beaver products with
/// [`AuthTriple`]s, every opening recorded in [`AuthF4::checker`].
pub struct AuthF4 {
    party: usize,
    delta: Block,
    triples: Vec<AuthTriple>,
    next: usize,
    pub checker: OpenChecker,
    /// Products computed so far.
    pub products: usize,
}

impl AuthF4 {
    pub fn new(party: usize, delta: Block, triples: Vec<AuthTriple>, checker: OpenChecker) -> Self {
        AuthF4 { party, delta, triples, next: 0, checker, products: 0 }
    }

    pub fn remaining(&self) -> usize {
        self.triples.len() - self.next
    }

    pub fn delta(&self) -> Block {
        self.delta
    }

    pub fn party(&self) -> usize {
        self.party
    }

    /// The public F4 constant c.
    pub fn const_f4(&self, c: u8) -> F4Sh<ABit> {
        F4Sh { h: self.constant(c & 2 == 2), l: self.constant(c & 1 == 1) }
    }

    /// Products `x_i·y_i` and the opening of `open`, in one round.
    pub fn mul_and_open(&mut self, ch: &mut Channel, x: &[F4Sh<ABit>], y: &[F4Sh<ABit>], open: &[ABit]) -> Result<(Vec<F4Sh<ABit>>, Vec<bool>), Abort> {
        let n = x.len();
        assert!(self.remaining() >= n, "authenticated triple pool exhausted");
        let t = &self.triples[self.next..self.next + n];
        self.next += n;
        self.products += n;
        let mut sh = Vec::with_capacity(4 * n + open.len());
        for i in 0..n {
            let (d, e) = (x[i].add(t[i].a), y[i].add(t[i].b));
            sh.extend([d.h, d.l, e.h, e.l]);
        }
        sh.extend_from_slice(open);
        let v = self.checker.open(ch, &sh)?;
        let f = |j: usize| (v[j] as u8) << 1 | v[j + 1] as u8;
        let z = (0..n)
            .map(|i| {
                let (d, e) = (f(4 * i), f(4 * i + 2));
                t[i].c.add(t[i].b.scale(d)).add(t[i].a.scale(e)).add(self.const_f4(f4::mul(d, e)))
            })
            .collect();
        Ok((z, v[4 * n..].to_vec()))
    }
}

impl TowerBackend for AuthF4 {
    type Bit = ABit;

    fn constant(&self, c: bool) -> ABit {
        ABit::constant(c, self.party, self.delta)
    }

    fn sbox(&mut self, ch: &mut Channel, bytes: &[[ABit; 8]]) -> Vec<[ABit; 8]> {
        sbox_f4(self, ch, bytes)
    }
}

impl F4Products for AuthF4 {
    /// Panics on a malformed message; deviations in the values are caught by
    /// the checker.
    fn mul_f4(&mut self, ch: &mut Channel, x: &[F4Sh<ABit>], y: &[F4Sh<ABit>]) -> Vec<F4Sh<ABit>> {
        self.mul_and_open(ch, x, y, &[]).expect("malformed Beaver opening").0
    }
}

/// Trusted-dealer helpers for tests.
pub mod dealer {
    use super::*;
    use rand::{CryptoRng, Rng, RngCore};

    /// A random sharing of the bit `x` under `deltas[0] ⊕ deltas[1]`.
    pub fn share<R: RngCore + CryptoRng>(rng: &mut R, x: bool, deltas: [Block; 2]) -> [ABit; 2] {
        let x0: bool = rng.gen();
        let m0 = Block::random(rng);
        [ABit { x: x0, m: m0 }, ABit { x: x ^ x0, m: m0 ^ (deltas[0] ^ deltas[1]).and_bit(x) }]
    }

    /// Opens and checks a sharing.
    pub fn open(s: &[ABit; 2], deltas: [Block; 2]) -> Option<bool> {
        let x = s[0].x ^ s[1].x;
        (s[0].m ^ s[1].m == (deltas[0] ^ deltas[1]).and_bit(x)).then_some(x)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aes_tower::{mmo_shared, Mmo, Shared128, PRODUCTS_PER_CALL};
    use crate::net::run_two_party;
    use crate::ot::FerretConfig;

    fn f4_of(s: [F4Sh<ABit>; 2], d: [Block; 2]) -> u8 {
        let h = dealer::open(&[s[0].h, s[1].h], d).expect("MAC");
        let l = dealer::open(&[s[0].l, s[1].l], d).expect("MAC");
        (h as u8) << 1 | l as u8
    }

    fn session(ch: &mut Channel, seed: u8, n: usize) -> (Result<Vec<AuthTriple>, Abort>, Block) {
        let mut mac = MacParty::setup(ch, [seed; 32]).unwrap();
        let mut rng = mac.rng().clone();
        mac.cot.enable_ferret(ch, FerretConfig::TOY, &mut rng).unwrap();
        *mac.rng() = rng;
        let d = mac.delta();
        let mut chk = OpenChecker::new(d);
        let t = auth_triples(ch, &mut mac, &mut chk, n).and_then(|t| {
            chk.check(ch, mac.rng())?;
            Ok(t)
        });
        (t, d)
    }

    #[test]
    fn bucketed_triples_are_authenticated_triples() {
        let ((t0, d0), (t1, d1)) = run_two_party(|c| session(c, 1, 300), |c| session(c, 2, 300));
        let (t0, t1) = (t0.unwrap(), t1.unwrap());
        let d = [d0, d1];
        for (x, y) in t0.iter().zip(&t1) {
            let (a, b, c) = (f4_of([x.a, y.a], d), f4_of([x.b, y.b], d), f4_of([x.c, y.c], d));
            assert_eq!(c, f4::mul(a, b));
        }
        assert_eq!(bucket_size(300), 6);
        assert_eq!(bucket_size(143_000), 4);
        assert_eq!(bucket_size(1 << 20), 3);
    }

    #[test]
    fn authenticated_mmo_and_tampering() {
        let mut rng = ChaCha20Rng::seed_from_u64(3);
        let deltas = super::super::binary::dealer::deltas(&mut rng);
        let ts: Vec<[AuthTriple; 2]> = (0..PRODUCTS_PER_CALL)
            .map(|_| {
                let (a, b): (u8, u8) = (rand::Rng::gen_range(&mut rng, 0..4), rand::Rng::gen_range(&mut rng, 0..4));
                let sh = |v: u8, rng: &mut ChaCha20Rng| {
                    let h = dealer::share(rng, v & 2 == 2, deltas);
                    let l = dealer::share(rng, v & 1 == 1, deltas);
                    [F4Sh { h: h[0], l: l[0] }, F4Sh { h: h[1], l: l[1] }]
                };
                let (sa, sb, sc) = (sh(a, &mut rng), sh(b, &mut rng), sh(f4::mul(a, b), &mut rng));
                [0, 1].map(|p| AuthTriple { a: sa[p], b: sb[p], c: sc[p] })
            })
            .collect();
        let x = Block::random(&mut rng);
        let xs: Vec<[ABit; 2]> = (0..128).map(|i| dealer::share(&mut rng, x.bit(i), deltas)).collect();
        let key = Mmo::new(*b"af4/test-mmo-key");
        for tamper in [false, true] {
            let party = |p: usize| {
                let (ts, xs, key) = (ts.clone(), xs.clone(), key.clone());
                move |ch: &mut Channel| {
                    let mut be = AuthF4::new(p, deltas[p], ts.iter().map(|t| t[p]).collect(), OpenChecker::new(deltas[p]));
                    let mut input: Shared128<ABit> = std::array::from_fn(|i| xs[i][p]);
                    if tamper && p == 1 {
                        input[5].x ^= true; // an unauthenticated change to the input
                    }
                    let y = mmo_shared(&mut be, ch, &[(&key, input)]);
                    let ok = be.checker.check(ch, &mut ChaCha20Rng::seed_from_u64(p as u64));
                    (y[0], ok)
                }
            };
            let ((y0, ok0), (y1, ok1)) = run_two_party(party(0), party(1));
            if tamper {
                assert!(ok0.is_err() && ok1.is_err());
            } else {
                ok0.unwrap();
                ok1.unwrap();
                let y = Block::from_bits(&(0..128).map(|i| dealer::open(&[y0[i], y1[i]], deltas).expect("output MAC")).collect::<Vec<_>>());
                assert_eq!(y, key.h(x));
            }
        }
    }
}
