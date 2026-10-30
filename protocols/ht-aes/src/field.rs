//! Fields for the arithmetic payload and its MAC, and the COT-based OLE the
//! leaf is built from.
//!
//! The paper takes the payload group to be the Babybear field `F_q`, `q =
//! 2^31 − 2^27 + 1` ([`BabyBear`]), with MAC key, MAC words and tags in its
//! quartic extension `F_{q^4} = F_q[X]/(X^4 − 11)` ([`BabyBear4`]): the
//! payload-MAC argument (Proposition "MAC Detection") bounds a forgery by
//! `Pr[δ·Δ_val = Δ_mac] ≤ 1/|E|` for the MAC field E, which needs every
//! nonzero `Δ_val` invertible (a field) and `|E|` large (`q^4 ≈ 2^124`).
//! [`Ext`] is the MAC field over the payload field; every field is its own
//! degree-1 extension, so Goldilocks `2^64 − 2^32 + 1` ([`Gold`]) and `2^127
//! − 1` ([`M127`]), for wider payloads, keep payload and MAC in one field.

use dpf_common::block::Block;
use dpf_common::hash::{cot_hash, CtrPrg};
use dpf_common::net::Channel;
use dpf_common::ot::CotPair;
use rand::{CryptoRng, RngCore};
use std::fmt::Debug;

pub trait Field: Copy + Default + Eq + Debug + Send + Sync + 'static {
    /// Bytes of one element on the wire.
    const BYTES: usize;
    /// `⌈log₂ p⌉`.
    const P_BITS: usize;
    /// Bits of a 128-bit hash output read as an integer and reduced mod p:
    /// `min(P_BITS + 40, 128)`, within `2^−40` of uniform.
    const KAPPA: usize;
    const ZERO: Self;
    const ONE: Self;
    fn add(self, o: Self) -> Self;
    fn sub(self, o: Self) -> Self;
    fn neg(self) -> Self;
    fn mul(self, o: Self) -> Self;
    /// The integer `x mod p`.
    fn from_u128(x: u128) -> Self;
    /// The canonical representative.
    fn to_u128(self) -> u128;
    fn random<R: RngCore + ?Sized>(rng: &mut R) -> Self;
    fn put(self, out: &mut Vec<u8>);
    fn get(b: &[u8]) -> Self;

    /// The low [`KAPPA`](Field::KAPPA) bits of a block, mod p: the leaf
    /// masks `F^pay`, `F^mac` in F_p.
    #[inline]
    fn from_block(b: Block) -> Self {
        Self::from_u128(if Self::KAPPA >= 128 { b.0 } else { b.0 & ((1u128 << Self::KAPPA) - 1) })
    }

    /// The weight of bit k of [`to_u128`](Field::to_u128): `x = Σ_k x_k·pow2(k)`
    /// (`2^k mod p` in a prime field).
    fn pow2(k: usize) -> Self {
        Self::from_u128(1u128 << k)
    }

    /// A pseudorandom element from a 128-bit seed, within `2^−40` of uniform
    /// (OLE pads, Π_Verify challenges).
    fn from_seed(seed: Block) -> Self {
        Self::from_u128(seed.0)
    }
}

/// A MAC field E over the payload field F: E = F, or an extension of degree
/// [`DEG`](Ext::DEG) given by its coordinates.
pub trait Ext<F: Field>: Field {
    const DEG: usize;
    fn embed(x: F) -> Self;
    fn coord(self, i: usize) -> F;
    fn from_coords(c: &[F]) -> Self;
}

impl<F: Field> Ext<F> for F {
    const DEG: usize = 1;
    #[inline]
    fn embed(x: F) -> Self {
        x
    }
    #[inline]
    fn coord(self, _: usize) -> F {
        self
    }
    #[inline]
    fn from_coords(c: &[F]) -> Self {
        c[0]
    }
}

/// Blocks of a leaf mask in E: [`Field::KAPPA`] bits of F per coordinate.
pub fn mask_blocks<F: Field, E: Ext<F>>() -> usize {
    (E::DEG * F::KAPPA).div_ceil(128)
}

/// Bits `start .. start + len` (`len ≤ 128`) of the concatenated blocks.
fn bit_range(blocks: &[Block], start: usize, len: usize) -> u128 {
    (0..len).fold(0u128, |acc, k| {
        let i = start + k;
        acc | ((blocks[i / 128].bit(i % 128) as u128) << k)
    })
}

/// A leaf mask in E from [`mask_blocks`] hash outputs: coordinate c is the
/// integer of bits `cκ .. (c + 1)κ`, mod p (κ = [`Field::KAPPA`]). For E = F
/// this is [`Field::from_block`].
pub fn mask_value<F: Field, E: Ext<F>>(blocks: &[Block]) -> E {
    if E::DEG == 1 {
        return E::embed(F::from_block(blocks[0]));
    }
    let c: Vec<F> = (0..E::DEG).map(|i| F::from_u128(bit_range(blocks, i * F::KAPPA, F::KAPPA))).collect();
    E::from_coords(&c)
}

/// Babybear, `q = 2^31 − 2^27 + 1`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct BabyBear(pub u32);

const BB_Q: u64 = 0x7800_0001;
/// `2^64 mod q`.
const BB_2_64: u64 = ((1u128 << 64) % BB_Q as u128) as u64;

impl Field for BabyBear {
    const BYTES: usize = 4;
    const P_BITS: usize = 31;
    const KAPPA: usize = 71;
    const ZERO: Self = BabyBear(0);
    const ONE: Self = BabyBear(1);
    #[inline]
    fn add(self, o: Self) -> Self {
        let s = self.0 as u64 + o.0 as u64;
        BabyBear(if s >= BB_Q { s - BB_Q } else { s } as u32)
    }
    #[inline]
    fn sub(self, o: Self) -> Self {
        BabyBear(if self.0 >= o.0 { self.0 - o.0 } else { (self.0 as u64 + BB_Q - o.0 as u64) as u32 })
    }
    #[inline]
    fn neg(self) -> Self {
        BabyBear(if self.0 == 0 { 0 } else { (BB_Q - self.0 as u64) as u32 })
    }
    #[inline]
    fn mul(self, o: Self) -> Self {
        BabyBear((self.0 as u64 * o.0 as u64 % BB_Q) as u32)
    }
    #[inline]
    fn from_u128(x: u128) -> Self {
        let (lo, hi) = (x as u64 % BB_Q, (x >> 64) as u64 % BB_Q);
        BabyBear(((hi * BB_2_64 + lo) % BB_Q) as u32)
    }
    fn to_u128(self) -> u128 {
        self.0 as u128
    }
    fn random<R: RngCore + ?Sized>(rng: &mut R) -> Self {
        BabyBear::from_u128(((rng.next_u64() as u128) << 64) | rng.next_u64() as u128)
    }
    fn put(self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.0.to_le_bytes());
    }
    fn get(b: &[u8]) -> Self {
        BabyBear(u32::from_le_bytes(b[..4].try_into().unwrap()))
    }
}

/// `F_{q^4} = F_q[X]/(X^4 − 11)` over Babybear (11 is a non-square mod q
/// and q ≡ 1 mod 4, so `X^4 − 11` is irreducible): the MAC field of the
/// arithmetic malicious variant. [`to_u128`](Field::to_u128) packs the four
/// coordinates at bit offsets 0, 31, 62, 93.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct BabyBear4(pub [BabyBear; 4]);

/// `X^4 = W`.
const BB4_W: BabyBear = BabyBear(11);

impl Field for BabyBear4 {
    const BYTES: usize = 16;
    const P_BITS: usize = 124;
    /// Not used: masks in F_{q^4} come from [`mask_value`].
    const KAPPA: usize = 128;
    const ZERO: Self = BabyBear4([BabyBear::ZERO; 4]);
    const ONE: Self = BabyBear4([BabyBear::ONE, BabyBear::ZERO, BabyBear::ZERO, BabyBear::ZERO]);
    #[inline]
    fn add(self, o: Self) -> Self {
        BabyBear4(std::array::from_fn(|i| self.0[i].add(o.0[i])))
    }
    #[inline]
    fn sub(self, o: Self) -> Self {
        BabyBear4(std::array::from_fn(|i| self.0[i].sub(o.0[i])))
    }
    #[inline]
    fn neg(self) -> Self {
        BabyBear4(self.0.map(BabyBear::neg))
    }
    fn mul(self, o: Self) -> Self {
        // Schoolbook in u64 (16 products < 2^62 each), then X^4 = W.
        let (a, b) = (self.0.map(|x| x.0 as u64), o.0.map(|x| x.0 as u64));
        let mut c = [0u64; 7];
        for i in 0..4 {
            for j in 0..4 {
                c[i + j] = (c[i + j] + a[i] * b[j] % BB_Q) % BB_Q;
            }
        }
        BabyBear4(std::array::from_fn(|k| {
            let hi = if k < 3 { BabyBear((c[k + 4]) as u32).mul(BB4_W) } else { BabyBear::ZERO };
            BabyBear(c[k] as u32).add(hi)
        }))
    }
    fn from_u128(x: u128) -> Self {
        BabyBear4(std::array::from_fn(|i| BabyBear::from_u128((x >> (31 * i)) & 0x7fff_ffff)))
    }
    fn to_u128(self) -> u128 {
        self.0.iter().enumerate().fold(0u128, |acc, (i, x)| acc | ((x.0 as u128) << (31 * i)))
    }
    /// `X^{k / 31}·2^{k mod 31}`, the weight of bit k of [`to_u128`](Field::to_u128).
    fn pow2(k: usize) -> Self {
        let mut c = [BabyBear::ZERO; 4];
        c[k / 31] = BabyBear::pow2(k % 31);
        BabyBear4(c)
    }
    fn from_seed(seed: Block) -> Self {
        let w = CtrPrg::new(seed).next_words(4);
        BabyBear4(std::array::from_fn(|i| BabyBear::from_u128(w[i])))
    }
    fn random<R: RngCore + ?Sized>(rng: &mut R) -> Self {
        BabyBear4(std::array::from_fn(|_| BabyBear::random(rng)))
    }
    fn put(self, out: &mut Vec<u8>) {
        self.0.iter().for_each(|x| x.put(out));
    }
    fn get(b: &[u8]) -> Self {
        BabyBear4(std::array::from_fn(|i| BabyBear::get(&b[4 * i..])))
    }
}

impl Ext<BabyBear> for BabyBear4 {
    const DEG: usize = 4;
    #[inline]
    fn embed(x: BabyBear) -> Self {
        BabyBear4([x, BabyBear::ZERO, BabyBear::ZERO, BabyBear::ZERO])
    }
    #[inline]
    fn coord(self, i: usize) -> BabyBear {
        self.0[i]
    }
    #[inline]
    fn from_coords(c: &[BabyBear]) -> Self {
        BabyBear4([c[0], c[1], c[2], c[3]])
    }
}

/// Goldilocks, `p = 2^64 − 2^32 + 1`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Gold(pub u64);

const GOLD_P: u64 = 0xffff_ffff_0000_0001;

impl Gold {
    /// `x mod p` for any 128-bit x: `2^64 ≡ 2^32 − 1` and `2^96 ≡ −1`.
    #[inline]
    fn reduce(x: u128) -> Gold {
        let (lo, hi) = (x as u64, (x >> 64) as u64);
        let (hh, hl) = (hi >> 32, hi & 0xffff_ffff);
        let (mut t, borrow) = lo.overflowing_sub(hh);
        if borrow {
            t = t.wrapping_sub(0xffff_ffff); // + p mod 2^64
        }
        let (mut r, carry) = t.overflowing_add(hl * 0xffff_ffff);
        if carry {
            r = r.wrapping_add(0xffff_ffff); // − p mod 2^64
        }
        Gold(if r >= GOLD_P { r - GOLD_P } else { r })
    }
}

impl Field for Gold {
    const BYTES: usize = 8;
    const P_BITS: usize = 64;
    const KAPPA: usize = 104;
    const ZERO: Self = Gold(0);
    const ONE: Self = Gold(1);
    #[inline]
    fn add(self, o: Self) -> Self {
        let (s, carry) = self.0.overflowing_add(o.0);
        Gold(if carry || s >= GOLD_P { s.wrapping_sub(GOLD_P) } else { s })
    }
    #[inline]
    fn sub(self, o: Self) -> Self {
        let (s, borrow) = self.0.overflowing_sub(o.0);
        Gold(if borrow { s.wrapping_add(GOLD_P) } else { s })
    }
    #[inline]
    fn neg(self) -> Self {
        Gold(if self.0 == 0 { 0 } else { GOLD_P - self.0 })
    }
    #[inline]
    fn mul(self, o: Self) -> Self {
        Gold::reduce(self.0 as u128 * o.0 as u128)
    }
    #[inline]
    fn from_u128(x: u128) -> Self {
        Gold::reduce(x)
    }
    fn to_u128(self) -> u128 {
        self.0 as u128
    }
    fn random<R: RngCore + ?Sized>(rng: &mut R) -> Self {
        Gold::reduce(((rng.next_u64() as u128) << 64) | rng.next_u64() as u128)
    }
    fn put(self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.0.to_le_bytes());
    }
    fn get(b: &[u8]) -> Self {
        Gold(u64::from_le_bytes(b[..8].try_into().unwrap()))
    }
}

/// The Mersenne prime field, `p = 2^127 − 1`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct M127(pub u128);

const M127_P: u128 = (1 << 127) - 1;

impl M127 {
    /// `x mod p` for `x < 2^128`.
    #[inline]
    fn reduce(x: u128) -> M127 {
        let r = (x & M127_P) + (x >> 127);
        M127(if r >= M127_P { r - M127_P } else { r })
    }
}

impl Field for M127 {
    const BYTES: usize = 16;
    const P_BITS: usize = 127;
    const KAPPA: usize = 128;
    const ZERO: Self = M127(0);
    const ONE: Self = M127(1);
    #[inline]
    fn add(self, o: Self) -> Self {
        M127::reduce(self.0 + o.0)
    }
    #[inline]
    fn sub(self, o: Self) -> Self {
        M127::reduce(self.0 + (M127_P - o.0))
    }
    #[inline]
    fn neg(self) -> Self {
        M127::reduce(M127_P - self.0)
    }
    fn mul(self, o: Self) -> Self {
        // The product `hi·2^128 + lo` in 64-bit limbs (a1, b1 < 2^63, so
        // `mid < 2^128` and `hi < 2^127`), then `2^128 ≡ 2`.
        let (a1, a0) = (self.0 >> 64, self.0 & u64::MAX as u128);
        let (b1, b0) = (o.0 >> 64, o.0 & u64::MAX as u128);
        let mid = a0 * b1 + a1 * b0;
        let (lo, c) = (a0 * b0).overflowing_add(mid << 64);
        let hi = a1 * b1 + (mid >> 64) + c as u128;
        M127::reduce(lo).add(M127::reduce(2 * hi))
    }
    #[inline]
    fn from_u128(x: u128) -> Self {
        M127::reduce(x)
    }
    fn to_u128(self) -> u128 {
        self.0
    }
    fn random<R: RngCore + ?Sized>(rng: &mut R) -> Self {
        M127::reduce(((rng.next_u64() as u128) << 64) | rng.next_u64() as u128)
    }
    fn put(self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.0.to_le_bytes());
    }
    fn get(b: &[u8]) -> Self {
        M127(u128::from_le_bytes(b[..16].try_into().unwrap()))
    }
}

/// A COT pad as a field element (domain-separated from the other COT hashes).
#[inline]
fn pad<F: Field>(k: Block, i: usize) -> F {
    F::from_seed(cot_hash().h(k, (5 << 60) | i as u64))
}

/// Batched OLE from COTs, both directions at once: for each i this party
/// selects with `g[i]` and offers the correlation `c[i]`; the outputs `z` of
/// the two parties satisfy `z_0 + z_1 = g_1[i]·c_0[i] + g_0[i]·c_1[i]`.
///
/// From a COT `(K, K ⊕ Δ)` the sender keeps `−H(K)` and sends
/// `u = H(K ⊕ Δ) − H(K) − c`; the receiver, holding `H(K ⊕ g·Δ)`, takes
/// `H(M) − g·u`. Two rounds (derandomisation, then u), one element per COT.
pub fn ole<F: Field, R: RngCore + CryptoRng>(ch: &mut Channel, cot: &mut CotPair, g: &[bool], c: &[F], rng: &mut R) -> Vec<F> {
    let n = g.len();
    assert_eq!(c.len(), n);
    let (k, m) = cot.extend(ch, g, n, rng).expect("semi-honest COT");
    let delta = cot.delta();
    let mut out = Vec::with_capacity(n);
    let mut msg = Vec::with_capacity(n * F::BYTES);
    for i in 0..n {
        let (x0, x1): (F, F) = (pad(k[i], i), pad(k[i] ^ delta, i));
        x1.sub(x0).sub(c[i]).put(&mut msg);
        out.push(x0.neg());
    }
    ch.send(msg);
    let theirs = ch.recv();
    assert_eq!(theirs.len(), n * F::BYTES, "malformed OLE message");
    for (i, u) in theirs.chunks(F::BYTES).map(F::get).enumerate() {
        let y = pad::<F>(m[i], i).sub(if g[i] { u } else { F::ZERO });
        out[i] = out[i].add(y);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    fn arith<F: Field>(p: u128) {
        let mut rng = ChaCha20Rng::seed_from_u64(1);
        // a·b mod p by double-and-add, as the reference (p < 2^127).
        let mulmod = |a: u128, mut b: u128| {
            let (mut r, mut x) = (0u128, a);
            while b > 0 {
                if b & 1 == 1 {
                    r = (r + x) % p;
                }
                x = (x + x) % p;
                b >>= 1;
            }
            r
        };
        for _ in 0..2000 {
            let (a, b) = (F::random(&mut rng), F::random(&mut rng));
            let (x, y) = (a.to_u128(), b.to_u128());
            assert!(x < p && y < p);
            assert_eq!(a.add(b).to_u128(), (x + y) % p);
            assert_eq!(a.sub(b).to_u128(), (x + (p - y)) % p);
            assert_eq!(a.add(a.neg()), F::ZERO);
            assert_eq!(a.mul(b).to_u128(), mulmod(x, y));
        }
        for x in [0u128, 1, p - 1, p, p + 1, u128::MAX, u128::MAX - 7, 1 << 127, (1 << 96) + 12345] {
            assert_eq!(F::from_u128(x).to_u128(), x % p, "x={x}");
        }
    }

    #[test]
    fn goldilocks() {
        arith::<Gold>(GOLD_P as u128);
    }

    #[test]
    fn mersenne_127() {
        arith::<M127>(M127_P);
    }

    #[test]
    fn babybear() {
        arith::<BabyBear>(BB_Q as u128);
    }

    /// `x^e` by square-and-multiply.
    fn pow<F: Field>(x: F, mut e: u128) -> F {
        let (mut r, mut b) = (F::ONE, x);
        while e > 0 {
            if e & 1 == 1 {
                r = r.mul(b);
            }
            b = b.mul(b);
            e >>= 1;
        }
        r
    }

    #[test]
    fn babybear4_is_a_field() {
        let q = BB_Q as u128;
        // 11 is a non-square (Euler) and q ≡ 1 mod 4: X^4 − 11 is irreducible.
        assert_eq!(pow(BB4_W, (q - 1) / 2), BabyBear::ONE.neg());
        assert_eq!(q % 4, 1);
        let mut rng = ChaCha20Rng::seed_from_u64(3);
        let x4 = BabyBear4::pow2(93); // X^3
        assert_eq!(x4.mul(BabyBear4::pow2(31)), BabyBear4::embed(BB4_W), "X^4 = 11");
        for _ in 0..200 {
            let (a, b, c) = (BabyBear4::random(&mut rng), BabyBear4::random(&mut rng), BabyBear4::random(&mut rng));
            assert_eq!(a.mul(b), b.mul(a));
            assert_eq!(a.mul(b.mul(c)), a.mul(b).mul(c));
            assert_eq!(a.mul(b.add(c)), a.mul(b).add(a.mul(c)));
            assert_eq!(a.add(a.neg()), BabyBear4::ZERO);
            // Fermat in F_{q^4}.
            assert_eq!(pow(a, q.pow(4) - 1), BabyBear4::ONE);
            assert_eq!(BabyBear4::from_u128(a.to_u128()), a);
            let x = (0..124).filter(|&k| a.to_u128() >> k & 1 == 1).fold(BabyBear4::ZERO, |s, k| s.add(BabyBear4::pow2(k)));
            assert_eq!(x, a, "bit weights");
        }
    }
}
