//! Prime fields for the arithmetic malicious variant, and the COT-based OLE
//! its leaf is built from.
//!
//! The payload-MAC argument of the paper (Propositions "MAC Detection") bounds
//! a forgery by `Pr[δ·Δ_val = Δ_mac] ≤ 1/|G|`, which needs every nonzero
//! `Δ_val` to be invertible: G must be a field. We take one prime per output
//! width, `p ≈ 2^ℓ`: Goldilocks `2^64 − 2^32 + 1` for ℓ ≤ 64 and the Mersenne
//! prime `2^127 − 1` above. Payload, δ and MACs all live in F_p.

use dpf_common::block::Block;
use dpf_common::hash::cot_hash;
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

    /// `2^k mod p`.
    fn pow2(k: usize) -> Self {
        Self::from_u128(1u128 << k)
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
    F::from_u128(cot_hash().h(k, (5 << 60) | i as u64).0)
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
}
