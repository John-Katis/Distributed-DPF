//! Arithmetic over Z_2^ℓ and the OT-based arithmetic multiplexer.
//!
//! Ring elements are machine words of a [`Ring`] type: `u64` for ℓ ≤ 64 and
//! `u128` for 64 < ℓ ≤ 128, so a protocol over Z_2^64 computes and sends
//! 64-bit words and one over Z_2^128 128-bit words. Values are reduced with
//! [`Ring::mask`]. [`mux`] is F^{A,ℓ}_MUX of NDSS'25 (instantiated as in
//! SIRNN): from an XOR-shared selector `g` and additive shares of `W0`, `W1`,
//! it outputs additive shares of `W_g`, using one correlated OT per selection
//! in each direction.

use crate::block::Block;
use crate::coin::Abort;
use crate::hash::cot_hash;
use crate::net::Channel;
use crate::ot::CotPair;
use rand::{CryptoRng, RngCore};
use std::fmt::Debug;

/// `2^bits − 1` as a `u64`, `1 ≤ bits ≤ 64` (also used for domain masks).
#[inline]
pub fn mask(bits: usize) -> u64 {
    <u64 as Ring>::mask(bits)
}

/// A ring Z_2^w (w = [`BITS`](Ring::BITS)) whose elements also represent
/// Z_2^ℓ for every ℓ ≤ w after reduction with [`mask`](Ring::mask).
pub trait Ring: Copy + Default + Eq + Ord + Debug + Send + Sync + 'static {
    /// Width of the machine word.
    const BITS: usize;
    /// Bytes of one word on the wire.
    const BYTES: usize = Self::BITS / 8;
    const ZERO: Self;
    const ONE: Self;
    /// `2^bits − 1`, `1 ≤ bits ≤ BITS`.
    fn mask(bits: usize) -> Self;
    fn add(self, o: Self) -> Self;
    fn sub(self, o: Self) -> Self;
    fn neg(self) -> Self;
    fn mul(self, o: Self) -> Self;
    fn and(self, o: Self) -> Self;
    fn shl(self, k: usize) -> Self;
    fn bit(self, i: usize) -> bool;
    fn from_u64(x: u64) -> Self;
    /// The low 64 bits.
    fn low_u64(self) -> u64;
    /// The low `BITS` bits of a block.
    fn from_block(b: Block) -> Self;
    fn random<R: RngCore + ?Sized>(rng: &mut R) -> Self;
    /// Appends the `BYTES` little-endian bytes.
    fn put(self, out: &mut Vec<u8>);
    /// Reads `BYTES` little-endian bytes.
    fn get(b: &[u8]) -> Self;
}

macro_rules! ring_impl {
    ($t:ty, $rand:ident) => {
        impl Ring for $t {
            const BITS: usize = <$t>::BITS as usize;
            const ZERO: Self = 0;
            const ONE: Self = 1;
            #[inline]
            fn mask(bits: usize) -> Self {
                assert!((1..=<Self as Ring>::BITS).contains(&bits), "ring width must be 1..={} bits", <Self as Ring>::BITS);
                if bits == <Self as Ring>::BITS { <$t>::MAX } else { (1 << bits) - 1 }
            }
            #[inline]
            fn add(self, o: Self) -> Self {
                self.wrapping_add(o)
            }
            #[inline]
            fn sub(self, o: Self) -> Self {
                self.wrapping_sub(o)
            }
            #[inline]
            fn neg(self) -> Self {
                self.wrapping_neg()
            }
            #[inline]
            fn mul(self, o: Self) -> Self {
                self.wrapping_mul(o)
            }
            #[inline]
            fn and(self, o: Self) -> Self {
                self & o
            }
            #[inline]
            fn shl(self, k: usize) -> Self {
                self << k
            }
            #[inline]
            fn bit(self, i: usize) -> bool {
                (self >> i) & 1 == 1
            }
            #[inline]
            fn from_u64(x: u64) -> Self {
                x as $t
            }
            #[inline]
            fn low_u64(self) -> u64 {
                self as u64
            }
            #[inline]
            fn from_block(b: Block) -> Self {
                b.0 as $t
            }
            #[inline]
            fn random<R: RngCore + ?Sized>(rng: &mut R) -> Self {
                $rand(rng)
            }
            #[inline]
            fn put(self, out: &mut Vec<u8>) {
                out.extend(self.to_le_bytes());
            }
            #[inline]
            fn get(b: &[u8]) -> Self {
                <$t>::from_le_bytes(b.try_into().expect("ring word length"))
            }
        }
    };
}

fn rand_u64<R: RngCore + ?Sized>(rng: &mut R) -> u64 {
    rng.next_u64()
}

fn rand_u128<R: RngCore + ?Sized>(rng: &mut R) -> u128 {
    let lo = rng.next_u64() as u128;
    lo | (rng.next_u64() as u128) << 64
}

ring_impl!(u64, rand_u64);
ring_impl!(u128, rand_u128);

/// `Convert_R` for a pseudorandom 128-bit seed: bits 1..=bits of `s`, for
/// `bits ≤ 127`. Bit 0 is skipped because the GGM leaf seeds carry the t-bit
/// there; a 128-bit output needs more PRG output than the seed has.
#[inline]
pub fn convert<R: Ring>(s: Block, bits: usize) -> R {
    assert!(bits < 128, "a seed has 127 bits above its t-bit");
    R::from_block(Block(s.0 >> 1)).and(R::mask(bits))
}

/// `(-1)^b · x mod 2^bits`.
#[inline]
pub fn signed<R: Ring>(b: bool, x: R, bits: usize) -> R {
    (if b { x.neg() } else { x }).and(R::mask(bits))
}

/// Turns a COT key into a ring element: `H(k, tweak)` truncated.
#[inline]
fn pad<R: Ring>(k: Block, tweak: u64, bits: usize) -> R {
    R::from_block(cot_hash().h(k, tweak)).and(R::mask(bits))
}

/// [`mux`] by SiRNN's own multiplexer in SCI ([`crate::ot::sci`]), as XLH+25
/// instantiate F^{A,ℓ}_MUX, for `bits ≤ 64`: shares of `W_g = W_0 + g·(W_1 − W_0)`
/// with SCI computing `g·(W_1 − W_0)`.
pub fn mux_sci<T: Ring>(ch: &mut Channel, sci: &mut crate::ot::sci::Sci, g: &[bool], w0: &[T], w1: &[T], bits: usize) -> Result<Vec<T>, Abort> {
    assert!(bits <= 64, "SCI's multiplexer works on 64-bit words");
    assert!(w0.len() == g.len() && w1.len() == g.len());
    let m = T::mask(bits);
    let x: Vec<u64> = w0.iter().zip(w1).map(|(a, b)| b.sub(*a).and(m).low_u64()).collect();
    let y = sci.mux(ch, g, &x, bits)?;
    Ok(w0.iter().zip(y).map(|(a, yi)| a.add(T::from_u64(yi)).and(m)).collect())
}

/// Additive shares of `W_{g_i}` for each i, given this party's XOR share of
/// every `g_i` and additive shares of `W0_i`, `W1_i` in Z_2^bits.
///
/// This is SIRNN's optimised F_MUX (App. C), the instantiation XLH+25 names
/// (and the reference code's `multiplexer2`): with `D = W1 − W0` and
/// `g = g_0 ⊕ g_1`,
///
/// ```text
/// g·D = g_0·D_0 + g_1·D_1 + g_1·(1 − 2g_0)·D_0 + g_0·(1 − 2g_1)·D_1.
/// ```
///
/// The first two terms are local. For the cross term `g_{1−b}·c_b` with
/// `c_b = (1 − 2g_b)·D_b`, party b is the sender of a correlated OT with
/// correlation `c_b` and the peer selects with `g_{1−b}`. From a COT
/// `(K, K ⊕ Δ)` the sender keeps `−H(K)` and sends the single word
/// `u = H(K ⊕ Δ) − H(K) − c_b`; the receiver gets `H(M) − g_{1−b}·u`. That is
/// one word per COT (`T::BYTES` bytes), 2(λ + |T|) bits per selection in
/// total.
pub fn mux<T: Ring, R: RngCore + CryptoRng>(
    ch: &mut Channel,
    cot: &mut CotPair,
    g: &[bool],
    w0: &[T],
    w1: &[T],
    bits: usize,
    rng: &mut R,
) -> Result<Vec<T>, Abort> {
    let n = g.len();
    assert!(w0.len() == n && w1.len() == n);
    let m = T::mask(bits);
    let (k, mm) = cot.extend(ch, g, n, rng)?;
    let delta = cot.delta();

    // Sender side: correlation c_b = (1 − 2g_b)·D_b.
    let mut out: Vec<T> = Vec::with_capacity(n);
    let mut msg = Vec::with_capacity(n * T::BYTES);
    for i in 0..n {
        let d = w1[i].sub(w0[i]).and(m);
        let c = signed(g[i], d, bits);
        let x0: T = pad(k[i], i as u64, bits);
        let x1: T = pad(k[i] ^ delta, i as u64, bits);
        x1.sub(x0).sub(c).and(m).put(&mut msg);
        let local = if g[i] { d } else { T::ZERO };
        out.push(w0[i].add(local).sub(x0).and(m));
    }
    ch.send(msg);

    // Receiver side: H(M) − g_b·u for the peer's correlation.
    let theirs = ch.recv();
    if theirs.len() != T::BYTES * n {
        return Err(Abort("malformed MUX message"));
    }
    for (i, u) in theirs.chunks(T::BYTES).map(T::get).enumerate() {
        let y = pad::<T>(mm[i], i as u64, bits).sub(if g[i] { u } else { T::ZERO });
        out[i] = out[i].add(y).and(m);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::run_two_party;
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha20Rng;

    fn mux_selects_in<T: Ring>(widths: &[usize]) {
        for &bits in widths {
            let m = T::mask(bits);
            let mut rng = ChaCha20Rng::seed_from_u64(bits as u64);
            let n = 50;
            let rnd = |rng: &mut ChaCha20Rng| T::random(rng).and(m);
            let g: Vec<bool> = (0..n).map(|_| rng.gen()).collect();
            let w0: Vec<T> = (0..n).map(|_| rnd(&mut rng)).collect();
            let w1: Vec<T> = (0..n).map(|_| rnd(&mut rng)).collect();
            let g0: Vec<bool> = (0..n).map(|_| rng.gen()).collect();
            let g1: Vec<bool> = g.iter().zip(&g0).map(|(a, b)| a ^ b).collect();
            let a0: Vec<T> = (0..n).map(|_| rnd(&mut rng)).collect();
            let b0: Vec<T> = (0..n).map(|_| rnd(&mut rng)).collect();
            let a1: Vec<T> = w0.iter().zip(&a0).map(|(w, a)| w.sub(*a).and(m)).collect();
            let b1: Vec<T> = w1.iter().zip(&b0).map(|(w, b)| w.sub(*b).and(m)).collect();
            let party = |seed: u64, g: Vec<bool>, a: Vec<T>, b: Vec<T>| {
                move |c: &mut Channel| {
                    let mut r = ChaCha20Rng::seed_from_u64(seed);
                    let d = Block::random(&mut r);
                    let mut cot = CotPair::setup(c, &mut r, d, false).unwrap();
                    let y = mux(c, &mut cot, &g, &a, &b, bits, &mut r).unwrap();
                    (y, c.stats().bytes_sent)
                }
            };
            let ((y0, _), (y1, _)) = run_two_party(party(1, g0, a0, b0), party(2, g1, a1, b1));
            for i in 0..n {
                let want = if g[i] { w1[i] } else { w0[i] };
                assert_eq!(y0[i].add(y1[i]).and(m), want, "bits={bits} i={i}");
            }
        }
    }

    #[test]
    fn mux_selects() {
        mux_selects_in::<u64>(&[1, 7, 32, 64]);
        mux_selects_in::<u128>(&[1, 65, 127, 128]);
    }

    #[test]
    fn ring_words() {
        assert_eq!(<u128 as Ring>::mask(128), u128::MAX);
        assert_eq!(<u128 as Ring>::mask(70), (1 << 70) - 1);
        assert_eq!(<u64 as Ring>::ONE.neg(), u64::MAX);
        let x: u128 = 0x0123_4567_89ab_cdef_fedc_ba98_7654_3210;
        let mut b = Vec::new();
        x.put(&mut b);
        assert_eq!((b.len(), <u128 as Ring>::get(&b)), (16, x));
        assert_eq!(convert::<u128>(Block(u128::MAX), 127), u128::MAX >> 1);
        assert_eq!(convert::<u64>(Block(0b110), 2), 0b11);
    }
}
