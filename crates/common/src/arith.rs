//! Arithmetic over Z_2^ℓ (ℓ ≤ 64) and the OT-based arithmetic multiplexer.
//!
//! Ring elements are `u64` values reduced with [`mask`]. [`mux`] is
//! F^{A,ℓ}_MUX of NDSS'25 (instantiated as in SIRNN): from an XOR-shared
//! selector `g` and additive shares of `W0`, `W1`, it outputs additive shares of
//! `W_g`, using one correlated OT per selection in each direction.

use crate::block::Block;
use crate::coin::Abort;
use crate::hash::cot_hash;
use crate::net::Channel;
use crate::ot::CotPair;
use rand::{CryptoRng, RngCore};

/// `2^bits − 1`, the reduction mask of Z_2^bits.
#[inline]
pub fn mask(bits: usize) -> u64 {
    assert!((1..=64).contains(&bits), "ring width must be 1..=64 bits");
    if bits == 64 { u64::MAX } else { (1u64 << bits) - 1 }
}

/// `Convert_R` for a pseudorandom 128-bit seed: bits 1..=bits of `s`. Bit 0 is
/// skipped because the GGM leaf seeds carry the t-bit there.
#[inline]
pub fn convert(s: Block, bits: usize) -> u64 {
    ((s.0 >> 1) as u64) & mask(bits)
}

/// `(-1)^b · x mod 2^bits`.
#[inline]
pub fn signed(b: bool, x: u64, bits: usize) -> u64 {
    (if b { x.wrapping_neg() } else { x }) & mask(bits)
}

/// Turns a COT key into a ring element: `H(k, tweak)` truncated.
#[inline]
fn pad(k: Block, tweak: u64, bits: usize) -> u64 {
    (cot_hash().h(k, tweak).0 as u64) & mask(bits)
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
/// one ℓ-bit word per COT, 2(λ + ℓ) bits per selection in total.
pub fn mux<R: RngCore + CryptoRng>(
    ch: &mut Channel,
    cot: &mut CotPair,
    g: &[bool],
    w0: &[u64],
    w1: &[u64],
    bits: usize,
    rng: &mut R,
) -> Result<Vec<u64>, Abort> {
    let n = g.len();
    assert!(w0.len() == n && w1.len() == n);
    let m = mask(bits);
    let (k, mm) = cot.extend(ch, g, n, rng)?;
    let delta = cot.delta();

    // Sender side: correlation c_b = (1 − 2g_b)·D_b.
    let mut out: Vec<u64> = Vec::with_capacity(n);
    let mut msgs = Vec::with_capacity(n);
    for i in 0..n {
        let d = w1[i].wrapping_sub(w0[i]) & m;
        let c = signed(g[i], d, bits);
        let x0 = pad(k[i], i as u64, bits);
        let x1 = pad(k[i] ^ delta, i as u64, bits);
        msgs.push(x1.wrapping_sub(x0).wrapping_sub(c) & m);
        let local = if g[i] { d } else { 0 };
        out.push(w0[i].wrapping_add(local).wrapping_sub(x0) & m);
    }
    ch.send(msgs.iter().flat_map(|x| x.to_le_bytes()).collect());

    // Receiver side: H(M) − g_b·u for the peer's correlation.
    let theirs = ch.recv();
    if theirs.len() != 8 * n {
        return Err(Abort("malformed MUX message"));
    }
    for i in 0..n {
        let u = u64::from_le_bytes(theirs[8 * i..8 * i + 8].try_into().unwrap());
        let y = pad(mm[i], i as u64, bits).wrapping_sub(if g[i] { u } else { 0 });
        out[i] = out[i].wrapping_add(y) & m;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::run_two_party;
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn mux_selects() {
        for bits in [1usize, 7, 32, 64] {
            let m = mask(bits);
            let mut rng = ChaCha20Rng::seed_from_u64(bits as u64);
            let n = 50;
            let g: Vec<bool> = (0..n).map(|_| rng.gen()).collect();
            let w0: Vec<u64> = (0..n).map(|_| rng.gen::<u64>() & m).collect();
            let w1: Vec<u64> = (0..n).map(|_| rng.gen::<u64>() & m).collect();
            let g0: Vec<bool> = (0..n).map(|_| rng.gen()).collect();
            let g1: Vec<bool> = g.iter().zip(&g0).map(|(a, b)| a ^ b).collect();
            let a0: Vec<u64> = (0..n).map(|_| rng.gen::<u64>() & m).collect();
            let b0: Vec<u64> = (0..n).map(|_| rng.gen::<u64>() & m).collect();
            let a1: Vec<u64> = w0.iter().zip(&a0).map(|(w, a)| w.wrapping_sub(*a) & m).collect();
            let b1: Vec<u64> = w1.iter().zip(&b0).map(|(w, b)| w.wrapping_sub(*b) & m).collect();
            let (y0, y1) = run_two_party(
                move |c| {
                    let mut r = ChaCha20Rng::seed_from_u64(1);
                    let d = Block::random(&mut r);
                    let mut cot = CotPair::setup(c, &mut r, d, false).unwrap();
                    mux(c, &mut cot, &g0, &a0, &b0, bits, &mut r).unwrap()
                },
                move |c| {
                    let mut r = ChaCha20Rng::seed_from_u64(2);
                    let d = Block::random(&mut r);
                    let mut cot = CotPair::setup(c, &mut r, d, false).unwrap();
                    mux(c, &mut cot, &g1, &a1, &b1, bits, &mut r).unwrap()
                },
            );
            for i in 0..n {
                let want = if g[i] { w1[i] } else { w0[i] };
                assert_eq!(y0[i].wrapping_add(y1[i]) & m, want, "bits={bits} i={i}");
            }
        }
    }
}
