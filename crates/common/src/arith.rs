//! Arithmetic over Z_2^ℓ (ℓ ≤ 64) and the OT-based arithmetic multiplexer.
//!
//! Ring elements are `u64` values reduced with [`mask`]. [`mux`] is
//! F^{A,ℓ}_MUX of NDSS'25 (instantiated as in SIRNN): from an XOR-shared
//! selector `g` and additive shares of `W0`, `W1`, it outputs additive shares of
//! `W_g`, using one COT per selection in each direction.

use crate::block::Block;
use crate::coin::Abort;
use crate::hash::cot_hash;
use crate::net::Channel;
use crate::ot::CotPair;
use rand::{CryptoRng, Rng, RngCore};

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
/// With `D = W1 − W0 = D_0 + D_1` and `g = g_0 ⊕ g_1`, each party `b` acts as OT
/// sender for the term `g·D_b`: the peer selects with `g_{1−b}` between
/// `(g_b ⊕ c)·D_b − r_b` for `c ∈ {0,1}`, and party `b` keeps `r_b`. The COTs
/// are derandomised with `H(K)`, `H(K ⊕ Δ)`. Two flights (semi-honest COT).
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

    // Sender side: party b's own term g·D_b.
    let mut out: Vec<u64> = Vec::with_capacity(n);
    let mut msgs = Vec::with_capacity(2 * n);
    for i in 0..n {
        let d = w1[i].wrapping_sub(w0[i]) & m;
        let r: u64 = rng.gen::<u64>() & m;
        let m0 = (if g[i] { d } else { 0 }).wrapping_sub(r) & m;
        let m1 = (if g[i] { 0 } else { d }).wrapping_sub(r) & m;
        msgs.push(m0.wrapping_add(pad(k[i], i as u64, bits)) & m);
        msgs.push(m1.wrapping_add(pad(k[i] ^ delta, i as u64, bits)) & m);
        out.push(w0[i].wrapping_add(r) & m);
    }
    ch.send(msgs.iter().flat_map(|x| x.to_le_bytes()).collect());

    // Receiver side: the peer's term g·D_{1−b}, selected with g_b.
    let theirs = ch.recv();
    if theirs.len() != 16 * n {
        return Err(Abort("malformed MUX message"));
    }
    for i in 0..n {
        let off = (2 * i + g[i] as usize) * 8;
        let e = u64::from_le_bytes(theirs[off..off + 8].try_into().unwrap());
        out[i] = out[i].wrapping_add(e.wrapping_sub(pad(mm[i], i as u64, bits))) & m;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::run_two_party;
    use rand::SeedableRng;
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
                    let mut cot = CotPair::setup(c, &mut r, d, false);
                    mux(c, &mut cot, &g0, &a0, &b0, bits, &mut r).unwrap()
                },
                move |c| {
                    let mut r = ChaCha20Rng::seed_from_u64(2);
                    let d = Block::random(&mut r);
                    let mut cot = CotPair::setup(c, &mut r, d, false);
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
