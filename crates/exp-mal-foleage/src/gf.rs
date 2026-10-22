//! GF(2^128) as an F4-algebra: the embedding `ι: F4 → GF(2^128)`, the square
//! root (for `Γ = √Δ`), the FOLEAGE FFT on GF(2^128)-valued vectors, and the
//! conversion of two MAC lanes into bit MACs.
//!
//! **Bit MACs from two lanes.** For a shared `v ∈ F4` the PCG gives shares of
//! `μ = ι(v)·Δ` and `ν = ι(v)·Γ` with `Γ² = Δ`. Squaring is F2-linear, so the
//! squared shares of ν are shares of `ι(v)²·Γ² = ι(v²)·Δ =: μ'`. With
//! `v = hω + l`: `h = v + v²` and `l = ω²v + ωv²`, hence
//! `M(h) = μ + μ'` and `M(l) = ι(ω²)μ + ι(ω)μ'`: SPDZ MACs on both bits under
//! Δ, the form of [`dpf_common::mac::af4::ABit`].

use dpf_common::block::Block;
use dpf_common::f4;
use dpf_common::gf128;
use dpf_common::mac::af4::{cube_root, ABit};

/// `ι(c)` for `c ∈ F4` (`ι(ω) = w`, the cube root of unity of [`cube_root`]).
#[inline]
pub fn iota(c: u8) -> Block {
    cube_root().and_bit(c & 2 == 2) ^ Block((c & 1) as u128)
}

/// `ι(c)·x`.
#[inline]
pub fn scale(c: u8, x: Block) -> Block {
    match c & 3 {
        0 => Block::ZERO,
        1 => x,
        _ => gf128::mul(iota(c), x),
    }
}

/// `√x = x^{2^127}`.
pub fn sqrt(x: Block) -> Block {
    (0..127).fold(x, |y, _| gf128::mul(y, y))
}

/// The FFT of [`dpf_common::foleage::fft`] on GF(2^128)-valued coefficients
/// (ω acts as multiplication by w).
pub fn fft_gf(c: &mut [Block]) {
    let n = c.len();
    let w = cube_root();
    let mut stride = 1;
    while stride < n {
        for base in (0..n).step_by(3 * stride) {
            for j in base..base + stride {
                let (l, m, r) = (c[j], c[j + stride], c[j + 2 * stride]);
                let t = gf128::mul(w, m ^ r);
                c[j] = l ^ m ^ r;
                c[j + stride] = l ^ r ^ t;
                c[j + 2 * stride] = l ^ m ^ t;
            }
        }
        stride *= 3;
    }
}

/// This party's bit MACs `(M(h), M(l))` from its shares of `ι(v)Δ` and `ι(v)Γ`,
/// with its share `v_b` of the value.
#[inline]
pub fn bit_macs(v_share: u8, mu: Block, nu: Block) -> (ABit, ABit) {
    let mu2 = gf128::mul(nu, nu);
    let mh = mu ^ mu2;
    let ml = scale(f4::OMEGA2, mu) ^ scale(f4::OMEGA, mu2);
    (ABit { x: v_share & 2 == 2, m: mh }, ABit { x: v_share & 1 == 1, m: ml })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn embedding_and_sqrt() {
        for a in 0..4u8 {
            for b in 0..4u8 {
                assert_eq!(gf128::mul(iota(a), iota(b)), iota(f4::mul(a, b)));
                assert_eq!(iota(a) ^ iota(b), iota(a ^ b));
            }
        }
        let mut rng = ChaCha20Rng::seed_from_u64(1);
        let x = Block::random(&mut rng);
        let r = sqrt(x);
        assert_eq!(gf128::mul(r, r), x);
        let _ = rng.gen::<u8>();
    }

    #[test]
    fn bit_macs_open() {
        let mut rng = ChaCha20Rng::seed_from_u64(2);
        let d = [Block::random(&mut rng), Block::random(&mut rng)];
        let (delta, gamma) = (d[0] ^ d[1], sqrt(d[0]) ^ sqrt(d[1]));
        for v in 0..4u8 {
            let v0: u8 = rng.gen_range(0..4);
            let (mu0, nu0) = (Block::random(&mut rng), Block::random(&mut rng));
            let (mu1, nu1) = (mu0 ^ scale(v, delta), nu0 ^ scale(v, gamma));
            let (h0, l0) = bit_macs(v0, mu0, nu0);
            let (h1, l1) = bit_macs(v ^ v0, mu1, nu1);
            assert_eq!(h0.m ^ h1.m, delta.and_bit(v & 2 == 2));
            assert_eq!(l0.m ^ l1.m, delta.and_bit(v & 1 == 1));
            assert_eq!(((h0.x ^ h1.x) as u8) << 1 | (l0.x ^ l1.x) as u8, v);
        }
    }
}
