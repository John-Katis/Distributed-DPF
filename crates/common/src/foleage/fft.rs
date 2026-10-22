//! The FFT of FOLEAGE (§4.3, `libs/fft`): evaluation of an element of
//! `F4[X_1, …, X_N]/(X_i³ − 1)` at all `3^N` points of `{1, ω, ω²}^N`, on
//! packed words so that every 2-bit lane carries an independent polynomial.
//!
//! Coefficient `i` belongs to the monomial whose exponent vector is the
//! ternary expansion of `i`. One variable at a time, the coefficients
//! `(c_L, c_M, c_R)` of `X^0, X^1, X^2` become
//!
//! ```text
//! (c_L + c_M + c_R,  c_L + c_R + ω(c_M + c_R),  c_L + c_M + ω(c_M + c_R))
//! ```
//!
//! the values at `1, ω, ω²` (with `ω² = ω + 1`). The variables are processed
//! from the lowest trit up; the reference recursion does the top trit last,
//! which gives the same result since the per-variable maps commute.

use crate::f4::{mul_omega_packed, Packed};

/// In-place FFT of `3^n` packed coefficients.
pub fn fft<T: Packed>(coeffs: &mut [T]) {
    let n = coeffs.len();
    let mut stride = 1;
    while stride < n {
        assert_eq!(n % (3 * stride), 0, "length must be a power of 3");
        for base in (0..n).step_by(3 * stride) {
            for j in base..base + stride {
                let (l, m, r) = (coeffs[j], coeffs[j + stride], coeffs[j + 2 * stride]);
                let w = mul_omega_packed(m ^ r);
                coeffs[j] = l ^ m ^ r;
                coeffs[j + stride] = l ^ r ^ w;
                coeffs[j + 2 * stride] = l ^ m ^ w;
            }
        }
        stride *= 3;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::f4;
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha20Rng;

    /// `ω^e` for `e ∈ Z_3`.
    fn omega_pow(e: usize) -> u8 {
        [1, f4::OMEGA, f4::OMEGA2][e % 3]
    }

    fn trits(mut x: usize, n: usize) -> Vec<usize> {
        (0..n).map(|_| {
            let t = x % 3;
            x /= 3;
            t
        }).collect()
    }

    /// Naive evaluation: the point with trits `p` is `(ω^{p_1}, …, ω^{p_n})`.
    fn eval_naive(c: &[u8], n: usize, point: usize) -> u8 {
        let p = trits(point, n);
        (0..c.len()).fold(0, |acc, i| {
            let e = trits(i, n);
            let mon = omega_pow(e.iter().zip(&p).map(|(a, b)| a * b).sum());
            acc ^ f4::mul(c[i], mon)
        })
    }

    #[test]
    fn fft_evaluates_and_is_multiplicative() {
        let mut rng = ChaCha20Rng::seed_from_u64(5);
        let n = 4;
        let len = 81;
        let a: Vec<u8> = (0..len).map(|_| rng.gen_range(0..4)).collect();
        let b: Vec<u8> = (0..len).map(|_| rng.gen_range(0..4)).collect();
        // Lane 0 holds a, lane 3 holds b.
        let mut packed: Vec<u8> = (0..len).map(|i| a[i] | b[i] << 6).collect();
        fft(&mut packed);
        for k in 0..len {
            assert_eq!(packed[k].lane(0), eval_naive(&a, n, k), "point {k}");
            assert_eq!(packed[k].lane(3), eval_naive(&b, n, k), "point {k}");
        }
        // The product in the group algebra (exponents added trit-wise mod 3)
        // evaluates to the pointwise product.
        let mut prod = vec![0u8; len];
        for i in 0..len {
            for j in 0..len {
                let (ti, tj) = (trits(i, n), trits(j, n));
                let k = (0..n).rev().fold(0, |acc, v| acc * 3 + (ti[v] + tj[v]) % 3);
                prod[k] ^= f4::mul(a[i], b[j]);
            }
        }
        let mut p: Vec<u32> = prod.iter().map(|&x| x as u32).collect();
        fft(&mut p);
        for k in 0..len {
            assert_eq!(p[k].lane(0), f4::mul(packed[k].lane(0), packed[k].lane(3)));
        }
    }
}
