//! Arithmetic in GF(2^64) = F_2[X]/(X^64 + X^4 + X^3 + X + 1).
//!
//! Bit `i` of a `u64` is the coefficient of `X^i`, so addition is XOR and `1`
//! is the multiplicative identity. The MAC field of the malicious DPF with a
//! Boolean payload of at most 64 bits.

use crate::gf128::clmul;

/// Reduces `hi·X^64 + lo` modulo X^64 + X^4 + X^3 + X + 1.
#[inline]
fn reduce(hi: u64, lo: u64) -> u64 {
    // X^64 ≡ X^4 + X^3 + X + 1. Folding `hi` overflows by at most 4 bits,
    // which a second fold absorbs.
    let over = (hi >> 63) ^ (hi >> 61) ^ (hi >> 60);
    let lo = lo ^ hi ^ (hi << 1) ^ (hi << 3) ^ (hi << 4);
    lo ^ over ^ (over << 1) ^ (over << 3) ^ (over << 4)
}

/// Product in GF(2^64).
#[inline]
pub fn mul(a: u64, b: u64) -> u64 {
    let (_, p) = clmul(a as u128, b as u128);
    reduce((p >> 64) as u64, p as u64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha20Rng;

    fn pow(a: u64, mut e: u128) -> u64 {
        let (mut r, mut b) = (1u64, a);
        while e != 0 {
            if e & 1 == 1 {
                r = mul(r, b);
            }
            b = mul(b, b);
            e >>= 1;
        }
        r
    }

    #[test]
    fn field_laws() {
        let mut rng = ChaCha20Rng::seed_from_u64(1);
        for _ in 0..500 {
            let (a, b, c): (u64, u64, u64) = (rng.gen(), rng.gen(), rng.gen());
            assert_eq!(mul(a, b), mul(b, a));
            assert_eq!(mul(a, b ^ c), mul(a, b) ^ mul(a, c));
            assert_eq!(mul(mul(a, b), c), mul(a, mul(b, c)));
            assert_eq!(mul(a, 1), a);
            if a != 0 {
                // Fermat: a^(2^64 − 1) = 1, which fails if the polynomial is reducible.
                assert_eq!(pow(a, u64::MAX as u128), 1);
            }
        }
    }

    #[test]
    fn reduction_polynomial() {
        // X^63 · X = X^64 = X^4 + X^3 + X + 1.
        assert_eq!(mul(1 << 63, 2), 0b11011);
        assert_eq!(mul(1 << 3, 1 << 4), 1 << 7);
        // X^63 · X^63 = X^126: the fold that overflows.
        assert_eq!(mul(1 << 63, 1 << 63), pow(2, 126));
    }
}
