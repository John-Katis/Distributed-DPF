//! Arithmetic in GF(2^128) = F_2[X]/(X^128 + X^7 + X^2 + X + 1).
//!
//! Bit `i` of a [`Block`] is the coefficient of `X^i`, so addition is XOR and
//! `Block(1)` is the multiplicative identity. Multiplication uses `pclmulqdq`
//! when the CPU has it and a portable carry-less multiply otherwise. The KOS
//! consistency check and the MAC batch checks are the main users.

use crate::block::Block;

/// Portable 64×64 → 128 carry-less multiply.
#[inline]
fn clmul64_soft(a: u64, b: u64) -> u128 {
    let a = a as u128;
    let mut r = 0u128;
    let mut b = b;
    let mut i = 0;
    while b != 0 {
        if b & 1 == 1 {
            r ^= a << i;
        }
        b >>= 1;
        i += 1;
    }
    r
}

/// 128×128 → 256 carry-less multiply as (hi, lo).
#[inline]
fn clmul128_soft(a: u128, b: u128) -> (u128, u128) {
    let (a0, a1) = (a as u64, (a >> 64) as u64);
    let (b0, b1) = (b as u64, (b >> 64) as u64);
    let lo = clmul64_soft(a0, b0);
    let hi = clmul64_soft(a1, b1);
    let mid = clmul64_soft(a0, b1) ^ clmul64_soft(a1, b0);
    (hi ^ (mid >> 64), lo ^ (mid << 64))
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "pclmulqdq,sse2")]
unsafe fn clmul128_hw(a: u128, b: u128) -> (u128, u128) {
    use core::arch::x86_64::*;
    let av = _mm_set_epi64x((a >> 64) as i64, a as i64);
    let bv = _mm_set_epi64x((b >> 64) as i64, b as i64);
    let lo = _mm_clmulepi64_si128(av, bv, 0x00);
    let hi = _mm_clmulepi64_si128(av, bv, 0x11);
    let m1 = _mm_clmulepi64_si128(av, bv, 0x10);
    let m2 = _mm_clmulepi64_si128(av, bv, 0x01);
    let mid = _mm_xor_si128(m1, m2);
    let to_u128 = |v: __m128i| -> u128 {
        let mut out = [0u8; 16];
        _mm_storeu_si128(out.as_mut_ptr() as *mut __m128i, v);
        u128::from_le_bytes(out)
    };
    let (lo, hi, mid) = (to_u128(lo), to_u128(hi), to_u128(mid));
    (hi ^ (mid >> 64), lo ^ (mid << 64))
}

#[inline]
fn has_clmul() -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        use std::sync::OnceLock;
        static HW: OnceLock<bool> = OnceLock::new();
        *HW.get_or_init(|| is_x86_feature_detected!("pclmulqdq"))
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        false
    }
}

/// Reduces `hi·X^128 + lo` modulo X^128 + X^7 + X^2 + X + 1.
#[inline]
fn reduce(hi: u128, lo: u128) -> u128 {
    // X^128 ≡ X^7 + X^2 + X + 1. Folding `hi` overflows by at most 7 bits,
    // which a second fold absorbs.
    let over = (hi >> 127) ^ (hi >> 126) ^ (hi >> 121);
    let lo = lo ^ hi ^ (hi << 1) ^ (hi << 2) ^ (hi << 7);
    lo ^ over ^ (over << 1) ^ (over << 2) ^ (over << 7)
}

/// Product in GF(2^128).
#[inline]
pub fn mul(a: Block, b: Block) -> Block {
    #[cfg(target_arch = "x86_64")]
    if has_clmul() {
        // SAFETY: the feature was detected at runtime.
        let (hi, lo) = unsafe { clmul128_hw(a.0, b.0) };
        return Block(reduce(hi, lo));
    }
    let (hi, lo) = clmul128_soft(a.0, b.0);
    Block(reduce(hi, lo))
}

/// Product computed with the portable path only; used to test the fast path.
pub fn mul_soft(a: Block, b: Block) -> Block {
    let (hi, lo) = clmul128_soft(a.0, b.0);
    Block(reduce(hi, lo))
}

/// The multiplicative identity.
pub const ONE: Block = Block(1);

/// `X^i` for `i < 128`.
#[inline]
pub fn x_pow(i: usize) -> Block {
    assert!(i < 128);
    Block(1u128 << i)
}

/// `a^e` by square-and-multiply.
pub fn pow(a: Block, mut e: u128) -> Block {
    let mut base = a;
    let mut r = ONE;
    while e != 0 {
        if e & 1 == 1 {
            r = mul(r, base);
        }
        base = mul(base, base);
        e >>= 1;
    }
    r
}

/// `[1, χ, χ^2, …, χ^{n-1}]`.
pub fn powers(chi: Block, n: usize) -> Vec<Block> {
    let mut v = Vec::with_capacity(n);
    let mut c = ONE;
    for _ in 0..n {
        v.push(c);
        c = mul(c, chi);
    }
    v
}

/// Inner product `Σ a_i · b_i`.
pub fn inner(a: &[Block], b: &[Block]) -> Block {
    assert_eq!(a.len(), b.len());
    a.iter().zip(b).fold(Block::ZERO, |acc, (x, y)| acc ^ mul(*x, *y))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn field_laws() {
        let mut rng = ChaCha20Rng::seed_from_u64(1);
        for _ in 0..200 {
            let (a, b, c) = (Block::random(&mut rng), Block::random(&mut rng), Block::random(&mut rng));
            assert_eq!(mul(a, b), mul_soft(a, b), "hardware and portable paths differ");
            assert_eq!(mul(a, b), mul(b, a));
            assert_eq!(mul(a, b ^ c), mul(a, b) ^ mul(a, c));
            assert_eq!(mul(mul(a, b), c), mul(a, mul(b, c)));
            assert_eq!(mul(a, ONE), a);
            // Fermat: a^(2^128 - 1) = 1 for a ≠ 0.
            if a != Block::ZERO {
                assert_eq!(pow(a, u128::MAX), ONE);
            }
        }
    }

    #[test]
    fn reduction_polynomial() {
        // X^127 · X = X^128 = X^7 + X^2 + X + 1.
        assert_eq!(mul(x_pow(127), x_pow(1)), Block(0x87));
        assert_eq!(mul(x_pow(3), x_pow(4)), x_pow(7));
        assert_eq!(powers(x_pow(1), 4), vec![ONE, x_pow(1), x_pow(2), x_pow(3)]);
    }
}
