//! The field F4 = F2[ω]/(ω² + ω + 1).
//!
//! An element `h·ω + l` is the two bits `(h, l)`, stored as the byte `h << 1 |
//! l`; this is the encoding of FOLEAGE's reference code (`f4ops.h`). Packed
//! words hold one element in every two bits, so [`mul_packed`] multiplies 64
//! pairs of elements in a `u128` at once.
//!
//! The AES tower ([`crate::aes_tower`]) calls the same field `F_{2^2}` with
//! `θ = ω`.

/// ω.
pub const OMEGA: u8 = 0b10;
/// ω² = ω + 1.
pub const OMEGA2: u8 = 0b11;

/// `a·b`.
#[inline]
pub fn mul(a: u8, b: u8) -> u8 {
    let (ah, al, bh, bl) = (a >> 1 & 1, a & 1, b >> 1 & 1, b & 1);
    let hh = ah & bh;
    // (ah ω + al)(bh ω + bl) = hh·(ω + 1) + (ah bl + al bh)·ω + al bl.
    (hh ^ (ah & bl) ^ (al & bh)) << 1 | (hh ^ (al & bl))
}

/// `a²`, the Frobenius map (F2-linear): `(h, l) ↦ (h, h ⊕ l)`.
#[inline]
pub fn sq(a: u8) -> u8 {
    a & 2 | (a >> 1 ^ a) & 1
}

/// `a^{-1}` for `a ≠ 0`, and `0 ↦ 0`: on F4, `a^{-1} = a²`.
#[inline]
pub fn inv(a: u8) -> u8 {
    sq(a)
}

/// Packed multiplication of every pair of 2-bit lanes, for any word width.
pub trait Packed: Copy + Default + Eq + std::fmt::Debug + std::ops::BitXor<Output = Self> + std::ops::BitXorAssign {
    /// `0b1010…`: the h bits of every lane.
    const HIGH: Self;
    /// Lanes per word.
    const LANES: usize;
    fn and(self, o: Self) -> Self;
    fn shl1(self) -> Self;
    fn shr1(self) -> Self;
    /// Lane `i`.
    fn lane(self, i: usize) -> u8;
    /// `self` with `v` XORed into lane `i`.
    fn xor_lane(self, i: usize, v: u8) -> Self;
}

macro_rules! packed_impl {
    ($t:ty) => {
        impl Packed for $t {
            const HIGH: Self = <$t>::MAX / 3 * 2;
            const LANES: usize = <$t>::BITS as usize / 2;
            #[inline]
            fn and(self, o: Self) -> Self {
                self & o
            }
            #[inline]
            fn shl1(self) -> Self {
                self << 1
            }
            #[inline]
            fn shr1(self) -> Self {
                self >> 1
            }
            #[inline]
            fn lane(self, i: usize) -> u8 {
                (self >> (2 * i)) as u8 & 3
            }
            #[inline]
            fn xor_lane(self, i: usize, v: u8) -> Self {
                self ^ ((v as $t) << (2 * i))
            }
        }
    };
}

packed_impl!(u8);
packed_impl!(u32);
packed_impl!(u64);
packed_impl!(u128);

/// Lane-wise product of two packed words (`multiply_fft_*` of FOLEAGE).
#[inline]
pub fn mul_packed<T: Packed>(a: T, b: T) -> T {
    let (ah, bh) = (a.and(T::HIGH), b.and(T::HIGH));
    let (al, bl) = (a.and(T::HIGH.shr1()), b.and(T::HIGH.shr1()));
    let hh = ah.and(bh);
    // h: hh ⊕ ah·bl ⊕ al·bh (aligned on the h bit), l: hh ⊕ al·bl.
    hh ^ ah.and(bl.shl1()) ^ al.shl1().and(bh) ^ al.and(bl) ^ hh.shr1()
}

/// Lane-wise `ω·a`: `(h, l) ↦ (h ⊕ l, h)`.
#[inline]
pub fn mul_omega_packed<T: Packed>(a: T) -> T {
    let (h, l) = (a.and(T::HIGH), a.and(T::HIGH.shr1()));
    h.shr1() ^ h ^ l.shl1()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The four elements as powers of ω: 0, 1, ω, ω².
    fn log(a: u8) -> Option<u32> {
        [1u8, OMEGA, OMEGA2].iter().position(|&x| x == a).map(|i| i as u32)
    }

    #[test]
    fn field_axioms() {
        for a in 0..4u8 {
            for b in 0..4u8 {
                let want = match (log(a), log(b)) {
                    (Some(x), Some(y)) => [1u8, OMEGA, OMEGA2][((x + y) % 3) as usize],
                    _ => 0,
                };
                assert_eq!(mul(a, b), want, "{a}·{b}");
            }
            assert_eq!(sq(a), mul(a, a));
            if a != 0 {
                assert_eq!(mul(a, inv(a)), 1);
            }
        }
        assert_eq!(mul(OMEGA, OMEGA), OMEGA2);
    }

    #[test]
    fn packed_matches_scalar() {
        let mut x: u128 = 0x0123_4567_89ab_cdef_fedc_ba98_7654_3210;
        let mut y: u128 = 0xdead_beef_0bad_f00d_cafe_babe_1234_5678;
        for _ in 0..20 {
            let p = mul_packed(x, y);
            let w = mul_omega_packed(x);
            for i in 0..64 {
                assert_eq!(p.lane(i), mul(x.lane(i), y.lane(i)));
                assert_eq!(w.lane(i), mul(OMEGA, x.lane(i)));
            }
            x = x.rotate_left(7) ^ y;
            y = y.rotate_left(13).wrapping_mul(3);
        }
    }
}
