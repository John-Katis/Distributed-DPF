//! 8 packed F4 lanes in a `u16` ([`dpf_common::f4::Packed`] has no `u16`
//! impl), so that both parties expand `3^19` OLEs in memory.

use dpf_common::f4::Packed;
use std::ops::{BitXor, BitXorAssign};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct P16(pub u16);

impl BitXor for P16 {
    type Output = P16;
    fn bitxor(self, o: P16) -> P16 {
        P16(self.0 ^ o.0)
    }
}

impl BitXorAssign for P16 {
    fn bitxor_assign(&mut self, o: P16) {
        self.0 ^= o.0;
    }
}

impl Packed for P16 {
    const HIGH: Self = P16(u16::MAX / 3 * 2);
    const LANES: usize = 8;
    #[inline]
    fn and(self, o: Self) -> Self {
        P16(self.0 & o.0)
    }
    #[inline]
    fn shl1(self) -> Self {
        P16(self.0 << 1)
    }
    #[inline]
    fn shr1(self) -> Self {
        P16(self.0 >> 1)
    }
    #[inline]
    fn lane(self, i: usize) -> u8 {
        (self.0 >> (2 * i)) as u8 & 3
    }
    #[inline]
    fn xor_lane(self, i: usize, v: u8) -> Self {
        P16(self.0 ^ ((v as u16) << (2 * i)))
    }
}
