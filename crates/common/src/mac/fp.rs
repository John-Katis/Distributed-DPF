//! SPDZ-style MACs over a prime field F_p (p < 2^64): `Σ m_b = x·α` with
//! `α ∈ F_p`. A cheating party passes a check with probability about `1/p`.
//!
//! `ArithMacParty<Fp<P>>` from [`super::ring`] is the engine.

use super::ring::MacRing;
use rand::{CryptoRng, RngCore};

/// An element of F_P, stored canonically.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Fp<const P: u64>(pub u64);

impl<const P: u64> MacRing for Fp<P> {
    fn from_u128(x: u128) -> Self {
        Fp((x % P as u128) as u64)
    }
    fn to_u128(self) -> u128 {
        self.0 as u128
    }
    fn add(self, o: Self) -> Self {
        Fp(((self.0 as u128 + o.0 as u128) % P as u128) as u64)
    }
    fn sub(self, o: Self) -> Self {
        Fp(((self.0 as u128 + P as u128 - o.0 as u128) % P as u128) as u64)
    }
    fn mul(self, o: Self) -> Self {
        Fp(((self.0 as u128 * o.0 as u128) % P as u128) as u64)
    }
    fn random_key<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        Self::random(rng)
    }
    fn chi(x: u128) -> Self {
        Self::from_u128(x)
    }
    fn share_bits() -> usize {
        (64 - P.leading_zeros()) as usize
    }
    fn opened(x: Self) -> Self {
        x
    }
    fn check_mask() -> Option<Self> {
        None
    }
}

/// The Mersenne prime 2^61 − 1.
pub type Fp61 = Fp<2_305_843_009_213_693_951>;
/// The Goldilocks prime 2^64 − 2^32 + 1.
pub type FpGoldilocks = Fp<18_446_744_069_414_584_321>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mac::ring::tests::{dealer_algebra, engine_roundtrip};

    #[test]
    fn fp_engine() {
        engine_roundtrip::<Fp61>();
        engine_roundtrip::<FpGoldilocks>();
    }

    #[test]
    fn fp_algebra() {
        dealer_algebra::<Fp61>();
        dealer_algebra::<FpGoldilocks>();
        // Sanity: p − 1 + 2 = 1.
        assert_eq!(Fp61::from_u128(Fp61::from_u128(0).sub(Fp61::from_u128(1)).0 as u128).add(Fp61::from_u128(2)), Fp61::from_u128(1));
    }
}
