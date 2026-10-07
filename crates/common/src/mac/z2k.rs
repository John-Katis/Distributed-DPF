//! SPDZ2k (Cramer–Damgård–Escudero–Scholl–Xing, CRYPTO'18): values in Z_2^k
//! authenticated in Z_2^{k+s} under a MAC key `α ∈ Z_2^s`. A cheating party
//! passes a check with probability about `2^{−s + log s}`.
//!
//! [`Z2k<K, S>`] plugs into the generic engine of [`super::ring`]:
//! `ArithMacParty<Z2k<64, 64>>` is SPDZ2k with k = s = 64.

use super::ring::MacRing;
use rand::{CryptoRng, RngCore};

/// An element of Z_2^{K+S} (K + S ≤ 128).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Z2k<const K: usize, const S: usize>(pub u128);

impl<const K: usize, const S: usize> Z2k<K, S> {
    const MASK: u128 = if K + S >= 128 { u128::MAX } else { (1u128 << (K + S)) - 1 };

    fn low(bits: usize) -> u128 {
        if bits >= 128 { u128::MAX } else { (1u128 << bits) - 1 }
    }
}

impl<const K: usize, const S: usize> MacRing for Z2k<K, S> {
    fn from_u128(x: u128) -> Self {
        assert!(K + S <= 128 && K >= 1 && S >= 1);
        Z2k(x & Self::MASK)
    }
    fn to_u128(self) -> u128 {
        self.0
    }
    fn add(self, o: Self) -> Self {
        Z2k(self.0.wrapping_add(o.0) & Self::MASK)
    }
    fn sub(self, o: Self) -> Self {
        Z2k(self.0.wrapping_sub(o.0) & Self::MASK)
    }
    fn mul(self, o: Self) -> Self {
        Z2k(self.0.wrapping_mul(o.0) & Self::MASK)
    }
    fn random_key<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        Self::chi(Self::random(rng).0)
    }
    fn chi(x: u128) -> Self {
        Z2k(x & Self::low(S))
    }
    fn share_bits() -> usize {
        K + S
    }
    fn opened(x: Self) -> Self {
        Z2k(x.0 & Self::low(K))
    }
    fn check_mask() -> Option<Self> {
        Some(Self::from_u128(1u128 << K))
    }
}

/// SPDZ2k with 64-bit values and 64-bit statistical security.
pub type Spdz2k64 = Z2k<64, 64>;
/// SPDZ2k with 32-bit values and 64-bit statistical security.
pub type Spdz2k32 = Z2k<32, 64>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mac::ring::tests::{dealer_algebra, engine_roundtrip};

    #[test]
    fn spdz2k_engine() {
        engine_roundtrip::<Spdz2k64>();
        engine_roundtrip::<Spdz2k32>();
        engine_roundtrip::<Z2k<16, 40>>();
    }

    #[test]
    fn spdz2k_algebra() {
        dealer_algebra::<Spdz2k64>();
        dealer_algebra::<Z2k<8, 40>>();
    }
}
