//! The field F4 = F2[ω]/(ω² + ω + 1).
//!
//! An element `h·ω + l` is the two bits `(h, l)`, stored as the byte `h << 1 |
//! l`.
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
}
