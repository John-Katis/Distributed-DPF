//! 128-bit blocks, the unit of every seed, label and payload word.
//!
//! Byte order is little-endian, so `lsb()` is bit 0 of byte 0. Floram reads its
//! t-bits the same way (`lda2[ii*BLOCKSIZE] & 1`).

use rand::{CryptoRng, RngCore};
use std::ops::{BitAnd, BitXor, BitXorAssign};

#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Block(pub u128);

impl Block {
    pub const ZERO: Block = Block(0);
    pub const BYTES: usize = 16;

    #[inline]
    pub fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Block {
        let mut b = [0u8; 16];
        rng.fill_bytes(&mut b);
        Block::from_bytes(&b)
    }

    #[inline]
    pub fn lsb(self) -> bool {
        self.0 & 1 == 1
    }

    /// `self` with its lsb replaced by `b` (a GGM node whose lsb is its t-bit).
    #[inline]
    pub fn with_lsb(self, b: bool) -> Block {
        Block((self.0 & !1) | b as u128)
    }

    #[inline]
    pub fn bit(self, i: usize) -> bool {
        (self.0 >> i) & 1 == 1
    }

    #[inline]
    pub fn from_bits(bits: &[bool]) -> Block {
        debug_assert!(bits.len() <= 128);
        Block(bits.iter().enumerate().fold(0u128, |acc, (i, &b)| acc | ((b as u128) << i)))
    }

    #[inline]
    pub fn to_bits(self) -> Vec<bool> {
        (0..128).map(|i| self.bit(i)).collect()
    }

    /// Returns `self` if `c` is set and zero otherwise, without branching.
    #[inline]
    pub fn and_bit(self, c: bool) -> Block {
        Block(self.0 & (c as u128).wrapping_neg())
    }

    #[inline]
    pub fn to_bytes(self) -> [u8; 16] {
        self.0.to_le_bytes()
    }

    #[inline]
    pub fn from_bytes(b: &[u8]) -> Block {
        Block(u128::from_le_bytes(b[..16].try_into().unwrap()))
    }
}

impl std::fmt::Debug for Block {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:032x}", self.0)
    }
}

impl BitXor for Block {
    type Output = Block;
    #[inline]
    fn bitxor(self, rhs: Block) -> Block {
        Block(self.0 ^ rhs.0)
    }
}

impl BitXorAssign for Block {
    #[inline]
    fn bitxor_assign(&mut self, rhs: Block) {
        self.0 ^= rhs.0;
    }
}

impl BitAnd for Block {
    type Output = Block;
    #[inline]
    fn bitand(self, rhs: Block) -> Block {
        Block(self.0 & rhs.0)
    }
}

/// The `n` index bits of `x`, most significant first. Floram walks the tree
/// with `(index >> (endlevel - ii)) & 1`, which is the same order.
pub fn bits_msb_first(x: u64, n: usize) -> Vec<bool> {
    (0..n).map(|j| (x >> (n - 1 - j)) & 1 == 1).collect()
}

/// Number of tree levels for a domain of `n_size` leaves, i.e. ceil(log2 N).
/// This is Floram's `endlevel`.
pub fn depth_for(n_size: u64) -> usize {
    assert!(n_size >= 2, "domain size must be at least 2");
    (64 - (n_size - 1).leading_zeros()) as usize
}

/// Blocks needed for a payload of `out_bits` bits (Floram's `blockmultiple`).
pub fn blocks_for_bits(out_bits: usize) -> usize {
    assert!(out_bits >= 1);
    out_bits.div_ceil(128)
}

/// Clears every bit at position `out_bits` or above in a payload of blocks.
pub fn mask_to_bits(v: &mut [Block], out_bits: usize) {
    for (i, b) in v.iter_mut().enumerate() {
        let lo = i * 128;
        if out_bits <= lo {
            *b = Block::ZERO;
        } else if out_bits < lo + 128 {
            b.0 &= (1u128 << (out_bits - lo)) - 1;
        }
    }
}

pub fn xor_blocks(a: &[Block], b: &[Block]) -> Vec<Block> {
    assert_eq!(a.len(), b.len());
    a.iter().zip(b).map(|(x, y)| *x ^ *y).collect()
}

pub fn blocks_to_bytes(v: &[Block]) -> Vec<u8> {
    let mut out = Vec::with_capacity(v.len() * 16);
    for b in v {
        out.extend_from_slice(&b.to_bytes());
    }
    out
}

pub fn blocks_from_bytes(bytes: &[u8]) -> Vec<Block> {
    assert_eq!(bytes.len() % 16, 0);
    bytes.chunks_exact(16).map(Block::from_bytes).collect()
}

pub fn pack_bits(bits: &[bool]) -> Vec<u8> {
    let mut out = vec![0u8; bits.len().div_ceil(8)];
    for (i, &b) in bits.iter().enumerate() {
        out[i / 8] |= (b as u8) << (i % 8);
    }
    out
}

pub fn unpack_bits(bytes: &[u8], n: usize) -> Vec<bool> {
    assert!(bytes.len() * 8 >= n);
    (0..n).map(|i| (bytes[i / 8] >> (i % 8)) & 1 == 1).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn depth() {
        assert_eq!(depth_for(2), 1);
        assert_eq!(depth_for(3), 2);
        assert_eq!(depth_for(4), 2);
        assert_eq!(depth_for(5), 3);
        assert_eq!(depth_for(1024), 10);
        assert_eq!(depth_for(1025), 11);
    }

    #[test]
    fn bit_roundtrips() {
        let b = Block(0x0123_4567_89ab_cdef_fedc_ba98_7654_3210);
        assert_eq!(Block::from_bits(&b.to_bits()), b);
        assert_eq!(Block::from_bytes(&b.to_bytes()), b);
        let bits = vec![true, false, true, true, false, false, false, true, true];
        assert_eq!(unpack_bits(&pack_bits(&bits), bits.len()), bits);
        assert_eq!(bits_msb_first(0b101, 3), vec![true, false, true]);
    }

    #[test]
    fn masking() {
        let mut v = vec![Block(u128::MAX); 3];
        mask_to_bits(&mut v, 130);
        assert_eq!(v, vec![Block(u128::MAX), Block(3), Block::ZERO]);
    }
}
