//! Floram's tree PRG (`offline_prg` in `floram_util.c`).
//!
//! Davies–Meyer with two fixed public keys: `G_k(x) = AES_k(x) ⊕ x`. The left
//! child uses `key_l` and the right child `key_r`. Payload blocks beyond the first
//! are chained with `key_l` (`offline_finalize`).

// `aes` 0.8 re-exports generic-array 0.14, whose newest patch release marks it deprecated.
#![allow(deprecated)]

use crate::block::Block;
use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockEncrypt, KeyInit};
use aes::Aes128;

/// Blocks per batched AES call. The `aes` crate pipelines 8 blocks with AES-NI,
/// so a multiple of 8 keeps it busy.
const BATCH: usize = 64;

#[derive(Clone)]
pub struct Prg {
    key_l: Block,
    key_r: Block,
    aes_l: Aes128,
    aes_r: Aes128,
}

#[inline]
fn aes_from_block(k: Block) -> Aes128 {
    Aes128::new(GenericArray::from_slice(&k.to_bytes()))
}

/// Encrypts `src` with `aes` into `dst` and XORs the input back in.
#[inline]
fn dm_many(aes: &Aes128, src: &[Block], dst: &mut [Block]) {
    debug_assert_eq!(src.len(), dst.len());
    let mut buf = [GenericArray::default(); BATCH];
    for (s, d) in src.chunks(BATCH).zip(dst.chunks_mut(BATCH)) {
        let buf = &mut buf[..s.len()];
        for (g, x) in buf.iter_mut().zip(s) {
            *g = GenericArray::from(x.to_bytes());
        }
        aes.encrypt_blocks(buf);
        for ((o, g), x) in d.iter_mut().zip(buf.iter()).zip(s) {
            *o = Block::from_bytes(g.as_slice()) ^ *x;
        }
    }
}

impl Prg {
    pub fn new(key_l: Block, key_r: Block) -> Prg {
        Prg { key_l, key_r, aes_l: aes_from_block(key_l), aes_r: aes_from_block(key_r) }
    }

    pub fn keys(&self) -> (Block, Block) {
        (self.key_l, self.key_r)
    }

    #[inline]
    fn dm(aes: &Aes128, x: Block) -> Block {
        let mut g = GenericArray::from(x.to_bytes());
        aes.encrypt_block(&mut g);
        Block::from_bytes(g.as_slice()) ^ x
    }

    #[inline]
    pub fn left(&self, s: Block) -> Block {
        Self::dm(&self.aes_l, s)
    }

    #[inline]
    pub fn right(&self, s: Block) -> Block {
        Self::dm(&self.aes_r, s)
    }

    #[inline]
    pub fn child(&self, s: Block, right: bool) -> Block {
        if right { self.right(s) } else { self.left(s) }
    }

    /// Applies `left` to every block of `src`, writing into `dst`.
    pub fn left_many(&self, src: &[Block], dst: &mut [Block]) {
        dm_many(&self.aes_l, src, dst);
    }

    /// Writes the children of `parents` into `children`, interleaved as
    /// `[L(p0), R(p0), L(p1), R(p1), ...]`. When `children` is one short (an odd
    /// count on a non-power-of-two level), the last right child is skipped, as in
    /// Floram's `process_round` tail loop.
    pub fn expand_many(&self, parents: &[Block], children: &mut [Block]) {
        let n = children.len();
        assert!(n == 2 * parents.len() || n + 1 == 2 * parents.len());
        let mut lbuf = [Block::ZERO; BATCH];
        let mut rbuf = [Block::ZERO; BATCH];
        for (ci, chunk) in parents.chunks(BATCH).enumerate() {
            let k = chunk.len();
            dm_many(&self.aes_l, chunk, &mut lbuf[..k]);
            dm_many(&self.aes_r, chunk, &mut rbuf[..k]);
            let base = ci * BATCH * 2;
            for i in 0..k {
                children[base + 2 * i] = lbuf[i];
                if base + 2 * i + 1 < n {
                    children[base + 2 * i + 1] = rbuf[i];
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fips197_kat() {
        // FIPS-197 appendix C.1.
        let key: [u8; 16] = core::array::from_fn(|i| i as u8);
        let pt: [u8; 16] = core::array::from_fn(|i| (i as u8) * 0x11);
        let ct: [u8; 16] = [
            0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5,
            0x5a,
        ];
        let prg = Prg::new(Block::from_bytes(&key), Block::ZERO);
        let x = Block::from_bytes(&pt);
        assert_eq!(prg.left(x), Block::from_bytes(&ct) ^ x);
    }

    #[test]
    fn batched_matches_single() {
        let prg = Prg::new(Block(7), Block(9));
        let parents: Vec<Block> = (0..131u128).map(|i| Block(i * 0x9e37_79b9_7f4a_7c15)).collect();
        for n in [262usize, 261] {
            let mut kids = vec![Block::ZERO; n];
            prg.expand_many(&parents, &mut kids);
            for (i, k) in kids.iter().enumerate() {
                assert_eq!(*k, prg.child(parents[i / 2], i % 2 == 1));
            }
        }
        let mut l = vec![Block::ZERO; parents.len()];
        prg.left_many(&parents, &mut l);
        for (p, x) in parents.iter().zip(&l) {
            assert_eq!(prg.left(*p), *x);
        }
    }
}
