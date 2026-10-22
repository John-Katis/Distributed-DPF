//! A ternary DPF with GF(2^128)-valued leaves: the tree of
//! [`dpf_common::foleage::tdpf`] (same PRG), with a leaf of `3^w` positions
//! of [`LANES`] blocks each, stretched with its own fixed-key AES. This is the
//! DPF the MAC parts of the PCG need: FOLEAGE packs 243 F4 values into a
//! 512-bit leaf, a MAC lane costs 128 bits per position.

// `aes` 0.8 re-exports generic-array 0.14, whose newest patch release marks it deprecated.
#![allow(deprecated)]

use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockEncrypt, KeyInit};
use aes::Aes128;
use dpf_common::block::Block;
use dpf_common::foleage::tdpf::tri_prg;
use rand::{CryptoRng, RngCore};
use std::sync::OnceLock;

/// MAC lanes per position: `ι(v)·Δ` and `ι(v)·Γ`.
pub const LANES: usize = 2;

fn ext_aes() -> &'static Aes128 {
    static A: OnceLock<Aes128> = OnceLock::new();
    A.get_or_init(|| Aes128::new(GenericArray::from_slice(b"exp-mal-fol/wide")))
}

/// `Ext(s)_j = AES(s ⊕ j) ⊕ (s ⊕ j)` for `j < blocks`, for every leaf.
pub fn extend(leaves: &[Block], blocks: usize, out: &mut Vec<Block>) {
    out.clear();
    out.reserve(leaves.len() * blocks);
    let aes = ext_aes();
    let mut buf: Vec<GenericArray<u8, _>> = Vec::with_capacity(64);
    let mut ins: Vec<Block> = Vec::with_capacity(64);
    for s in leaves {
        for j in 0..blocks {
            ins.push(*s ^ Block(j as u128));
            if ins.len() == 64 {
                flush(aes, &mut ins, &mut buf, out);
            }
        }
    }
    flush(aes, &mut ins, &mut buf, out);
}

fn flush(aes: &Aes128, ins: &mut Vec<Block>, buf: &mut Vec<GenericArray<u8, aes::cipher::consts::U16>>, out: &mut Vec<Block>) {
    buf.clear();
    buf.extend(ins.iter().map(|x| GenericArray::from(x.to_bytes())));
    aes.encrypt_blocks(buf);
    out.extend(buf.iter().zip(ins.iter()).map(|(g, x)| Block::from_bytes(g.as_slice()) ^ *x));
    ins.clear();
}

/// One party's key. `cw_out.len()` is the leaf width in blocks.
#[derive(Clone, Debug)]
pub struct WideKey {
    pub root: Block,
    pub cws: Vec<[Block; 3]>,
    pub cw_out: Vec<Block>,
}

impl WideKey {
    pub fn size_bytes(&self) -> usize {
        16 * (1 + 3 * self.cws.len() + self.cw_out.len())
    }

    /// The full-domain output, `cw_out.len()` blocks per leaf, XORed into
    /// `acc` (which must hold `3^depth` leaves).
    pub fn eval_into(&self, acc: &mut [Block]) {
        let prg = tri_prg();
        let mut nodes = vec![self.root];
        let mut next = Vec::new();
        for cw in &self.cws {
            prg.expand(&nodes, &mut next);
            for (p, &parent) in nodes.iter().enumerate() {
                if parent.lsb() {
                    for j in 0..3 {
                        next[3 * p + j] ^= cw[j];
                    }
                }
            }
            std::mem::swap(&mut nodes, &mut next);
        }
        let lb = self.cw_out.len();
        let mut out = Vec::new();
        extend(&nodes, lb, &mut out);
        assert_eq!(acc.len(), out.len());
        for (i, s) in nodes.iter().enumerate() {
            for j in 0..lb {
                let v = out[lb * i + j] ^ self.cw_out[j].and_bit(s.lsb());
                acc[lb * i + j] ^= v;
            }
        }
    }
}

/// Dealer keys for the point `path ∈ [3^depth]` (top trit first) with leaf
/// value `leaf`.
pub fn deal<R: RngCore + CryptoRng>(depth: usize, path: usize, leaf: &[Block], rng: &mut R) -> [WideKey; 2] {
    let prg = tri_prg();
    let mut s = [Block::random(rng).with_lsb(false), Block::random(rng).with_lsb(true)];
    let roots = s;
    let mut cws = Vec::with_capacity(depth);
    let mut kids = Vec::new();
    for i in 0..depth {
        let a = path / 3usize.pow((depth - 1 - i) as u32) % 3;
        prg.expand(&s, &mut kids);
        let mut cw = [kids[0] ^ kids[3], kids[1] ^ kids[4], kids[2] ^ kids[5]];
        cw[a] ^= Block::random(rng).with_lsb(true);
        s = [kids[a] ^ cw[a].and_bit(s[0].lsb()), kids[3 + a] ^ cw[a].and_bit(s[1].lsb())];
        cws.push(cw);
    }
    let lb = leaf.len();
    let mut ext = Vec::new();
    extend(&s, lb, &mut ext);
    let cw_out: Vec<Block> = (0..lb).map(|j| leaf[j] ^ ext[j] ^ ext[lb + j]).collect();
    [WideKey { root: roots[0], cws: cws.clone(), cw_out: cw_out.clone() }, WideKey { root: roots[1], cws, cw_out }]
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn wide_point_function() {
        let mut rng = ChaCha20Rng::seed_from_u64(4);
        for depth in [1, 3] {
            let path = rng.gen_range(0..3usize.pow(depth as u32));
            let leaf: Vec<Block> = (0..6).map(|_| Block::random(&mut rng)).collect();
            let k = deal(depth, path, &leaf, &mut rng);
            let n = 3usize.pow(depth as u32) * 6;
            let mut acc = vec![Block::ZERO; n];
            k[0].eval_into(&mut acc);
            k[1].eval_into(&mut acc);
            for (i, v) in acc.iter().enumerate() {
                assert_eq!(*v, if i / 6 == path { leaf[i % 6] } else { Block::ZERO });
            }
        }
    }
}
