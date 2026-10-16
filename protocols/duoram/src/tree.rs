//! The DPF tree of Duoram's preprocessing (`preprocessing/dpfgen.h`), which is
//! Doerner–shelat's construction (Duoram App. C).
//!
//! A node is one block: bit 0 is the flag `t`, the rest the seed. `traverse`
//! clears the two low bits and applies the PRG
//! `G_i(s) = AES_k(s ⊕ i) ⊕ i ⊕ s` for `i = 0, 1` (`prg_aes_impl.h`). The
//! reference passes an uninitialised `AES_KEY`, so the key here is a fixed
//! public constant.
//!
//! Correcting a child follows `create_dpfs`/`evaluate_dpfs`:
//!
//! ```text
//! t_child = lsb(G(s)_side) ⊕ (cwt_side ∧ t_parent)
//! s_child = G(s)_side ⊕ CW   if t_parent = 0      (xor_if(…, CW, !t))
//! ```
//!
//! On α's path the parents' flags differ, so exactly one party adds CW and
//! exactly one adds the flag corrections, and the off-path child pair becomes
//! equal.

// `aes` 0.8 re-exports generic-array 0.14, whose newest patch release marks it deprecated.
#![allow(deprecated)]

use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockEncrypt, KeyInit};
use aes::Aes128;
use dpf_common::block::{expand_in_place, Block};
use dpf_common::stream::{walk, TreeMode};
use std::sync::OnceLock;

const PRG_KEY: [u8; 16] = *b"duoram/dpf-prg!!";

/// Correction word of one level: the seed word and the two flag bits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CorrectionWord {
    /// Seed word, lsb 0 (bit 0 of a node is its flag).
    pub s: Block,
    pub t: [bool; 2],
}

fn aes() -> &'static Aes128 {
    static A: OnceLock<Aes128> = OnceLock::new();
    A.get_or_init(|| Aes128::new(GenericArray::from_slice(&PRG_KEY)))
}

/// Both children of each node, uncorrected: `out[2j + i] = G_i(nodes[j])`.
pub fn expand_many(nodes: &[Block], out: &mut Vec<Block>) {
    out.clear();
    out.resize(2 * nodes.len(), Block::ZERO);
    expand_into(nodes, out);
}

/// [`expand_many`] into a slice of length `2·nodes.len()`.
pub fn expand_into(nodes: &[Block], out: &mut [Block]) {
    assert_eq!(out.len(), 2 * nodes.len());
    let mut buf = [GenericArray::default(); 512];
    for (ns, os) in nodes.chunks(buf.len() / 2).zip(out.chunks_mut(buf.len())) {
        let buf = &mut buf[..os.len()];
        for (j, n) in ns.iter().enumerate() {
            let s = n.0 & !3;
            buf[2 * j] = GenericArray::from(s.to_le_bytes());
            buf[2 * j + 1] = GenericArray::from((s ^ 1).to_le_bytes());
        }
        aes().encrypt_blocks(buf);
        for (k, (o, g)) in os.iter_mut().zip(buf.iter()).enumerate() {
            let s = ns[k / 2].0 & !3;
            *o = Block(u128::from_le_bytes(g.as_slice().try_into().unwrap()) ^ (k as u128 & 1) ^ s);
        }
    }
}

/// Child `side` of `node`, uncorrected.
pub fn expand_one(node: Block, side: bool) -> Block {
    let s = node.0 & !3;
    let mut g = GenericArray::from((s ^ side as u128).to_le_bytes());
    aes().encrypt_block(&mut g);
    Block(u128::from_le_bytes(g.as_slice().try_into().unwrap()) ^ side as u128 ^ s)
}

/// Applies a level's correction to an uncorrected child of a parent with flag
/// `t_parent`; returns the child node (flag in bit 0).
#[inline]
pub fn correct(child: Block, t_parent: bool, cw: &CorrectionWord, side: bool) -> Block {
    let t = child.lsb() ^ (cw.t[side as usize] & t_parent);
    let s = if t_parent { child } else { child ^ cw.s };
    Block((s.0 & !1) | t as u128)
}

/// The two lanes of a leaf: lane 0 for the DPF word, lane 1 for the share
/// conversion (the reference's `output[i][0]` and `output[i][1]`). Bit 0 is
/// the flag and must stay out of both: a lane 0 whose lsb is fixed (or is the
/// flag) makes `lsb(F) = lsb(β)` public. So lane 0 is bits 1..=64 (a full
/// 64-bit word, since β can be 64 bits) and lane 1 is bits 65..=127 (63
/// bits). Lane 1 only feeds `Γ'`, and `c − F̄ = pm·(1 − Γ')` with a 63-bit
/// `Γ'` hides pm up to statistical distance 2^-62.
#[inline]
pub fn lanes(leaf: Block) -> (u64, u64) {
    ((leaf.0 >> 1) as u64, (leaf.0 >> 65) as u64)
}

/// The per-level interface that preprocessing drives. [`StoredTree`] keeps
/// every level (the reference code); [`StreamTree`] regenerates them
/// ([`dpf_common::stream`]).
pub trait DuoramTree: Sized {
    fn new(root: Block, mode: TreeMode) -> Self;
    /// Expands the current level: `(L, R)`, the XOR of all uncorrected left
    /// and right children.
    fn level_sums(&mut self) -> (Block, Block);
    /// Corrects the children expanded by [`level_sums`](Self::level_sums).
    fn correct(&mut self, cw: CorrectionWord);
    /// Over all `2^n` leaves: `(Σ lane0, Σ lane1, Σ t)` mod 2^64.
    fn leaf_sums(&self) -> (u64, u64, u64);
}

/// `(Σ lane0, Σ lane1, Σ t)` of some leaves.
fn sums_of(leaves: &[Block]) -> (u64, u64, u64) {
    leaves.iter().fold((0u64, 0u64, 0u64), |(g, g2, pm), leaf| {
        let (v, v2) = lanes(*leaf);
        (g.wrapping_add(v), g2.wrapping_add(v2), pm.wrapping_add(leaf.lsb() as u64))
    })
}

/// The tree as `create_dpfs` holds it: every node of the current level.
pub struct StoredTree {
    /// The current level. [`level_sums`](DuoramTree::level_sums) replaces it
    /// in place by the uncorrected children, [`correct`](DuoramTree::correct)
    /// corrects them in place.
    nodes: Vec<Block>,
    /// Flags of the parents of the uncorrected children in `nodes`.
    parent_t: Vec<bool>,
}

impl DuoramTree for StoredTree {
    fn new(root: Block, _: TreeMode) -> Self {
        StoredTree { nodes: vec![root], parent_t: Vec::new() }
    }

    fn level_sums(&mut self) -> (Block, Block) {
        self.parent_t = self.nodes.iter().map(|x| x.lsb()).collect();
        self.nodes.reserve_exact(self.nodes.len());
        expand_in_place(&mut self.nodes, expand_into);
        let (mut l, mut r) = (Block::ZERO, Block::ZERO);
        for k in self.nodes.chunks(2) {
            l ^= k[0];
            r ^= k[1];
        }
        (l, r)
    }

    fn correct(&mut self, cw: CorrectionWord) {
        for (k, x) in self.nodes.iter_mut().enumerate() {
            *x = correct(*x, self.parent_t[k / 2], &cw, k & 1 == 1);
        }
        self.parent_t = Vec::new();
    }

    fn leaf_sums(&self) -> (u64, u64, u64) {
        sums_of(&self.nodes)
    }
}

/// The same tree holding only the root and the correction words so far.
pub struct StreamTree {
    root: Block,
    batch: usize,
    cws: Vec<CorrectionWord>,
}

impl StreamTree {
    /// A streaming tree over known correction words (for key evaluation).
    pub fn with_cws(root: Block, cws: Vec<CorrectionWord>, batch: usize) -> Self {
        StreamTree { root, batch, cws }
    }

    /// Visits the nodes of `level ≤ cws.len()` in order and batches.
    pub fn visit_level(&self, level: usize, visit: impl FnMut(u64, &[Block])) {
        let expand = |l: usize, parents: &[Block], out: &mut Vec<Block>| {
            expand_many(parents, out);
            for (k, x) in out.iter_mut().enumerate() {
                *x = correct(*x, parents[k / 2].lsb(), &self.cws[l - 1], k & 1 == 1);
            }
        };
        walk(self.root, level, self.batch, expand, visit);
    }
}

impl DuoramTree for StreamTree {
    fn new(root: Block, mode: TreeMode) -> Self {
        StreamTree::with_cws(root, Vec::new(), mode.batch())
    }

    fn level_sums(&mut self) -> (Block, Block) {
        let (mut l, mut r, mut kids) = (Block::ZERO, Block::ZERO, Vec::new());
        self.visit_level(self.cws.len(), |_, nodes| {
            expand_many(nodes, &mut kids);
            for k in kids.chunks(2) {
                l ^= k[0];
                r ^= k[1];
            }
        });
        (l, r)
    }

    fn correct(&mut self, cw: CorrectionWord) {
        self.cws.push(cw);
    }

    fn leaf_sums(&self) -> (u64, u64, u64) {
        let mut acc = (0u64, 0u64, 0u64);
        self.visit_level(self.cws.len(), |_, leaves| {
            let (g, g2, pm) = sums_of(leaves);
            acc = (acc.0.wrapping_add(g), acc.1.wrapping_add(g2), acc.2.wrapping_add(pm));
        });
        acc
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn batched_matches_single() {
        let nodes = [Block(5), Block(0xdead_beef << 40 | 3), Block(u128::MAX)];
        let mut out = Vec::new();
        expand_many(&nodes, &mut out);
        for (j, n) in nodes.iter().enumerate() {
            assert_eq!(out[2 * j], expand_one(*n, false));
            assert_eq!(out[2 * j + 1], expand_one(*n, true));
        }
        // The two low bits of the seed do not matter.
        assert_eq!(expand_one(Block(8), true), expand_one(Block(11), true));
    }
}
