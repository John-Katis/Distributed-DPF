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
use dpf_common::block::Block;
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
    let mut buf: Vec<_> = nodes
        .iter()
        .flat_map(|n| {
            let s = n.0 & !3;
            [GenericArray::from(s.to_le_bytes()), GenericArray::from((s ^ 1).to_le_bytes())]
        })
        .collect();
    aes().encrypt_blocks(&mut buf);
    out.extend(buf.iter().enumerate().map(|(k, g)| {
        let s = nodes[k / 2].0 & !3;
        Block(u128::from_le_bytes(g.as_slice().try_into().unwrap()) ^ (k as u128 & 1) ^ s)
    }));
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
