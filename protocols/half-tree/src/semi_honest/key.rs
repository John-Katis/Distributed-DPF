//! The Half-Tree DPF key (GYW+23 Fig. 8): the party's root share, the public
//! hash key `S`, `n−1` correlated correction words, the last-level word
//! `(HCW, LCW_0, LCW_1)` and the output word `CW_{n+1}`.

use crate::tree::{hb, Convert, FullEval, HtLocal};
use dpf_common::block::{depth_for, Block};
use dpf_common::hash::CcrHash;

#[derive(Clone)]
pub struct HtKey {
    pub party: usize,
    pub n_size: u64,
    pub conv: Convert,
    pub hash: CcrHash,
    pub root: Block,
    /// `CW_1 … CW_{n−1}`.
    pub cws: Vec<Block>,
    /// `HCW` (lsb clear).
    pub hcw: Block,
    pub lcw: [bool; 2],
    /// `CW_{n+1}`, `bm` blocks.
    pub cw_out: Vec<Block>,
}

impl HtKey {
    pub fn depth(&self) -> usize {
        depth_for(self.n_size)
    }

    pub fn bm(&self) -> usize {
        self.conv.bm
    }

    /// The parts that are identical in both parties' keys.
    pub fn public_part(&self) -> (Block, &[Block], Block, [bool; 2], &[Block]) {
        (self.hash.key(), &self.cws, self.hcw, self.lcw, &self.cw_out)
    }

    /// Compact size: root + S + (n−1) CWs + HCW∥LCW_0∥LCW_1 (λ+1 bits, one
    /// block + 1 byte) + `bm` output blocks.
    pub fn size_bytes(&self) -> usize {
        16 + 16 + self.cws.len() * 16 + 17 + self.cw_out.len() * 16
    }

    /// The leaf `X_x` this party reaches for input `x` (DPF.Eval lines 2–5).
    pub fn leaf(&self, x: u64) -> Block {
        assert!(x < self.n_size, "x out of domain");
        let depth = self.depth();
        let bit = |j: usize| (x >> (depth - 1 - j)) & 1 == 1;
        let mut node = self.root;
        for (j, cw) in self.cws.iter().enumerate() {
            let mut next = self.hash.h(node) ^ cw.and_bit(node.lsb());
            if bit(j) {
                next ^= node;
            }
            node = next;
        }
        let sigma = bit(depth - 1);
        let corr = Block(self.hcw.0 | self.lcw[sigma as usize] as u128);
        self.hash.h(node ^ Block(sigma as u128)) ^ corr.and_bit(node.lsb())
    }

    /// This party's share at `x`, written into `out` (`bm` blocks).
    pub fn eval_point_into(&self, x: u64, out: &mut [Block]) {
        assert_eq!(out.len(), self.bm());
        let leaf = self.leaf(x);
        let t = leaf.lsb();
        for (k, (o, g)) in out.iter_mut().zip(&self.cw_out).enumerate() {
            *o = self.conv.word(leaf, k) ^ g.and_bit(t);
        }
    }

    pub fn eval_point(&self, x: u64) -> Vec<Block> {
        let mut out = vec![Block::ZERO; self.bm()];
        self.eval_point_into(x, &mut out);
        out
    }

    /// Non-interactive full-domain evaluation (about 1.5N hash calls).
    pub fn eval_full(&self) -> FullEval {
        let mut local = HtLocal::start(self.hash.clone(), self.n_size, self.conv, self.root);
        for cw in &self.cws {
            local.correlated_sum();
            local.apply_correlated(*cw);
        }
        local.last_sums();
        local.apply_last(hb(self.hcw), self.lcw);
        local.finalize();
        local.output(&self.cw_out)
    }
}
