//! The DPF key that CPRG generation outputs, with point and full-domain eval.
//!
//! The key is a standard BGI DPF key (Floram Fig. 1): a root seed whose lsb is
//! the party's t-bit, one correction word `(σ_j, τ_{j,0}, τ_{j,1})` per level, and
//! the leaf correction γ. Floram never materialises the key, because it consumes
//! the full-domain output during Gen. We keep it so the output can be checked
//! and evaluated at single points.

use crate::cprg::{CprgLocal, FullEval};
use dpf_common::block::{depth_for, Block};
use dpf_common::prg::Prg;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CorrectionWord {
    /// σ_j, the seed correction applied to both children (Floram's `Z`).
    pub z: Block,
    /// τ_{j,0}, the advice bit for left children.
    pub tau_l: bool,
    /// τ_{j,1}, the advice bit for right children.
    pub tau_r: bool,
}

#[derive(Clone)]
pub struct DpfKey {
    pub party: usize,
    pub n_size: u64,
    /// Floram's `blockmultiple`: 128-bit blocks per output element.
    pub bm: usize,
    /// Public PRG; holds `keyL` and `keyR`.
    pub prg: Prg,
    pub root: Block,
    pub cws: Vec<CorrectionWord>,
    pub gamma: Vec<Block>,
}

impl DpfKey {
    pub fn depth(&self) -> usize {
        depth_for(self.n_size)
    }

    /// The parts that are identical in both parties' keys. The PRG keys, CWs and
    /// γ are public after generation.
    pub fn public_part(&self) -> ((Block, Block), &[CorrectionWord], &[Block]) {
        (self.prg.keys(), &self.cws, &self.gamma)
    }

    /// Key size in bytes when serialised compactly: root + PRG keys + n × (σ, 2
    /// advice bits) + bm × γ.
    pub fn size_bytes(&self) -> usize {
        16 + 32 + self.cws.len() * (16 + 1) + self.gamma.len() * 16
    }

    /// Evaluates this party's share at `x`, writing `bm` blocks into `out`.
    pub fn eval_point_into(&self, x: u64, out: &mut [Block]) {
        assert!(x < self.n_size, "x out of domain");
        assert_eq!(out.len(), self.bm);
        let depth = self.depth();
        let mut s = self.root;
        let mut t = self.root.lsb();
        for (j, cw) in self.cws.iter().enumerate() {
            let right = (x >> (depth - 1 - j)) & 1 == 1;
            let raw = self.prg.child(s, right);
            let tau = if right { cw.tau_r } else { cw.tau_l };
            let t_next = raw.lsb() ^ (t & tau);
            s = raw ^ cw.z.and_bit(t);
            t = t_next;
        }
        out[0] = s ^ self.gamma[0].and_bit(t);
        for (o, g) in out.iter_mut().zip(&self.gamma).skip(1) {
            s = self.prg.left(s);
            *o = s ^ g.and_bit(t);
        }
    }

    pub fn eval_point(&self, x: u64) -> Vec<Block> {
        let mut out = vec![Block::ZERO; self.bm];
        self.eval_point_into(x, &mut out);
        out
    }

    /// Non-interactive full-domain evaluation. It runs the same level-by-level
    /// expansion as generation, with the correction words already known.
    pub fn eval_full(&self) -> FullEval {
        let (mut local, _) = CprgLocal::start(self.prg.clone(), self.n_size, self.bm, self.root);
        for cw in &self.cws {
            local.step(cw.z, cw.tau_l, cw.tau_r);
        }
        local.finalize();
        local.output(&self.gamma)
    }
}
