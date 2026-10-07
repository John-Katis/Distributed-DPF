//! The DPF key of XLH+25 Alg. 2 line 23, `k_b = s^{0,0}_b ∥ CW_0 ∥ … ∥ CW_{ℓ_in−1} ∥ W_CW`,
//! with evaluation as in BCG+21 / the reference `evalDPF`:
//!
//! ```text
//! y_b(x) = (−1)^b · (Convert(s_b(x)) + t_b(x)·W_CW)  mod 2^ℓ
//! ```

use crate::tree::{expand, CorrectionWord, Tree};
use dpf_common::arith::{convert, mask, signed};
use dpf_common::block::{depth_for, Block};

#[derive(Clone)]
pub struct ArithKey {
    pub party: usize,
    pub n_size: u64,
    /// ℓ, the payload ring Z_2^ℓ.
    pub bits: usize,
    pub root: Block,
    pub cws: Vec<CorrectionWord>,
    pub w_cw: u64,
}

impl ArithKey {
    pub fn depth(&self) -> usize {
        depth_for(self.n_size)
    }

    /// The parts that are identical in both parties' keys.
    pub fn public_part(&self) -> (&[CorrectionWord], u64) {
        (&self.cws, self.w_cw)
    }

    /// root + n × (σ, 2 advice bits) + ℓ-bit output word.
    pub fn size_bytes(&self) -> usize {
        16 + self.cws.len() * 17 + self.bits.div_ceil(8)
    }

    /// The share at a leaf with seed `s` and control bit `t`.
    #[inline]
    pub fn output(&self, s: Block, t: bool) -> u64 {
        let y = convert(s, self.bits).wrapping_add(if t { self.w_cw } else { 0 });
        signed(self.party == 1, y, self.bits)
    }

    pub fn eval_point(&self, x: u64) -> u64 {
        assert!(x < self.n_size, "x out of domain");
        let depth = self.depth();
        let mut s = self.root;
        let mut t = self.party == 1;
        for (j, cw) in self.cws.iter().enumerate() {
            let side = ((x >> (depth - 1 - j)) & 1) as usize;
            let raw = expand(s)[side];
            s = raw ^ cw.sigma.and_bit(t);
            t = raw.lsb() ^ (t & cw.tau[side]);
        }
        self.output(s, t)
    }

    /// Full-domain evaluation, level by level.
    pub fn eval_full(&self) -> Vec<u64> {
        let mut tree = Tree::new(self.n_size, self.root, self.party == 1);
        for cw in &self.cws {
            tree.expand_level();
            tree.correct(*cw);
        }
        let (s, t) = tree.leaves();
        s.iter().zip(t).map(|(s, t)| self.output(*s, *t)).collect()
    }

    pub fn ring_mask(&self) -> u64 {
        mask(self.bits)
    }
}
