//! The DPF key with an arithmetic payload (BGI16 / NDSS'25 Alg. 2): Floram's
//! GGM key (root, per-level `(σ, τ_L, τ_R)`) plus the final correction word
//! `W_CW ∈ Z_2^ℓ`. Party b's share at x is
//!
//! ```text
//! y_b(x) = (−1)^b · (Convert(s_b(x)) + t_b(x)·W_CW)  mod 2^ℓ
//! ```

use dpf_common::arith::{convert, mask, signed};
use dpf_common::block::{depth_for, Block};
use dpf_common::prg::Prg;
use floram_cprg::cprg::CprgLocal;
use floram_cprg::CorrectionWord;

#[derive(Clone)]
pub struct ArithKey {
    pub party: usize,
    pub n_size: u64,
    /// ℓ, the payload ring Z_2^ℓ.
    pub bits: usize,
    pub prg: Prg,
    pub root: Block,
    pub cws: Vec<CorrectionWord>,
    pub w_cw: u64,
}

impl ArithKey {
    pub fn depth(&self) -> usize {
        depth_for(self.n_size)
    }

    pub fn public_part(&self) -> ((Block, Block), &[CorrectionWord], u64) {
        (self.prg.keys(), &self.cws, self.w_cw)
    }

    /// root + PRG keys + n × (σ, 2 advice bits) + ℓ-bit output word.
    pub fn size_bytes(&self) -> usize {
        16 + 32 + self.cws.len() * 17 + self.bits.div_ceil(8)
    }

    /// The share at a leaf with seed `s` and t-bit `t`.
    #[inline]
    pub fn output(&self, s: Block, t: bool) -> u64 {
        let y = convert(s, self.bits).wrapping_add(if t { self.w_cw } else { 0 });
        signed(self.party == 1, y, self.bits)
    }

    pub fn eval_point(&self, x: u64) -> u64 {
        assert!(x < self.n_size, "x out of domain");
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
        self.output(s, t)
    }

    /// Full-domain evaluation with Floram's batched tree expansion.
    pub fn eval_full(&self) -> Vec<u64> {
        let (mut local, _) = CprgLocal::start(self.prg.clone(), self.n_size, 1, self.root);
        for cw in &self.cws {
            local.step(cw.z, cw.tau_l, cw.tau_r);
        }
        local.finalize();
        let (s, t) = local.leaves();
        s.iter().zip(t).map(|(s, t)| self.output(*s, *t)).collect()
    }

    pub fn ring_mask(&self) -> u64 {
        mask(self.bits)
    }
}
