//! The adjusted Duoram DPF and its evaluation.
//!
//! After preprocessing, party b holds a Floram DPF at the random target `r`
//! (root and CWs), the conversion scalars `c = pm + ρ` and `F̄ = Γ'·pm + ρ` of
//! App. D, and after the online phase the shift `S = α − r mod 2^n` and the
//! final word `F = β − (v_0[r] + v_1[r])`. At input x, with `x' = x − S`:
//!
//! ```text
//! v_b  = (−1)^b · lane0(leaf_b(x'))        // the DPF word
//! v'_b = (−1)^b · lane1(leaf_b(x'))        // the second lane, for App. D
//! t_b  = (−1)^b · flag_b(x')
//! t̃_b  = t_b·c + v'_b − t_b·F̄              // additive shares of e_r(x')
//! y_b  = v_b + F·t̃_b  mod 2^w
//! ```
//!
//! so `y_0 + y_1 = β·e_α(x)`. Party 1's negation turns the XOR-shared tree
//! into additive shares (equal off-path pairs cancel), as in
//! `convert_shares`.

use crate::tree::{correct, expand_many, expand_one, lanes, CorrectionWord};
use dpf_common::arith::mask;
use dpf_common::block::{depth_for, Block};

#[derive(Clone, Debug)]
pub struct DuoramKey {
    pub party: usize,
    pub n_size: u64,
    /// Output ring Z_2^bits.
    pub bits: usize,
    pub root: Block,
    pub cws: Vec<CorrectionWord>,
    /// `pm + ρ` (App. D).
    pub c: u64,
    /// `Γ'·pm + ρ` (App. D).
    pub fbar: u64,
    /// Cyclic shift `α − r mod 2^n`.
    pub shift: u64,
    /// Final correction word `β − (v_0[r] + v_1[r])`.
    pub f: u64,
}

impl DuoramKey {
    pub fn depth(&self) -> usize {
        depth_for(self.n_size)
    }

    /// The part both parties share.
    pub fn public_part(&self) -> (&[CorrectionWord], u64, u64) {
        (&self.cws, self.shift, self.f)
    }

    /// Root, CWs (16 + 1 bytes each) and the four scalars.
    pub fn size_bytes(&self) -> usize {
        16 + 17 * self.cws.len() + 4 * 8
    }

    fn sign(&self, x: u64) -> u64 {
        if self.party == 1 {
            x.wrapping_neg()
        } else {
            x
        }
    }

    /// Output share for a leaf of the unshifted tree.
    pub fn output(&self, leaf: Block) -> u64 {
        let (v, v2) = lanes(leaf);
        let (v, v2, t) = (self.sign(v), self.sign(v2), self.sign(leaf.lsb() as u64));
        let tt = t.wrapping_mul(self.c).wrapping_add(v2).wrapping_sub(t.wrapping_mul(self.fbar));
        v.wrapping_add(self.f.wrapping_mul(tt)) & mask(self.bits)
    }

    fn unshift(&self, x: u64) -> u64 {
        x.wrapping_sub(self.shift) & mask(self.depth())
    }

    /// The leaf of the unshifted tree at `x'`.
    pub fn leaf(&self, xp: u64) -> Block {
        let n = self.depth();
        let mut node = self.root;
        for (i, cw) in self.cws.iter().enumerate() {
            let side = (xp >> (n - 1 - i)) & 1 == 1;
            node = correct(expand_one(node, side), node.lsb(), cw, side);
        }
        node
    }

    /// This party's additive share of `β·e_α(x)` mod 2^bits.
    pub fn eval_point(&self, x: u64) -> u64 {
        assert!(x < self.n_size);
        self.output(self.leaf(self.unshift(x)))
    }

    /// All `2^n` leaves of the unshifted tree.
    pub fn leaves(&self) -> Vec<Block> {
        let mut nodes = vec![self.root];
        let mut kids = Vec::new();
        for cw in &self.cws {
            expand_many(&nodes, &mut kids);
            nodes = kids.iter().enumerate().map(|(k, &c)| correct(c, nodes[k / 2].lsb(), cw, k & 1 == 1)).collect();
        }
        nodes
    }

    /// Shares of `β·e_α(x)` for `x ∈ [0, N)`.
    pub fn eval_full(&self) -> Vec<u64> {
        let leaves = self.leaves();
        (0..self.n_size).map(|x| self.output(leaves[self.unshift(x) as usize])).collect()
    }
}
