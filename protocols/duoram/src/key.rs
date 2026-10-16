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
//!
//! The key is generic over the word type of Z_2^w ([`Lanes`]): `u64` for
//! w ≤ 64 (the reference's `value_t`), `u128` up to w = 128.

use crate::tree::{correct, expand_many, expand_one, lanes, CorrectionWord, Lanes, StreamTree};
use dpf_common::arith::mask;
use dpf_common::block::{depth_for, Block};

#[derive(Clone, Debug)]
pub struct DuoramKey<R: Lanes = u64> {
    pub party: usize,
    pub n_size: u64,
    /// Output ring Z_2^bits.
    pub bits: usize,
    pub root: Block,
    pub cws: Vec<CorrectionWord>,
    /// `pm + ρ` (App. D).
    pub c: R,
    /// `Γ'·pm + ρ` (App. D).
    pub fbar: R,
    /// Cyclic shift `α − r mod 2^n`.
    pub shift: u64,
    /// Final correction word `β − (v_0[r] + v_1[r])`.
    pub f: R,
}

impl<R: Lanes> DuoramKey<R> {
    pub fn depth(&self) -> usize {
        depth_for(self.n_size)
    }

    /// The part both parties share.
    pub fn public_part(&self) -> (&[CorrectionWord], u64, R) {
        (&self.cws, self.shift, self.f)
    }

    /// Root, CWs (16 + 1 bytes each), the 8-byte shift and three ring words.
    pub fn size_bytes(&self) -> usize {
        16 + 17 * self.cws.len() + 8 + 3 * R::BYTES
    }

    fn sign(&self, x: R) -> R {
        if self.party == 1 {
            x.neg()
        } else {
            x
        }
    }

    /// Output share for a leaf with lanes `v`, `v2`.
    #[inline]
    fn output_lanes(&self, leaf: Block, v: R, v2: R) -> R {
        let (v, v2, t) = (self.sign(v), self.sign(v2), self.sign(R::from_u64(leaf.lsb() as u64)));
        let tt = t.mul(self.c).add(v2).sub(t.mul(self.fbar));
        v.add(self.f.mul(tt)).and(R::mask(self.bits))
    }

    /// Output share for a leaf of the unshifted tree.
    pub fn output(&self, leaf: Block) -> R {
        let (v, v2) = lanes::<R>(leaf);
        self.output_lanes(leaf, v, v2)
    }

    /// Output shares of some leaves of the unshifted tree, `f(i, y)` for
    /// `leaves[i]`.
    fn outputs(&self, leaves: &[Block], mut f: impl FnMut(usize, R)) {
        R::for_each(leaves, |i, v, v2| f(i, self.output_lanes(leaves[i], v, v2)));
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
    pub fn eval_point(&self, x: u64) -> R {
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
    pub fn eval_full(&self) -> Vec<R> {
        let leaves = self.leaves();
        let mut ys = vec![R::ZERO; leaves.len()];
        self.outputs(&leaves, |i, y| ys[i] = y);
        (0..self.n_size).map(|x| ys[self.unshift(x) as usize]).collect()
    }

    /// [`eval_full`](Self::eval_full) without holding the domain: a batched
    /// walk ([`dpf_common::stream`]) over the unshifted tree that calls
    /// `visit(x, y)` with this party's share `y` at every `x < N`. The points
    /// arrive in the order of their unshifted index `x − shift mod 2^n`.
    pub fn eval_full_stream(&self, batch: usize, mut visit: impl FnMut(u64, R)) {
        let m = mask(self.depth());
        StreamTree::with_cws(self.root, self.cws.clone(), batch).visit_level(self.depth(), |xp0, leaves| {
            self.outputs(leaves, |i, y| {
                let x = (xp0 + i as u64).wrapping_add(self.shift) & m;
                if x < self.n_size {
                    visit(x, y);
                }
            });
        });
    }
}
