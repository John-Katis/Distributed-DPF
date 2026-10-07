//! The key of the actively secure DPF (ZGY+24 Fig. 5) and its outputs.
//!
//! A key is a root share `Δ_b ⊕ W`, `n` correlated correction words and the
//! leaf word `CW^{(n)} = (CW_v, CW_M)` with `bm` blocks each. Evaluating it at `x`
//! gives SPDZ shares
//!
//! * `u(x) = (t_x, X_x)`: a share of `[x = α]` with MAC `X_x`, and
//! * `v_k(x) = (H(X_x ⊕ 2k) ⊕ t·CW_v[k], H(X_x ⊕ 2k+1) ⊕ t·CW_M[k])`: a share
//!   of `[x = α]·β_k` with its MAC (`H_1` of the paper, widened to `bm` blocks).

use crate::tree::{level_count, HtLocal};
use dpf_common::block::{depth_for, Block};
use dpf_common::hash::CcrHash;
use dpf_common::mac::binary::AuthGf;

#[derive(Clone)]
pub struct MalKey {
    pub party: usize,
    pub n_size: u64,
    pub hash: CcrHash,
    pub root: Block,
    /// `CW^{(0)} … CW^{(n−1)}`.
    pub cws: Vec<Block>,
    /// `CW^{(n)}`, payload half.
    pub cw_v: Vec<Block>,
    /// `CW^{(n)}`, MAC half.
    pub cw_m: Vec<Block>,
}

/// One party's full-domain output.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MalFull {
    pub n: usize,
    /// `u(x)` for every x.
    pub u: Vec<AuthGf>,
    /// `v_k(x)`, column-major: `v[k][x]`.
    pub v: Vec<Vec<AuthGf>>,
}

impl MalFull {
    pub fn v_at(&self, x: usize) -> Vec<AuthGf> {
        self.v.iter().map(|c| c[x]).collect()
    }
}

/// Turns leaves into `(u, v)` with the leaf correction word.
pub(crate) fn leaf_outputs(hash: &CcrHash, leaves: &[Block], cw_v: &[Block], cw_m: &[Block]) -> MalFull {
    let n = leaves.len();
    let u = leaves.iter().map(|x| AuthGf { x: Block(x.lsb() as u128), m: *x }).collect();
    let mut hv = vec![Block::ZERO; n];
    let mut hm = vec![Block::ZERO; n];
    let v = (0..cw_v.len())
        .map(|k| {
            hash.h_many_tweak(leaves, Block(2 * k as u128), &mut hv);
            hash.h_many_tweak(leaves, Block(2 * k as u128 + 1), &mut hm);
            (0..n)
                .map(|j| {
                    let t = leaves[j].lsb();
                    AuthGf { x: hv[j] ^ cw_v[k].and_bit(t), m: hm[j] ^ cw_m[k].and_bit(t) }
                })
                .collect()
        })
        .collect();
    MalFull { n, u, v }
}

/// `⊕_j H_1(X^j)` over the leaves, as `(payload sums, MAC sums)`.
pub(crate) fn leaf_sums(hash: &CcrHash, leaves: &[Block], bm: usize) -> (Vec<Block>, Vec<Block>) {
    let mut buf = vec![Block::ZERO; leaves.len()];
    let mut sum = |tw: u128| {
        hash.h_many_tweak(leaves, Block(tw), &mut buf);
        buf.iter().fold(Block::ZERO, |a, b| a ^ *b)
    };
    let v = (0..bm).map(|k| sum(2 * k as u128)).collect();
    let m = (0..bm).map(|k| sum(2 * k as u128 + 1)).collect();
    (v, m)
}

impl MalKey {
    pub fn depth(&self) -> usize {
        depth_for(self.n_size)
    }

    pub fn bm(&self) -> usize {
        self.cw_v.len()
    }

    pub fn public_part(&self) -> (Block, &[Block], &[Block], &[Block]) {
        (self.hash.key(), &self.cws, &self.cw_v, &self.cw_m)
    }

    /// root + S + n CWs + 2·bm leaf words.
    pub fn size_bytes(&self) -> usize {
        16 + 16 + self.cws.len() * 16 + 2 * self.bm() * 16
    }

    pub fn leaf(&self, x: u64) -> Block {
        assert!(x < self.n_size, "x out of domain");
        let depth = self.depth();
        let mut node = self.root;
        for (j, cw) in self.cws.iter().enumerate() {
            let mut next = self.hash.h(node) ^ cw.and_bit(node.lsb());
            if (x >> (depth - 1 - j)) & 1 == 1 {
                next ^= node;
            }
            node = next;
        }
        node
    }

    /// `(u(x), v(x))` for this party.
    pub fn eval_point(&self, x: u64) -> (AuthGf, Vec<AuthGf>) {
        let leaf = self.leaf(x);
        let t = leaf.lsb();
        let u = AuthGf { x: Block(t as u128), m: leaf };
        let v = (0..self.bm())
            .map(|k| AuthGf {
                x: self.hash.h(leaf ^ Block(2 * k as u128)) ^ self.cw_v[k].and_bit(t),
                m: self.hash.h(leaf ^ Block(2 * k as u128 + 1)) ^ self.cw_m[k].and_bit(t),
            })
            .collect();
        (u, v)
    }

    pub fn eval_full(&self) -> MalFull {
        let mut local = HtLocal::start_all_correlated(self.hash.clone(), self.n_size, self.root);
        for cw in &self.cws {
            local.correlated_sum();
            local.apply_correlated(*cw);
        }
        debug_assert_eq!(local.nodes().len(), level_count(self.n_size, self.depth(), self.depth()));
        leaf_outputs(&self.hash, local.nodes(), &self.cw_v, &self.cw_m)
    }
}
