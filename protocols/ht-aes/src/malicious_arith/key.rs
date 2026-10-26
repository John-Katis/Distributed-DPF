//! The arithmetic malicious key: root, level words, payload word `W_CW ∈ F_p`
//! and payload-MAC word `W^MAC_CW ∈ F_p`; evaluation returns additive shares
//! of the output and of its MAC, and [`verify`] is Π_Verify over F_p.

use crate::field::Field;
use crate::{child, children, leaf_seed, mac_hash, pay_hash};
use dpf_common::block::{depth_for, Block};
use dpf_common::coin::{coin_block, commit_and_open_blocks, Abort};
use dpf_common::hash::CtrPrg;
use dpf_common::net::Channel;
use dpf_common::stream::walk;
use rand::{CryptoRng, RngCore};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArithMalKey<F: Field> {
    pub party: usize,
    pub n_size: u64,
    pub root: Block,
    pub cws: Vec<Block>,
    /// `W_CW = (−1)^{t_{n,0}}·(W_0 − W_1 − β)`.
    pub w_cw: F,
    /// `W^MAC_CW = (−1)^{t_{n,0}}·(W̃_0 − W̃_1 − δβ)`.
    pub wm_cw: F,
}

impl<F: Field> ArithMalKey<F> {
    pub fn depth(&self) -> usize {
        depth_for(self.n_size)
    }

    /// Root, n words, `W_CW` and `W^MAC_CW`.
    pub fn size_bytes(&self) -> usize {
        16 + 16 * self.cws.len() + 2 * F::BYTES
    }

    /// `(−1)^b·(F^pay(s) + t·W_CW, F^mac(s) + t·W^MAC_CW)` at a leaf, from the
    /// two mask blocks.
    #[inline]
    fn output(&self, leaf: Block, w: Block, wm: Block) -> (F, F) {
        let (mut y, mut m) = (F::from_block(w), F::from_block(wm));
        if leaf.lsb() {
            y = y.add(self.w_cw);
            m = m.add(self.wm_cw);
        }
        if self.party == 1 {
            (y.neg(), m.neg())
        } else {
            (y, m)
        }
    }

    /// This party's shares `(y, m)` at x: additive shares of `f(x)` and of `δ·f(x)`.
    pub fn eval_point(&self, x: u64) -> (F, F) {
        assert!(x < self.n_size);
        let n = self.depth();
        let mut st = self.root;
        for (i, &cw) in self.cws.iter().enumerate() {
            st = child(st, cw, (x >> (n - 1 - i)) & 1 == 1);
        }
        let s = leaf_seed(st);
        self.output(st, pay_hash().h(s), mac_hash().h(s))
    }

    /// Shares `(y, m)` at x = 0, …, N − 1: all 2^n leaves, one level at a time.
    pub fn eval_full(&self) -> Vec<(F, F)> {
        let mut nodes = vec![self.root];
        for &cw in &self.cws {
            let mut next = Vec::new();
            children(&nodes, cw, &mut next);
            nodes = next;
        }
        nodes.truncate(self.n_size as usize);
        let mut outs = Vec::new();
        self.outputs(&nodes, &mut Vec::new(), &mut outs);
        outs
    }

    /// [`eval_full`](Self::eval_full) without holding the domain: a batched
    /// walk ([`dpf_common::stream`]) that calls `visit(x0, outs)` with this
    /// party's shares at `x0 .. x0 + outs.len()`, for all x < N.
    pub fn eval_full_stream(&self, batch: usize, mut visit: impl FnMut(u64, &[(F, F)])) {
        let (mut buf, mut outs) = (Vec::new(), Vec::new());
        walk(self.root, self.cws.len(), batch, |l, parents, out| children(parents, self.cws[l - 1], out), |x0, leaves| {
            if x0 < self.n_size {
                self.outputs(&leaves[..leaves.len().min((self.n_size - x0) as usize)], &mut buf, &mut outs);
                visit(x0, &outs);
            }
        });
    }

    /// The outputs at `leaves` into `outs`; `buf` is scratch, reused across calls.
    fn outputs(&self, leaves: &[Block], buf: &mut Vec<Block>, outs: &mut Vec<(F, F)>) {
        let k = leaves.len();
        buf.clear();
        buf.extend(leaves.iter().map(|&s| leaf_seed(s)));
        buf.resize(3 * k, Block::ZERO);
        let (seeds, rest) = buf.split_at_mut(k);
        let (w, wm) = rest.split_at_mut(k);
        pay_hash().h_many(seeds, w);
        mac_hash().h_many(seeds, wm);
        outs.clear();
        outs.extend(leaves.iter().zip(w.iter().zip(&*wm)).map(|(&st, (&wv, &mv))| self.output(st, wv, mv)));
    }
}

/// Π_Verify over F_p for a batch of evaluations: opens the outputs, then
/// checks `Σ χ_i (m_i − δ·y_i) = 0` with coin-tossed `χ_i` through a
/// commitment (`δ_share` is this party's share of the payload-MAC key δ).
/// Returns the outputs, or aborts.
pub fn verify<F: Field, R: RngCore + CryptoRng>(ch: &mut Channel, outs: &[(F, F)], delta_share: F, rng: &mut R) -> Result<Vec<F>, Abort> {
    let mut msg = Vec::with_capacity(outs.len() * F::BYTES);
    outs.iter().for_each(|o| o.0.put(&mut msg));
    ch.send(msg);
    let theirs = ch.recv();
    if theirs.len() != outs.len() * F::BYTES {
        return Err(Abort("malformed output shares"));
    }
    let ys: Vec<F> = outs.iter().zip(theirs.chunks(F::BYTES)).map(|(o, t)| o.0.add(F::get(t))).collect();
    let chi = CtrPrg::new(coin_block(ch, rng)?).next_words(outs.len());
    let (mut y, mut m) = (F::ZERO, F::ZERO);
    for ((o, yi), &c) in outs.iter().zip(&ys).zip(&chi) {
        let c = F::from_u128(c);
        y = y.add(c.mul(*yi));
        m = m.add(c.mul(o.1));
    }
    let sigma = m.sub(delta_share.mul(y));
    // σ_0 + σ_1 = Σ χ_i (m_i − δ y_i): zero iff the check passes.
    let other = commit_and_open_blocks(ch, &[Block(sigma.to_u128())], rng)?[0];
    if F::from_u128(other.0).add(sigma) != F::ZERO {
        return Err(Abort("output MAC check failed"));
    }
    Ok(ys)
}
