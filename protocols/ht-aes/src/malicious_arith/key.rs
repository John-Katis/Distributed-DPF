//! The arithmetic malicious key: AES keys, root, level words, payload word
//! `W_CW ∈ F` and payload-MAC word `W^MAC_CW ∈ E`; evaluation returns
//! additive shares of the output (in F) and of its MAC (in E), and [`verify`]
//! is Π_Verify over E.

use super::gen::mac_mask;
use crate::field::{Ext, Field};
use crate::{child, children, leaf_seed};
use dpf_common::aes_tower::Mmo;
use dpf_common::block::{depth_for, Block};
use dpf_common::coin::{coin_block, commit_and_open_blocks, Abort};
use dpf_common::hash::CtrPrg;
use dpf_common::net::Channel;
use dpf_common::stream::walk;
use rand::{CryptoRng, RngCore};

/// This party's shares of a Π_Verify mask `(r, δ·r)`, r uniform in E; one per
/// Π_Verify call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifyMask<E> {
    pub r: E,
    pub dr: E,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArithMalKey<F: Field, E: Ext<F>> {
    pub party: usize,
    pub n_size: u64,
    /// `F = H_K`.
    pub prf: Mmo,
    /// `F^pay = H_{K'}(· ∥ 0)`.
    pub pay: Mmo,
    /// `F^mac`: [`crate::field::mask_blocks`] blocks of `H_{K''}(· ∥ 0 ⊕ tweak(j))`.
    pub mac: Mmo,
    pub root: Block,
    pub cws: Vec<Block>,
    /// `W_CW = (−1)^{t_{n,0}}·(W_0 − W_1 − β)`.
    pub w_cw: F,
    /// `W^MAC_CW = (−1)^{t_{n,0}}·(W̃_0 − W̃_1 − δβ)`.
    pub wm_cw: E,
}

impl<F: Field, E: Ext<F>> ArithMalKey<F, E> {
    pub fn depth(&self) -> usize {
        depth_for(self.n_size)
    }

    /// K, K', K'', root, n words, `W_CW` and `W^MAC_CW`.
    pub fn size_bytes(&self) -> usize {
        3 * 16 + 16 + 16 * self.cws.len() + F::BYTES + E::BYTES
    }

    /// `(−1)^b·(F^pay(s) + t·W_CW, F^mac(s) + t·W^MAC_CW)` at a leaf, from the
    /// payload mask block and the MAC mask.
    #[inline]
    fn output(&self, leaf: Block, w: Block, wm: E) -> (F, E) {
        let (mut y, mut m) = (F::from_block(w), wm);
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
    pub fn eval_point(&self, x: u64) -> (F, E) {
        assert!(x < self.n_size);
        let n = self.depth();
        let mut st = self.root;
        for (i, &cw) in self.cws.iter().enumerate() {
            st = child(&self.prf, st, cw, (x >> (n - 1 - i)) & 1 == 1);
        }
        let s = leaf_seed(st);
        self.output(st, self.pay.h(s), mac_mask::<F, E>(&self.mac, s))
    }

    /// Shares `(y, m)` at x = 0, …, N − 1: all 2^n leaves, one level at a time.
    pub fn eval_full(&self) -> Vec<(F, E)> {
        let mut nodes = vec![self.root];
        for &cw in &self.cws {
            let mut next = Vec::new();
            children(&self.prf, &nodes, cw, &mut next);
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
    pub fn eval_full_stream(&self, batch: usize, mut visit: impl FnMut(u64, &[(F, E)])) {
        let (mut buf, mut outs) = (Vec::new(), Vec::new());
        walk(
            self.root,
            self.cws.len(),
            batch,
            |l, parents, out| children(&self.prf, parents, self.cws[l - 1], out),
            |x0, leaves| {
                if x0 < self.n_size {
                    self.outputs(&leaves[..leaves.len().min((self.n_size - x0) as usize)], &mut buf, &mut outs);
                    visit(x0, &outs);
                }
            },
        );
    }

    /// The outputs at `leaves` into `outs`; `buf` is scratch, reused across calls.
    fn outputs(&self, leaves: &[Block], buf: &mut Vec<Block>, outs: &mut Vec<(F, E)>) {
        let k = leaves.len();
        buf.clear();
        buf.extend(leaves.iter().map(|&s| leaf_seed(s)));
        buf.resize(2 * k, Block::ZERO);
        let (seeds, w) = buf.split_at_mut(k);
        self.pay.h_many(seeds, w);
        outs.clear();
        outs.extend(leaves.iter().zip(seeds.iter().zip(&*w)).map(|(&st, (&s, &wv))| self.output(st, wv, mac_mask::<F, E>(&self.mac, s))));
    }
}

/// Π_Verify (Figure "Π_Verify") over E for a batch of evaluation outputs
/// `(⟦y_i⟧, ⟦m_i⟧)`, which stay shared: with coin-tossed `χ_i` and this
/// key's mask `(⟦r⟧, ⟦δr⟧)`, open `z = Σ χ_i y_i + r`, then commit to and
/// open `σ_b = Σ χ_i m_{i,b} + (δr)_b − δ_b·z` and accept iff `σ_0 + σ_1 =
/// 0`. Only z, uniform through r, and σ are opened.
pub fn verify<F: Field, E: Ext<F>, R: RngCore + CryptoRng>(
    ch: &mut Channel,
    outs: &[(F, E)],
    delta_share: E,
    mask: VerifyMask<E>,
    rng: &mut R,
) -> Result<(), Abort> {
    let chi: Vec<E> = CtrPrg::new(coin_block(ch, rng)?).next_words(outs.len()).into_iter().map(|c| E::from_seed(Block(c))).collect();
    let (mut y, mut m) = (mask.r, mask.dr);
    for (o, &c) in outs.iter().zip(&chi) {
        y = y.add(c.mul(E::embed(o.0)));
        m = m.add(c.mul(o.1));
    }
    let mut msg = Vec::with_capacity(E::BYTES);
    y.put(&mut msg);
    ch.send(msg);
    let theirs = ch.recv();
    if theirs.len() != E::BYTES {
        return Err(Abort("malformed verify message"));
    }
    let z = y.add(E::get(&theirs));
    let sigma = m.sub(delta_share.mul(z));
    let other = commit_and_open_blocks(ch, &[Block(sigma.to_u128())], rng)?[0];
    if E::from_u128(other.0).add(sigma) != E::ZERO {
        return Err(Abort("output MAC check failed"));
    }
    Ok(())
}
