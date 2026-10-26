//! The malicious key: root, level words, payload word `W_CW` (ℓ bits, XOR
//! group) and payload-MAC word `W^MAC_CW ∈ GF(2^128)`; evaluation returns the
//! output share and its MAC share, and [`verify`] is Π_Verify.

use crate::{child, children, leaf_seed, mac_hash, pay_hash};
use dpf_common::block::{depth_for, Block};
use dpf_common::stream::walk;
use dpf_common::coin::{coin_block, commit_and_open_blocks, Abort};
use dpf_common::gf128;
use dpf_common::hash::CtrPrg;
use dpf_common::net::Channel;
use rand::{CryptoRng, RngCore};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MalKey {
    pub party: usize,
    pub n_size: u64,
    /// ℓ ≤ 128: outputs live in `{0,1}^ℓ ⊂ GF(2^128)`.
    pub bits: usize,
    pub root: Block,
    pub cws: Vec<Block>,
    /// `W_CW = F^pay(s_0) ⊕ F^pay(s_1) ⊕ β` (low ℓ bits).
    pub w_cw: Block,
    /// `W^MAC_CW = F^mac(s_0) ⊕ F^mac(s_1) ⊕ δ·β`.
    pub wm_cw: Block,
}

/// The low `bits` bits of a block.
#[inline]
pub fn low(x: Block, bits: usize) -> Block {
    if bits >= 128 { x } else { Block(x.0 & ((1u128 << bits) - 1)) }
}

impl MalKey {
    pub fn depth(&self) -> usize {
        depth_for(self.n_size)
    }

    /// Root, n words, ⌈ℓ/8⌉ bytes of `W_CW`, 16 bytes of `W^MAC_CW`.
    pub fn size_bytes(&self) -> usize {
        16 + 16 * self.cws.len() + self.bits.div_ceil(8) + 16
    }

    pub fn public_part(&self) -> (&[Block], Block, Block) {
        (&self.cws, self.w_cw, self.wm_cw)
    }

    /// This party's shares `(y, m)` at x: XOR shares of `f(x)` and of `δ·f(x)`.
    pub fn eval_point(&self, x: u64) -> (Block, Block) {
        assert!(x < self.n_size);
        let n = self.depth();
        let mut st = self.root;
        for (i, &cw) in self.cws.iter().enumerate() {
            st = child(st, cw, (x >> (n - 1 - i)) & 1 == 1);
        }
        let s = leaf_seed(st);
        let t = st.lsb();
        (low(pay_hash().h(s), self.bits) ^ self.w_cw.and_bit(t), mac_hash().h(s) ^ self.wm_cw.and_bit(t))
    }

    /// Shares `(y, m)` at x = 0, …, N − 1: all 2^n leaves, one level at a time.
    pub fn eval_full(&self) -> Vec<(Block, Block)> {
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
    pub fn eval_full_stream(&self, batch: usize, mut visit: impl FnMut(u64, &[(Block, Block)])) {
        let (mut buf, mut outs) = (Vec::new(), Vec::new());
        walk(self.root, self.cws.len(), batch, |l, parents, out| children(parents, self.cws[l - 1], out), |x0, leaves| {
            if x0 < self.n_size {
                self.outputs(&leaves[..leaves.len().min((self.n_size - x0) as usize)], &mut buf, &mut outs);
                visit(x0, &outs);
            }
        });
    }

    /// The outputs at `leaves` into `outs`; `buf` is scratch, reused across calls.
    fn outputs(&self, leaves: &[Block], buf: &mut Vec<Block>, outs: &mut Vec<(Block, Block)>) {
        let k = leaves.len();
        buf.clear();
        buf.extend(leaves.iter().map(|&s| leaf_seed(s)));
        buf.resize(3 * k, Block::ZERO);
        let (seeds, rest) = buf.split_at_mut(k);
        let (w, wm) = rest.split_at_mut(k);
        pay_hash().h_many(seeds, w);
        mac_hash().h_many(seeds, wm);
        let (wc, mc) = (self.w_cw, self.wm_cw);
        outs.clear();
        outs.extend(leaves.iter().zip(w.iter().zip(&*wm)).map(|(&st, (&wv, &mv))| {
            let t = st.lsb();
            (low(wv, self.bits) ^ wc.and_bit(t), mv ^ mc.and_bit(t))
        }));
    }
}

/// Π_Verify for a batch of evaluations: opens the outputs, then checks
/// `Σ χ_i (m_i ⊕ δ·y_i) = 0` with coin-tossed `χ_i` through a commitment
/// (`δ_share` is this party's share of the payload-MAC key δ). Returns the
/// outputs, or aborts.
pub fn verify<R: RngCore + CryptoRng>(ch: &mut Channel, outs: &[(Block, Block)], delta_share: Block, rng: &mut R) -> Result<Vec<Block>, Abort> {
    let mine: Vec<Block> = outs.iter().map(|o| o.0).collect();
    ch.send_blocks(&mine);
    let theirs = ch.recv_blocks(outs.len());
    let ys: Vec<Block> = mine.iter().zip(&theirs).map(|(a, b)| *a ^ *b).collect();
    let chi = CtrPrg::new(coin_block(ch, rng)?).next_words(outs.len());
    let (mut y, mut m) = (Block::ZERO, Block::ZERO);
    for ((o, yi), &c) in outs.iter().zip(&ys).zip(&chi) {
        y ^= gf128::mul(Block(c), *yi);
        m ^= gf128::mul(Block(c), o.1);
    }
    let sigma = m ^ gf128::mul(delta_share, y);
    // σ_0 ⊕ σ_1 = Σ χ_i (m_i ⊕ δ y_i): equal shares iff it is zero.
    if commit_and_open_blocks(ch, &[sigma], rng)?[0] != sigma {
        return Err(Abort("output MAC check failed"));
    }
    Ok(ys)
}
