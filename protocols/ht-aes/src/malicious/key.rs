//! The Boolean malicious key: the semi-honest key's words, the leaf MAC's words
//! `C^j`, `N^j`, and `W^MAC_CW ∈ F_{2^k}`; evaluation returns XOR shares of the
//! output and of its MAC, and [`verify`] is Π_Verify over `F_{2^k}`.

use crate::field::{bits_at, Field};
use crate::verify::{self, pi_verify, VerifyMask};
use crate::{expand_level, leaf_hash, leaf_hash_many, Bottom};
use dpf_common::aes_tower::Mmo;
use dpf_common::block::{depth_for, Block};
use dpf_common::coin::Abort;
use dpf_common::net::Channel;
use dpf_common::stream::walk;
use rand::{CryptoRng, RngCore};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MalKey<K: Field> {
    pub party: usize,
    pub n_size: u64,
    /// ℓ ≤ k: outputs live in the first ℓ coordinates of `F_{2^k}`.
    pub bits: usize,
    /// `F = H_K`, K public (the session's).
    pub prf: Mmo,
    pub root: Block,
    pub cws: Vec<Block>,
    /// `M^0_ℓ`, `C_ℓ` and `b^τ_ℓ` for `ν ≤ ℓ ≤ n`.
    pub bottom: Bottom,
    /// `[C^j, N^j]` of the leaf hash, `2 ≤ j ≤ τ`.
    pub leaf_words: Vec<[Block; 2]>,
    /// `W_CW = W(h^(0)) ⊕ W(h^(1)) ⊕ β` (low ℓ bits).
    pub w_cw: Block,
    /// `W^MAC_CW = F^mac(h^(0)) ⊕ F^mac(h^(1)) ⊕ β·δ`.
    pub wm_cw: K,
}

/// The low `bits` bits of a block.
#[inline]
pub fn low(x: Block, bits: usize) -> Block {
    if bits >= 128 {
        x
    } else {
        Block(x.0 & ((1u128 << bits) - 1))
    }
}

/// `F^mac(h)`: the k bits of the leaf hash after the ℓ payload bits.
#[inline]
pub(crate) fn mac_of<K: Field>(h: &[Block], bits: usize) -> K {
    K::from_u128(bits_at(h, bits, K::P_BITS))
}

impl<K: Field> MalKey<K> {
    pub fn depth(&self) -> usize {
        depth_for(self.n_size)
    }

    /// The glue level ν.
    pub fn nu(&self) -> usize {
        self.bottom.nu
    }

    /// K, root, n level words, the bottom layer's words, `C^j` and `N^j`,
    /// ⌈ℓ/8⌉ bytes of `W_CW` and `W^MAC_CW`.
    pub fn size_bytes(&self) -> usize {
        16 + 16 + 16 * self.cws.len() + self.bottom.size_bytes() + 32 * self.leaf_words.len() + self.bits.div_ceil(8) + K::BYTES
    }

    #[inline]
    fn output(&self, t: bool, h: &[Block]) -> (Block, K) {
        let (y, m) = (low(h[0], self.bits), mac_of::<K>(h, self.bits));
        if t {
            (y ^ self.w_cw, m.add(self.wm_cw))
        } else {
            (y, m)
        }
    }

    /// This party's shares `(y, m)` at x: XOR shares of `f(x)` and of `δ·f(x)`.
    pub fn eval_point(&self, x: u64) -> (Block, K) {
        assert!(x < self.n_size);
        let st = self.bottom.path(&self.prf, self.root, &self.cws, x);
        self.output(st.lsb(), &leaf_hash(&self.prf, &self.bottom, &self.leaf_words, st))
    }

    /// Shares `(y, m)` at x = 0, …, N − 1: all 2^n leaves, one level at a time.
    pub fn eval_full(&self) -> Vec<(Block, K)> {
        let mut nodes = vec![self.root];
        for (i, &cw) in self.cws.iter().enumerate() {
            let mut next = Vec::new();
            expand_level(&self.prf, &nodes, cw, &self.bottom, i + 1, &mut next);
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
    pub fn eval_full_stream(&self, batch: usize, mut visit: impl FnMut(u64, &[(Block, K)])) {
        let (mut buf, mut outs) = (Vec::new(), Vec::new());
        walk(
            self.root,
            self.cws.len(),
            batch,
            |l, parents, out| expand_level(&self.prf, parents, self.cws[l - 1], &self.bottom, l, out),
            |x0, leaves| {
                if x0 < self.n_size {
                    self.outputs(&leaves[..leaves.len().min((self.n_size - x0) as usize)], &mut buf, &mut outs);
                    visit(x0, &outs);
                }
            },
        );
    }

    /// The outputs at `leaves` into `outs`; `buf` is scratch, reused across calls.
    fn outputs(&self, leaves: &[Block], buf: &mut Vec<Block>, outs: &mut Vec<(Block, K)>) {
        leaf_hash_many(&self.prf, &self.bottom, &self.leaf_words, leaves, buf);
        let (k, tau) = (leaves.len(), self.leaf_words.len() + 1);
        let mut h = vec![Block::ZERO; tau];
        outs.clear();
        outs.extend(leaves.iter().enumerate().map(|(i, st)| {
            for (j, x) in h.iter_mut().enumerate() {
                *x = buf[j * k + i];
            }
            self.output(st.lsb(), &h)
        }));
    }
}

/// An output and its MAC, both in `F_{2^k}`.
fn lift<K: Field>(outs: &[(Block, K)]) -> Vec<(K, K)> {
    outs.iter().map(|&(y, m)| (K::from_u128(y.0), m)).collect()
}

/// Π_Verify over `F_{2^k}` on the evaluation outputs `(⟨y_i⟩, ⟨m_i⟩)`, which
/// stay shared.
pub fn verify<K: Field, R: RngCore + CryptoRng>(ch: &mut Channel, outs: &[(Block, K)], delta_share: K, mask: VerifyMask<K>, rng: &mut R) -> Result<(), Abort> {
    pi_verify(ch, &lift(outs), delta_share, mask, None, rng)
}

/// Opens outputs that [`verify`] accepted, checking them against their MACs.
pub fn open_checked<K: Field, R: RngCore + CryptoRng>(ch: &mut Channel, outs: &[(Block, K)], delta_share: K, rng: &mut R) -> Result<Vec<Block>, Abort> {
    Ok(verify::open_checked::<K, K, R>(ch, &lift(outs), delta_share, rng)?.into_iter().map(|y| Block(y.to_u128())).collect())
}

/// The full output pipeline: [`verify`], then [`open_checked`].
pub fn verify_and_open<K: Field, R: RngCore + CryptoRng>(ch: &mut Channel, outs: &[(Block, K)], delta_share: K, mask: VerifyMask<K>, rng: &mut R) -> Result<Vec<Block>, Abort> {
    verify(ch, outs, delta_share, mask, rng)?;
    open_checked(ch, outs, delta_share, rng)
}
