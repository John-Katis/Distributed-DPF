//! The arithmetic malicious key: the semi-honest key's words, the leaf MAC's
//! words `C^j`, `N^j` and `W^MAC_CW ∈ E`; evaluation returns additive shares of
//! the output (in F) and of its MAC (in E), and [`verify`] is Π_Verify over E
//! with the keys' glue residuals over `𝔽'`.

use crate::field::{mac_mask, Ext, Field, M127};
use crate::leaf::Triple;
use crate::verify::{open_checked, pi_verify, VerifyMask};
use crate::{expand_level, leaf_hash, leaf_hash_many, Bottom};
use dpf_common::aes_tower::Mmo;
use dpf_common::block::{depth_for, Block};
use dpf_common::coin::Abort;
use dpf_common::net::Channel;
use dpf_common::stream::walk;
use rand::{CryptoRng, RngCore};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArithMalKey<F: Field, E: Ext<F>> {
    pub party: usize,
    pub n_size: u64,
    /// `F = H_K`, K public (the session's).
    pub prf: Mmo,
    pub root: Block,
    pub cws: Vec<Block>,
    /// `M^0_ℓ`, `C_ℓ` and `b^τ_ℓ` for `ν ≤ ℓ ≤ n`.
    pub bottom: Bottom,
    /// `[C^j, N^j]` of the leaf hash, `2 ≤ j ≤ τ`.
    pub leaf_words: Vec<[Block; 2]>,
    /// `W_CW = (1 − 2σ)·(W_0 − W_1 − β)`, `σ = r_n`.
    pub w_cw: F,
    /// `W^MAC_CW = (1 − 2σ)·(W̃_0 − W̃_1 − δβ)`.
    pub wm_cw: E,
}

impl<F: Field, E: Ext<F>> ArithMalKey<F, E> {
    pub fn depth(&self) -> usize {
        depth_for(self.n_size)
    }

    /// The glue level ν.
    pub fn nu(&self) -> usize {
        self.bottom.nu
    }

    /// K, root, n level words, the bottom layer's words, `C^j` and `N^j`,
    /// `W_CW`, `W^MAC_CW`, and the share of ω a server keeps with its key.
    pub fn size_bytes(&self) -> usize {
        16 + 16 + 16 * self.cws.len() + self.bottom.size_bytes() + 32 * self.leaf_words.len() + F::BYTES + E::BYTES + M127::BYTES
    }

    /// `(−1)^b·(W(h) + t·W_CW, F^mac(h) + t·W^MAC_CW)` at a leaf with tag `t`.
    #[inline]
    fn output(&self, t: bool, h: &[Block]) -> (F, E) {
        let (mut y, mut m) = (F::from_block(h[0]), mac_mask::<F, E>(h));
        if t {
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
        let st = self.bottom.path(&self.prf, self.root, &self.cws, x);
        self.output(st.lsb(), &leaf_hash(&self.prf, &self.bottom, &self.leaf_words, st))
    }

    /// Shares `(y, m)` at x = 0, …, N − 1: all 2^n leaves, one level at a time.
    pub fn eval_full(&self) -> Vec<(F, E)> {
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
    pub fn eval_full_stream(&self, batch: usize, mut visit: impl FnMut(u64, &[(F, E)])) {
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
    fn outputs(&self, leaves: &[Block], buf: &mut Vec<Block>, outs: &mut Vec<(F, E)>) {
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

/// Π_Verify ([`pi_verify`]) over E on the evaluation outputs `(⟦y_i⟧, ⟦m_i⟧)`,
/// which stay shared, and the glue residuals `⟦ω_j⟧` of the keys in the batch;
/// `glue` is the triple that masks μ′.
pub fn verify<F: Field, E: Ext<F>, R: RngCore + CryptoRng>(
    ch: &mut Channel,
    outs: &[(F, E)],
    omegas: &[M127],
    delta_share: E,
    mask: VerifyMask<E>,
    glue: Triple<M127>,
    rng: &mut R,
) -> Result<(), Abort> {
    let lifted: Vec<(E, E)> = outs.iter().map(|&(y, m)| (E::embed(y), m)).collect();
    pi_verify(ch, &lifted, delta_share, mask, Some((omegas, glue)), rng)
}

/// The full output pipeline: [`verify`], then [`open_checked`]. Returns the
/// outputs, or aborts.
#[allow(clippy::too_many_arguments)]
pub fn verify_and_open<F: Field, E: Ext<F>, R: RngCore + CryptoRng>(
    ch: &mut Channel,
    outs: &[(F, E)],
    omegas: &[M127],
    delta_share: E,
    mask: VerifyMask<E>,
    glue: Triple<M127>,
    rng: &mut R,
) -> Result<Vec<F>, Abort> {
    verify(ch, outs, omegas, delta_share, mask, glue, rng)?;
    open_checked(ch, outs, delta_share, rng)
}
