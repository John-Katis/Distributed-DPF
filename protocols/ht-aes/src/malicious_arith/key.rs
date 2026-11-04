//! The arithmetic malicious key: AES keys, root, level words, payload word
//! `W_CW ∈ F` and payload-MAC word `W^MAC_CW ∈ E`; evaluation returns
//! additive shares of the output (in F) and of its MAC (in E), and [`verify`]
//! is Π_Verify over E, with the keys' glue residuals.

use super::gen::mac_mask;
use crate::field::{Ext, Field};
use crate::semi_honest::key::level_word;
use crate::{child, children_masked, leaf_seed};
use dpf_common::aes_tower::Mmo;
use dpf_common::block::{depth_for, Block};
use dpf_common::coin::{coin_block, commit_and_open_blocks, Abort};
use dpf_common::hash::CtrPrg;
use dpf_common::net::Channel;
use dpf_common::stream::walk;
use rand::{CryptoRng, RngCore};

/// This party's shares of a Π_Verify mask `(ρ, δ·ρ)`, ρ uniform in E; one per
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
    /// `F = H_K` and `F^pay = H_K(· ∥ 0)`, K public (the session's).
    pub prf: Mmo,
    /// `F^mac`: `H_{K^mac_1}(· ∥ 0) ∥ … ∥ H_{K^mac_c}(· ∥ 0)`, c =
    /// [`crate::field::mask_blocks`].
    pub mac: Vec<Mmo>,
    pub root: Block,
    /// The glue level ν ≥ 1.
    pub nu: usize,
    pub cws: Vec<Block>,
    /// `M_ν, …, M_n`.
    pub ms: Vec<Block>,
    /// `W_CW = (−1)^{t_{n,0}}·(W_0 − W_1 − β)`.
    pub w_cw: F,
    /// `W^MAC_CW = (−1)^{t_{n,0}}·(W̃_0 − W̃_1 − δβ)`.
    pub wm_cw: E,
}

impl<F: Field, E: Ext<F>> ArithMalKey<F, E> {
    pub fn depth(&self) -> usize {
        depth_for(self.n_size)
    }

    /// K and the c keys `K^mac_j`, root, n + (n − ν + 1) words, `W_CW` and
    /// `W^MAC_CW`.
    pub fn size_bytes(&self) -> usize {
        16 * (1 + self.mac.len()) + 16 + 16 * (self.cws.len() + self.ms.len()) + F::BYTES + E::BYTES
    }

    /// `M_ℓ`, zero above the glue level.
    #[inline]
    pub fn m(&self, level: usize) -> Block {
        level_word(self.nu, &self.ms, level)
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
        let mut st = self.root ^ self.m(0);
        for (i, &cw) in self.cws.iter().enumerate() {
            st = child(&self.prf, st, cw, (x >> (n - 1 - i)) & 1 == 1) ^ self.m(i + 1);
        }
        let s = leaf_seed(st);
        self.output(st, self.prf.h(s), mac_mask::<F, E>(&self.mac, s))
    }

    /// Shares `(y, m)` at x = 0, …, N − 1: all 2^n leaves, one level at a time.
    pub fn eval_full(&self) -> Vec<(F, E)> {
        let mut nodes = vec![self.root ^ self.m(0)];
        for (i, &cw) in self.cws.iter().enumerate() {
            let mut next = Vec::new();
            children_masked(&self.prf, &nodes, cw, self.m(i + 1), &mut next);
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
            self.root ^ self.m(0),
            self.cws.len(),
            batch,
            |l, parents, out| children_masked(&self.prf, parents, self.cws[l - 1], self.m(l), out),
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
        self.prf.h_many(seeds, w);
        outs.clear();
        outs.extend(leaves.iter().zip(seeds.iter().zip(&*w)).map(|(&st, (&s, &wv))| self.output(st, wv, mac_mask::<F, E>(&self.mac, s))));
    }
}

/// Π_Verify (Figure "Π_Verify") over E for a batch of evaluation outputs
/// `(⟦y_i⟧, ⟦m_i⟧)`, which stay shared, and the glue residuals `⟦ω_j⟧` of
/// the keys in the batch: with coin-tossed `χ_i`, `χ'_j` (after the outputs
/// are fixed) and the mask `(⟦ρ⟧, ⟦δρ⟧)`, open `z = Σ χ_i y_i + ρ`, then commit
/// to and open `μ_b = Σ χ_i m_{i,b} + (δρ)_b − δ_b·z + Σ χ'_j ω_{j,b}` and
/// accept iff `μ_0 + μ_1 = 0`. Only z, uniform through ρ, and μ are opened.
pub fn verify<F: Field, E: Ext<F>, R: RngCore + CryptoRng>(
    ch: &mut Channel,
    outs: &[(F, E)],
    omegas: &[E],
    delta_share: E,
    mask: VerifyMask<E>,
    rng: &mut R,
) -> Result<(), Abort> {
    let chi: Vec<E> = CtrPrg::new(coin_block(ch, rng)?).next_words(outs.len() + omegas.len()).into_iter().map(|c| E::from_seed(Block(c))).collect();
    let (mut y, mut m) = (mask.r, mask.dr);
    for (o, &c) in outs.iter().zip(&chi) {
        y = y.add(c.mul(E::embed(o.0)));
        m = m.add(c.mul(o.1));
    }
    let residual = omegas.iter().zip(&chi[outs.len()..]).fold(E::ZERO, |a, (&w, &c)| a.add(c.mul(w)));
    let mut msg = Vec::with_capacity(E::BYTES);
    y.put(&mut msg);
    ch.send(msg);
    let theirs = ch.recv();
    if theirs.len() != E::BYTES {
        return Err(Abort("malformed verify message"));
    }
    let z = y.add(E::get(&theirs));
    let sigma = m.sub(delta_share.mul(z)).add(residual);
    let other = commit_and_open_blocks(ch, &[Block(sigma.to_u128())], rng)?[0];
    if E::from_u128(other.0).add(sigma) != E::ZERO {
        return Err(Abort("output MAC check failed"));
    }
    Ok(())
}

/// Opens checked outputs: exchanges the output shares, then checks the
/// opened `y_i` against their MAC shares, `Σ χ'_i (m_{i,b} − δ_b·y_i)` for
/// fresh coin-tossed `χ'_i`, committed and opened, so a party that opens a
/// share other than the one Π_Verify checked is caught. Returns the outputs.
pub fn open_checked<F: Field, E: Ext<F>, R: RngCore + CryptoRng>(
    ch: &mut Channel,
    outs: &[(F, E)],
    delta_share: E,
    rng: &mut R,
) -> Result<Vec<F>, Abort> {
    let mut msg = Vec::with_capacity(outs.len() * F::BYTES);
    outs.iter().for_each(|o| o.0.put(&mut msg));
    ch.send(msg);
    let theirs = ch.recv();
    if theirs.len() != outs.len() * F::BYTES {
        return Err(Abort("malformed output shares"));
    }
    let ys: Vec<F> = outs.iter().zip(theirs.chunks(F::BYTES)).map(|(o, t)| o.0.add(F::get(t))).collect();
    let chi = CtrPrg::new(coin_block(ch, rng)?).next_words(outs.len());
    let sigma =
        outs.iter().zip(&ys).zip(&chi).fold(E::ZERO, |acc, ((o, &y), &c)| acc.add(E::from_seed(Block(c)).mul(o.1.sub(delta_share.mul(E::embed(y))))));
    let other = commit_and_open_blocks(ch, &[Block(sigma.to_u128())], rng)?[0];
    if E::from_u128(other.0).add(sigma) != E::ZERO {
        return Err(Abort("opened output MAC check failed"));
    }
    Ok(ys)
}

/// The full output pipeline: [`verify`] on the shared outputs and the keys'
/// glue residuals, then [`open_checked`]. Returns the outputs, or aborts.
pub fn verify_and_open<F: Field, E: Ext<F>, R: RngCore + CryptoRng>(
    ch: &mut Channel,
    outs: &[(F, E)],
    omegas: &[E],
    delta_share: E,
    mask: VerifyMask<E>,
    rng: &mut R,
) -> Result<Vec<F>, Abort> {
    verify(ch, outs, omegas, delta_share, mask, rng)?;
    open_checked(ch, outs, delta_share, rng)
}
