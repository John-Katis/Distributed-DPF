//! Semi-honest variant with a binary payload: `β ∈ F_2^ℓ` XOR-shared, output
//! XOR shares (ℓ ≤ 128).
//!
//! Gen is the arithmetic one ([`super::gen`]) up to the leaf. In a group of
//! characteristic 2 the sign `(−1)^{t_{n,0}}` is 1, so the order of the two
//! leaf states does not matter and the payload needs no B2A: the leaf hashes
//! `u_n`, `u_n ⊕ Δ` directly (no `Y`, no 𝓕_COT for `t_{n,0}`) and opens `W_CW =
//! h_0 ⊕ h_1 ⊕ β` (low ℓ bits) right after the AES–MMO calls, concurrently
//! with Step B. Evaluation outputs `F^pay(s) ⊕ t·W_CW`.
//!
//! Rounds: `max(ν + 3, 42)` for ν < n, `max(n + 3, 41)` for ν = n.
//! Preprocessing: as the arithmetic variant's, without the leaf's daBits.

use super::gen::{drive, walk, Deviation, GenOutput, Pre, Session, Shape, Walk};
use super::key::level_word;
use crate::malicious::low;
use crate::{child, children_masked, deal_walk_nu, default_nu, leaf_seed};
use dpf_common::aes_tower::Mmo;
use dpf_common::block::{depth_for, Block};
use dpf_common::net::Channel;
use dpf_common::ot::FerretConfig;
use dpf_common::stream::walk as stream_walk;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BinKey {
    pub party: usize,
    pub n_size: u64,
    /// ℓ ≤ 128.
    pub bits: usize,
    /// `F = H_K` and `F^pay = H_K(· ∥ 0)`, K public.
    pub prf: Mmo,
    pub root: Block,
    /// The glue level ν ≥ 1.
    pub nu: usize,
    pub cws: Vec<Block>,
    /// `M_ν, …, M_n`.
    pub ms: Vec<Block>,
    /// `W_CW = F^pay(s_0) ⊕ F^pay(s_1) ⊕ β` (low ℓ bits).
    pub w_cw: Block,
}

impl BinKey {
    pub fn depth(&self) -> usize {
        depth_for(self.n_size)
    }

    /// K, root, n + (n − ν + 1) words, ⌈ℓ/8⌉ bytes of `W_CW`.
    pub fn size_bytes(&self) -> usize {
        16 + 16 + 16 * (self.cws.len() + self.ms.len()) + self.bits.div_ceil(8)
    }

    /// `M_ℓ`, zero above the glue level.
    #[inline]
    pub fn m(&self, level: usize) -> Block {
        level_word(self.nu, &self.ms, level)
    }

    /// This party's XOR share of `f(x)`.
    pub fn eval_point(&self, x: u64) -> Block {
        assert!(x < self.n_size);
        let n = self.depth();
        let mut st = self.root ^ self.m(0);
        for (i, &cw) in self.cws.iter().enumerate() {
            st = child(&self.prf, st, cw, (x >> (n - 1 - i)) & 1 == 1) ^ self.m(i + 1);
        }
        low(self.prf.h(leaf_seed(st)), self.bits) ^ self.w_cw.and_bit(st.lsb())
    }

    /// Shares of `f(0), …, f(N − 1)`: all 2^n leaves, one level at a time.
    pub fn eval_full(&self) -> Vec<Block> {
        let mut nodes = vec![self.root ^ self.m(0)];
        for (i, &cw) in self.cws.iter().enumerate() {
            let mut next = Vec::new();
            children_masked(&self.prf, &nodes, cw, self.m(i + 1), &mut next);
            nodes = next;
        }
        nodes.truncate(self.n_size as usize);
        let mut ys = Vec::new();
        self.outputs(&nodes, &mut Vec::new(), &mut ys);
        ys
    }

    /// [`eval_full`](Self::eval_full) without holding the domain: a batched
    /// walk ([`dpf_common::stream`]) that calls `visit(x0, ys)` with this
    /// party's shares at `x0 .. x0 + ys.len()`, for all x < N.
    pub fn eval_full_stream(&self, batch: usize, mut visit: impl FnMut(u64, &[Block])) {
        let (mut buf, mut ys) = (Vec::new(), Vec::new());
        stream_walk(
            self.root ^ self.m(0),
            self.cws.len(),
            batch,
            |l, parents, out| children_masked(&self.prf, parents, self.cws[l - 1], self.m(l), out),
            |x0, leaves| {
                if x0 < self.n_size {
                    self.outputs(&leaves[..leaves.len().min((self.n_size - x0) as usize)], &mut buf, &mut ys);
                    visit(x0, &ys);
                }
            },
        );
    }

    /// The outputs at `leaves` into `ys`; `buf` is scratch, reused across calls.
    fn outputs(&self, leaves: &[Block], buf: &mut Vec<Block>, ys: &mut Vec<Block>) {
        let k = leaves.len();
        buf.clear();
        buf.extend(leaves.iter().map(|&s| leaf_seed(s)));
        buf.resize(2 * k, Block::ZERO);
        let (seeds, w) = buf.split_at_mut(k);
        self.prf.h_many(seeds, w);
        ys.clear();
        ys.extend(leaves.iter().zip(&*w).map(|(&st, &wv)| low(wv, self.bits) ^ self.w_cw.and_bit(st.lsb())));
    }
}

impl Session {
    /// Preprocessing and generation of a key with a binary payload: XOR
    /// shares of α (random) and of `β ∈ F_2^ℓ`, glue level `nu ≥ 1`
    /// ([`default_nu`] if `None`).
    pub fn gen_bin(&mut self, ch: &mut Channel, n_size: u64, nu: Option<usize>, bits: usize, beta_share: Block) -> GenOutput<BinKey> {
        assert!((1..=128).contains(&bits));
        let n = depth_for(n_size);
        drive(
            ch,
            &mut self.s,
            n,
            Shape::sh(nu.unwrap_or(default_nu(n)), false),
            0,
            |_, _, _| (),
            |mut pre, (), ch| {
                let b = ch.party();
                let Walk { cws, ms, leaf, mut leaf_lane, top_lane, .. } = walk(&mut pre, ch, onpath_leaf_jobs, Deviation::default(), false);
                let w_share = low(leaf[0] ^ leaf[1], bits) ^ low(beta_share, bits);
                let theirs = ch.exchange_on(&mut leaf_lane, w_share.to_bytes().to_vec());
                assert_eq!(theirs.len(), 16, "malformed payload share");
                ch.join(leaf_lane);
                ch.join(top_lane);
                let w_cw = w_share ^ Block::from_bytes(&theirs);
                (BinKey { party: b, n_size, bits, prf: pre.keys.swap_remove(0), root: pre.root(), nu: pre.shape.nu, cws, ms, w_cw }, pre.be.ands)
            },
        )
    }
}

/// Leaf jobs for a binary payload: `H_K(seed(u_n ⊕ c·Δ))`, `c = 0, 1`.
pub(crate) fn onpath_leaf_jobs(pre: &Pre) -> Vec<(usize, Block)> {
    vec![(0, leaf_seed(pre.un())), (0, leaf_seed(pre.un() ^ pre.delta))]
}

/// [`Session::setup`] and one [`Session::gen_bin`].
pub fn gen(ch: &mut Channel, n_size: u64, nu: Option<usize>, bits: usize, beta_share: Block, seed: [u8; 32], ferret: Option<FerretConfig>) -> GenOutput<BinKey> {
    Session::setup(ch, seed, ferret).gen_bin(ch, n_size, nu, bits, beta_share)
}

/// Trusted-dealer generation for given roots (`lsb(root_b) = b`), AES key K,
/// glue level ν ≥ 1 and on-path states `us = [u_ν, …, u_n]` of party 0: the
/// cleartext Gen, and the bit-exact oracle of [`gen`].
#[allow(clippy::too_many_arguments)]
pub fn deal(roots: [Block; 2], key: [u8; 16], n_size: u64, nu: usize, bits: usize, alpha: u64, beta: Block, us: &[Block]) -> [BinKey; 2] {
    assert_eq!(beta, low(beta, bits), "β must fit in the output width");
    let prf = Mmo::new(key);
    let (cws, ms, st) = deal_walk_nu(&prf, roots, depth_for(n_size), nu, alpha, us);
    let w_cw = low(prf.h(leaf_seed(st[0])) ^ prf.h(leaf_seed(st[1])), bits) ^ beta;
    let mk = |party: usize| BinKey { party, n_size, bits, prf: prf.clone(), root: roots[party], nu, cws: cws.clone(), ms: ms.clone(), w_cw };
    [mk(0), mk(1)]
}

/// Trusted-dealer generation from a seed, glue level [`default_nu`].
pub fn gen_reference(n_size: u64, bits: usize, alpha: u64, beta: Block, seed: [u8; 32]) -> [BinKey; 2] {
    assert!(alpha < n_size);
    let mut rng = ChaCha20Rng::from_seed(seed);
    let (roots, key, nu, us) = super::gen::reference_params(n_size, &mut rng);
    deal(roots, key, n_size, nu, bits, alpha, beta, &us)
}
