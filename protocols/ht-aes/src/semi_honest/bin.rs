//! Semi-honest variant with a binary payload: `β ∈ F_2^ℓ` XOR-shared, output
//! XOR shares (ℓ ≤ 128).
//!
//! Gen is the arithmetic one ([`super::gen`]) up to the leaf, as in the paper's
//! paragraph "Boolean payloads": the servers open `W_CW = W(L^0_{n+1}) ⊕
//! W(L^1_{n+1}) ⊕ β` right after the pairs, with no sign, B2A or product.
//! Below ν the servers play symmetric roles, so the glue takes the state of
//! the server with tag 1 as `st_{ν,0}`: no tag count and no 𝓕_COT, and `M^0_ν
//! = E ⊕ u^0_ν ⊕ C_ν`. Evaluation outputs `W(h) ⊕ t·W_CW`.
//!
//! Rounds: `max(ν + 2, 23)` for ν < n, `max(ν + 1, 22)` for ν = n.
//! Preprocessing: as the arithmetic variant's, without the leaf's daBits and
//! triple and without the glue's COT.

use super::gen::{drive, walk_pairs, GenOutput, PairWalk, PreSpec, Session};
use crate::malicious::low;
use crate::{deal_pairs, default_nu, expand_level, Bottom};
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
    /// `F = H_K`, K public.
    pub prf: Mmo,
    pub root: Block,
    pub cws: Vec<Block>,
    /// `M^0_ℓ`, `C_ℓ` and `b^τ_ℓ` for `ν ≤ ℓ ≤ n`.
    pub bottom: Bottom,
    /// `W_CW = W(L^0_{n+1}) ⊕ W(L^1_{n+1}) ⊕ β` (low ℓ bits).
    pub w_cw: Block,
}

impl BinKey {
    pub fn depth(&self) -> usize {
        depth_for(self.n_size)
    }

    /// The glue level ν.
    pub fn nu(&self) -> usize {
        self.bottom.nu
    }

    /// K, root, n level words, the bottom layer's words, ⌈ℓ/8⌉ bytes of `W_CW`.
    pub fn size_bytes(&self) -> usize {
        16 + 16 + 16 * self.cws.len() + self.bottom.size_bytes() + self.bits.div_ceil(8)
    }

    /// This party's XOR share of `f(x)`.
    pub fn eval_point(&self, x: u64) -> Block {
        assert!(x < self.n_size);
        let st = self.bottom.path(&self.prf, self.root, &self.cws, x);
        low(self.prf.h(self.bottom.hash_input(self.depth(), st)), self.bits) ^ self.w_cw.and_bit(st.lsb())
    }

    /// Shares of `f(0), …, f(N − 1)`: all 2^n leaves, one level at a time.
    pub fn eval_full(&self) -> Vec<Block> {
        let mut nodes = vec![self.root];
        for (i, &cw) in self.cws.iter().enumerate() {
            let mut next = Vec::new();
            expand_level(&self.prf, &nodes, cw, &self.bottom, i + 1, &mut next);
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
            self.root,
            self.cws.len(),
            batch,
            |l, parents, out| expand_level(&self.prf, parents, self.cws[l - 1], &self.bottom, l, out),
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
        let (k, n) = (leaves.len(), self.depth());
        buf.clear();
        buf.extend(leaves.iter().map(|&s| self.bottom.hash_input(n, s)));
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
            nu.unwrap_or(default_nu(n)),
            PreSpec { binary: true, ..Default::default() },
            |_, _, _| (),
            |mut pre, (), ch| {
                let b = ch.party();
                let PairWalk { cws, bottom, hs, xs, mut leaf_lane, .. } = walk_pairs(&mut pre, ch, None, false);
                let w_share = low(hs[0] ^ hs[1], bits) ^ low(beta_share, bits);
                let theirs = ch.exchange_on(&mut leaf_lane, w_share.to_bytes().to_vec());
                assert_eq!(theirs.len(), 16, "malformed payload share");
                ch.join(leaf_lane);
                let w_cw = w_share ^ Block::from_bytes(&theirs);
                let root = pre.root();
                (BinKey { party: b, n_size, bits, prf: pre.key, root, cws, bottom, w_cw }, pre.be.ands, xs)
            },
        )
    }
}

/// [`Session::setup`] and one [`Session::gen_bin`].
pub fn gen(ch: &mut Channel, n_size: u64, nu: Option<usize>, bits: usize, beta_share: Block, seed: [u8; 32], ferret: Option<FerretConfig>) -> GenOutput<BinKey> {
    Session::setup(ch, seed, ferret).gen_bin(ch, n_size, nu, bits, beta_share)
}

/// Trusted-dealer generation for given roots (`lsb(root_b) = b`), AES key K,
/// glue level ν ≥ 1, inputs `pairs = [[X^0_ℓ, X^1_ℓ]]` and bits `rs` of levels
/// ν..=n: the cleartext Gen, and the bit-exact oracle of [`gen`].
#[allow(clippy::too_many_arguments)]
pub fn deal(roots: [Block; 2], key: [u8; 16], n_size: u64, nu: usize, bits: usize, alpha: u64, beta: Block, pairs: &[[Block; 2]], rs: &[bool]) -> [BinKey; 2] {
    assert_eq!(beta, low(beta, bits), "β must fit in the output width");
    let prf = Mmo::new(key);
    let (cws, bottom, h) = deal_pairs(&prf, roots, depth_for(n_size), nu, alpha, pairs, rs, true);
    let w_cw = low(h[0] ^ h[1], bits) ^ beta;
    let mk = |party: usize| BinKey { party, n_size, bits, prf: prf.clone(), root: roots[party], cws: cws.clone(), bottom: bottom.clone(), w_cw };
    [mk(0), mk(1)]
}

/// Trusted-dealer generation from a seed, glue level [`default_nu`].
pub fn gen_reference(n_size: u64, bits: usize, alpha: u64, beta: Block, seed: [u8; 32]) -> [BinKey; 2] {
    assert!(alpha < n_size);
    let mut rng = ChaCha20Rng::from_seed(seed);
    let (roots, key, nu, pairs, rs) = super::gen::reference_params(n_size, &mut rng);
    deal(roots, key, n_size, nu, bits, alpha, beta, &pairs, &rs)
}
