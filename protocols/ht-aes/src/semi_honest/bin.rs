//! Semi-honest variant with a binary payload: `β ∈ F_2^ℓ` XOR-shared, output
//! XOR shares (ℓ ≤ 128).
//!
//! Gen is the arithmetic one up to the leaf. In a group of characteristic 2
//! the sign `(−1)^{t_{n,0}}` is 1 and the payload needs no B2A, so the leaf is
//! `W_b = F^pay(s_{n,b})` for both b (40 rounds) and the opening of
//! `W_CW = W_0 ⊕ W_1 ⊕ β`. Evaluation outputs `F^pay(s) ⊕ t·W_CW`.
//!
//! Rounds: `1 + 41n + 40 + 1 = 41n + 42`. Preprocessing: the OT tower's COTs
//! for [`crate::sh_calls`] AES–MMO calls, n string triples, n COTs per
//! direction (the α-bits).

use super::gen::{drive, walk, GenOutput, Pre, Walk};
use crate::malicious::low;
use crate::{child, children, leaf_seed, pay_hash, state_hash};
use dpf_common::aes_tower::{bits_of, block_of, mmo_shared, Mmo, Shared128};
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
    pub root: Block,
    pub cws: Vec<Block>,
    /// `W_CW = F^pay(s_0) ⊕ F^pay(s_1) ⊕ β` (low ℓ bits).
    pub w_cw: Block,
}

impl BinKey {
    pub fn depth(&self) -> usize {
        depth_for(self.n_size)
    }

    /// Root, n words, ⌈ℓ/8⌉ bytes of `W_CW`.
    pub fn size_bytes(&self) -> usize {
        16 + 16 * self.cws.len() + self.bits.div_ceil(8)
    }

    /// This party's XOR share of `f(x)`.
    pub fn eval_point(&self, x: u64) -> Block {
        assert!(x < self.n_size);
        let n = self.depth();
        let mut st = self.root;
        for (i, &cw) in self.cws.iter().enumerate() {
            st = child(st, cw, (x >> (n - 1 - i)) & 1 == 1);
        }
        low(pay_hash().h(leaf_seed(st)), self.bits) ^ self.w_cw.and_bit(st.lsb())
    }

    /// Shares of `f(0), …, f(N − 1)`: all 2^n leaves, one level at a time.
    pub fn eval_full(&self) -> Vec<Block> {
        let mut nodes = vec![self.root];
        for &cw in &self.cws {
            let mut next = Vec::new();
            children(&nodes, cw, &mut next);
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
        stream_walk(self.root, self.cws.len(), batch, |l, parents, out| children(parents, self.cws[l - 1], out), |x0, leaves| {
            if x0 < self.n_size {
                self.outputs(&leaves[..leaves.len().min((self.n_size - x0) as usize)], &mut buf, &mut ys);
                visit(x0, &ys);
            }
        });
    }

    /// The outputs at `leaves` into `ys`; `buf` is scratch, reused across calls.
    fn outputs(&self, leaves: &[Block], buf: &mut Vec<Block>, ys: &mut Vec<Block>) {
        let k = leaves.len();
        buf.clear();
        buf.extend(leaves.iter().map(|&s| leaf_seed(s)));
        buf.resize(2 * k, Block::ZERO);
        let (seeds, w) = buf.split_at_mut(k);
        pay_hash().h_many(seeds, w);
        ys.clear();
        ys.extend(leaves.iter().zip(&*w).map(|(&st, &wv)| low(wv, self.bits) ^ self.w_cw.and_bit(st.lsb())));
    }
}

/// Setup, preprocessing and generation for one party: XOR shares of α and of
/// `β ∈ F_2^ℓ`.
#[allow(clippy::too_many_arguments)]
pub fn gen(ch: &mut Channel, n_size: u64, bits: usize, alpha_share: u64, beta_share: Block, seed: [u8; 32], ferret: Option<FerretConfig>) -> GenOutput<BinKey> {
    assert!((1..=128).contains(&bits));
    let n = depth_for(n_size);
    drive(ch, seed, ferret, n, n, |_, _, _| (), |cot, pre, (), rng, ch| {
        let b = ch.party();
        let Pre { mut be, string_triples } = pre;
        let delta = cot.delta();
        let Walk { root, st, cws, .. } = walk(&mut be, &string_triples, cot, rng, ch, n, alpha_share, &[], None);
        let fp = pay_hash();
        let jobs: [(&Mmo, Shared128<bool>); 2] = [(fp, bits_of(leaf_seed(st))), (fp, bits_of(leaf_seed(st ^ delta)))];
        let w = mmo_shared(&mut be, ch, &jobs);
        let w_share = low(block_of(&w[0]) ^ block_of(&w[1]), bits) ^ low(beta_share, bits);
        ch.send(w_share.to_bytes().to_vec());
        let theirs = ch.recv();
        assert_eq!(theirs.len(), 16, "malformed payload share");
        let w_cw = w_share ^ Block::from_bytes(&theirs);
        (BinKey { party: b, n_size, bits, root, cws, w_cw }, be.ands)
    })
}

/// Trusted-dealer generation for given roots (`lsb(root_b) = b`): the cleartext
/// Gen, and the bit-exact oracle of [`gen`].
pub fn deal(roots: [Block; 2], n_size: u64, bits: usize, alpha: u64, beta: Block) -> [BinKey; 2] {
    assert!(alpha < n_size);
    assert!(!roots[0].lsb() && roots[1].lsb(), "lsb(root_b) = b");
    assert_eq!(beta, low(beta, bits), "β must fit in the output width");
    let n = depth_for(n_size);
    let delta = roots[0] ^ roots[1];
    let mut st = roots;
    let mut cws = Vec::with_capacity(n);
    for i in 0..n {
        let a = (alpha >> (n - 1 - i)) & 1 == 1;
        let cw = state_hash().h(st[0]) ^ state_hash().h(st[1]) ^ delta.and_bit(!a);
        st = [child(st[0], cw, a), child(st[1], cw, a)];
        cws.push(cw);
    }
    let w_cw = low(pay_hash().h(leaf_seed(st[0])) ^ pay_hash().h(leaf_seed(st[1])), bits) ^ beta;
    let mk = |party: usize| BinKey { party, n_size, bits, root: roots[party], cws: cws.clone(), w_cw };
    [mk(0), mk(1)]
}

/// Trusted-dealer generation from a seed.
pub fn gen_reference(n_size: u64, bits: usize, alpha: u64, beta: Block, seed: [u8; 32]) -> [BinKey; 2] {
    let mut rng = ChaCha20Rng::from_seed(seed);
    let roots = [Block::random(&mut rng).with_lsb(false), Block::random(&mut rng).with_lsb(true)];
    deal(roots, n_size, bits, alpha, beta)
}
