//! Malicious generation with abort on the semi-honest preprocessing.
//!
//! Gen is the semi-honest one ([`crate::semi_honest`]), with the same
//! correlations (FOLEAGE F4 triples, Ferret COTs, string triples), extended as
//! in the paper's "Authenticated generation":
//!
//! 1. A persistent payload-MAC key `δ = δ_0 ⊕ δ_1 ∈ GF(2^128)`, sampled once
//!    per session and never opened. Π_Verify opens the outputs before it
//!    uses δ, so δ only ever enters linearly and needs no MAC of its own.
//! 2. The MAC mask `F^mac` (a third fixed-key MMO) on both leaf seeds, in
//!    parallel with `F^pay`.
//! 3. `⟨δ·β⟩ = Σ_i β_i·⟨X^i δ⟩`: ℓ bit-times-block Beaver products, opened
//!    with the level-0 message.
//! 4. `W_CW = W_0 ⊕ W_1 ⊕ β` and `W^MAC_CW = W̃_0 ⊕ W̃_1 ⊕ δβ`, opened
//!    together (in a binary payload group the sign `(−1)^{t_{n,0}}` is 1).
//!
//! Every deviation in Gen, in the PRF products, the branch selection or an
//! opening, shows up only in the published key material, which Π_Verify
//! ([`super::verify`]) checks at evaluation time (Propositions "One-Hot" and
//! "MAC Detection" of the paper).
//!
//! Rounds: `1 + 41n + 40 + 1 = 41n + 42`.

use super::key::{low, MalKey};
use crate::semi_honest::gen::{precompute_counts, setup, walk, F4Source, Pre, Setup, Walk};
use crate::{leaf_seed, mac_hash, pay_hash};
use dpf_common::aes_tower::{bits_of, block_of, mmo_shared, Mmo, Shared128, PRODUCTS_PER_CALL};
use dpf_common::block::{depth_for, Block};
use dpf_common::foleage::Params;
use dpf_common::gf128;
use dpf_common::net::{Channel, CommStats};
use dpf_common::ot::FerretConfig;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::time::{Duration, Instant};

/// F4 products of one malicious Gen: two MMO calls per level, four at the leaf.
pub fn mal_products(n: usize) -> usize {
    (2 * n + 4) * PRODUCTS_PER_CALL
}

/// The FOLEAGE instance a malicious Gen of depth n needs.
pub fn mal_foleage_for(n: usize) -> Params {
    Params::for_oles(2 * mal_products(n))
}

/// Deliberate deviation for the abort tests: XOR `err` into this party's
/// share of the word opened at `level` (`n` = the payload word, `n + 1` = the
/// payload-MAC word) before opening it.
#[derive(Clone, Copy, Debug)]
pub struct Fault {
    pub level: usize,
    pub err: Block,
}

/// One party's long-lived state.
pub struct MalSession {
    s: Setup,
    /// `δ_b`, this party's share of the persistent payload-MAC key.
    pub delta_mac: Block,
}

impl MalSession {
    /// The semi-honest setup (base OTs, Ferret, FOLEAGE seed generation) and δ_b.
    pub fn setup(ch: &mut Channel, seed: [u8; 32], ferret: Option<FerretConfig>, foleage: impl Into<F4Source>) -> Self {
        let mut s = setup(ch, seed, ferret, foleage.into());
        let delta_mac = Block::random(&mut s.rng);
        MalSession { s, delta_mac }
    }

    /// FOLEAGE expansion into [`mal_products`] triples, `n + ℓ` string
    /// triples (branch selection, δ·β) and n COTs per direction.
    pub fn precompute(&mut self, ch: &mut Channel, n: usize, bits: usize) -> Pre {
        let s = &mut self.s;
        precompute_counts(ch, &mut s.cot, s.fseed.as_ref(), &mut s.fused, mal_products(n), n + bits, n, &mut s.rng)
    }

    /// One generation: XOR shares of α and of β ∈ {0,1}^ℓ.
    #[allow(clippy::too_many_arguments)]
    pub fn gen(&mut self, ch: &mut Channel, n_size: u64, bits: usize, alpha_share: u64, beta_share: Block, pre: Pre, fault: Option<Fault>) -> (MalKey, usize) {
        let b = ch.party();
        let n = depth_for(n_size);
        let err = |lvl: usize| match fault {
            Some(f) if f.level == lvl => f.err,
            _ => Block::ZERO,
        };
        let Pre { mut be, string_triples } = pre;
        let (branch, dm) = string_triples.split_at(n);

        // 3. Beaver openings of β_i·(X^i δ), riding with level 0.
        let xd: Vec<Block> = (0..bits).map(|i| gf128::mul(Block(1 << i), self.delta_mac)).collect();
        let mut extra = Vec::with_capacity(17 * bits);
        for i in 0..bits {
            let (ta, tb, _) = dm[i];
            extra.extend_from_slice(&(xd[i] ^ tb).to_bytes());
            extra.push((beta_share.bit(i) ^ ta) as u8);
        }

        let s = &mut self.s;
        let cw_err = fault.filter(|f| f.level < n).map(|f| (f.level, f.err));
        let Walk { root, st, cws, reply } = walk(&mut be, branch, &mut s.cot, &mut s.rng, ch, n, alpha_share, &extra, cw_err);
        assert_eq!(reply.len(), 17 * bits, "malformed δ·β opening");
        let mut db = Block::ZERO;
        for i in 0..bits {
            let (ta, tb, tc) = dm[i];
            let f = xd[i] ^ tb ^ Block::from_bytes(&reply[17 * i..17 * i + 16]);
            let e = beta_share.bit(i) ^ ta ^ (reply[17 * i + 16] & 1 == 1);
            db ^= f.and_bit(e && b == 0) ^ tb.and_bit(e) ^ f.and_bit(ta) ^ tc;
        }

        // 2 + 4. Leaf words.
        let delta = s.cot.delta();
        let (s0, s1) = (bits_of(leaf_seed(st)), bits_of(leaf_seed(st ^ delta)));
        let (fp, fm): (&Mmo, &Mmo) = (pay_hash(), mac_hash());
        let jobs: [(&Mmo, Shared128<bool>); 4] = [(fp, s0), (fp, s1), (fm, s0), (fm, s1)];
        let w: Vec<Block> = mmo_shared(&mut be, ch, &jobs).iter().map(block_of).collect();
        let w_share = low(w[0] ^ w[1], bits) ^ beta_share ^ low(err(n), bits);
        let wm_share = w[2] ^ w[3] ^ db ^ err(n + 1);
        let mut msg = w_share.to_bytes().to_vec();
        msg.extend_from_slice(&wm_share.to_bytes());
        ch.send(msg);
        let theirs = ch.recv();
        assert_eq!(theirs.len(), 32, "malformed payload words");
        let w_cw = w_share ^ Block::from_bytes(&theirs[..16]);
        let wm_cw = wm_share ^ Block::from_bytes(&theirs[16..]);
        let products = be.products;
        (MalKey { party: b, n_size, bits, root, cws, w_cw: low(w_cw, bits), wm_cw }, products)
    }
}

/// Everything one party gets from [`run_mal`].
pub struct MalRun {
    pub key: MalKey,
    /// This party's share of the payload-MAC key δ.
    pub delta_share: Block,
    /// Base OTs, Ferret bootstrap and the FOLEAGE seed generation.
    pub setup_stats: CommStats,
    pub setup_time: Duration,
    pub pre_stats: CommStats,
    pub pre_time: Duration,
    pub gen_stats: CommStats,
    pub gen_time: Duration,
    pub products: usize,
    /// COTs consumed after setup (α-bits, string triples).
    pub cots: usize,
    pub foleage: Option<Params>,
    pub seedgen_stats: CommStats,
    pub seedgen_time: Duration,
}

/// Setup, preprocessing and generation for one party. `foleage`: at least
/// [`mal_foleage_for`]`(n)`.
#[allow(clippy::too_many_arguments)]
pub fn run_mal(ch: &mut Channel, n_size: u64, bits: usize, alpha_share: u64, beta_share: Block, seed: [u8; 32], ferret: Option<FerretConfig>, foleage: impl Into<F4Source>, fault: Option<Fault>) -> MalRun {
    assert!((1..=128).contains(&bits));
    let f4: F4Source = foleage.into();
    let mut s = MalSession::setup(ch, seed, ferret, f4);
    let (setup_stats, setup_time) = (s.s.stats, s.s.time);
    let cots_before = s.s.cot.produced;
    let n = depth_for(n_size);
    let t_pre = Instant::now();
    let pre = s.precompute(ch, n, bits);
    let pre_stats = ch.stats().since(&setup_stats);
    let pre_time = t_pre.elapsed();
    // Timing only: counted in no phase.
    ch.sync();
    let before = ch.stats();
    let t = Instant::now();
    let (key, products) = s.gen(ch, n_size, bits, alpha_share, beta_share, pre, fault);
    MalRun {
        key,
        delta_share: s.delta_mac,
        setup_stats,
        setup_time,
        pre_stats,
        pre_time,
        gen_stats: ch.stats().since(&before),
        gen_time: t.elapsed(),
        products,
        cots: s.s.cot.produced - cots_before,
        foleage: f4.foleage(),
        seedgen_stats: s.s.seedgen_stats,
        seedgen_time: s.s.seedgen_time,
    }
}

/// Trusted-dealer generation for given roots (`lsb(root_b) = b`) and
/// payload-MAC key δ: the cleartext Gen and the oracle of [`MalSession::gen`].
pub fn deal(roots: [Block; 2], n_size: u64, bits: usize, alpha: u64, beta: Block, delta_mac: Block) -> [MalKey; 2] {
    assert!(alpha < n_size);
    assert!(!roots[0].lsb() && roots[1].lsb(), "lsb(root_b) = b");
    assert_eq!(beta, low(beta, bits), "β must fit in the output width");
    let n = depth_for(n_size);
    let delta = roots[0] ^ roots[1];
    let mut st = roots;
    let mut cws = Vec::with_capacity(n);
    for i in 0..n {
        let a = (alpha >> (n - 1 - i)) & 1 == 1;
        let cw = crate::state_hash().h(st[0]) ^ crate::state_hash().h(st[1]) ^ delta.and_bit(!a);
        st = [crate::child(st[0], cw, a), crate::child(st[1], cw, a)];
        cws.push(cw);
    }
    let s = [leaf_seed(st[0]), leaf_seed(st[1])];
    let w_cw = low(pay_hash().h(s[0]) ^ pay_hash().h(s[1]), bits) ^ beta;
    let wm_cw = mac_hash().h(s[0]) ^ mac_hash().h(s[1]) ^ gf128::mul(delta_mac, beta);
    let mk = |party: usize| MalKey { party, n_size, bits, root: roots[party], cws: cws.clone(), w_cw, wm_cw };
    [mk(0), mk(1)]
}

/// Dealer keys from a seed, with the δ shares.
pub fn gen_reference(n_size: u64, bits: usize, alpha: u64, beta: Block, seed: [u8; 32]) -> ([MalKey; 2], [Block; 2]) {
    let mut rng = ChaCha20Rng::from_seed(seed);
    let roots = [Block::random(&mut rng).with_lsb(false), Block::random(&mut rng).with_lsb(true)];
    let d = [Block::random(&mut rng), Block::random(&mut rng)];
    (deal(roots, n_size, bits, alpha, beta, d[0] ^ d[1]), d)
}
