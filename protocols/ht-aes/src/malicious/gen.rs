//! Malicious generation with abort, binary payload: the semi-honest Gen of
//! [`crate::semi_honest::gen`] in its session (one public K, one global ⟨Δ⟩,
//! a public W per Gen; top phase of ν ≥ 1 levels, glue, level-independent
//! lower levels joined by `M_ℓ`) with the paper's additions (Figure
//! "Additions to DPF.Gen") for a payload in `{0,1}^ℓ ⊂ GF(2^128)`:
//!
//! * Setup: a persistent payload-MAC key `δ = δ_0 ⊕ δ_1 ∈ GF(2^128)`, never
//!   opened, and a public `K^mac` (one block covers the MAC field, c = 1).
//! * (B) One product per bottom level: `(⟨α_ℓ·Δ⟩, ⟨P_ℓ⟩)` from one
//!   bit-times-2-block product of `⟨α_ℓ⟩` with `⟨Δ⟩ ∥ ⟨u_{ℓ−1}⟩`, so one choice
//!   bit serves Steps B and C (no zeroing).
//! * (A) The MAC word: `F^pay = H_K(· ∥ 0)` and `F^mac = H_{K^mac}(· ∥ 0)` on
//!   the two on-path leaf states `u_n`, `u_n ⊕ Δ` in the batch of the lower
//!   levels' AES–MMO calls; then `W_CW = h_0 ⊕ h_1 ⊕ β` and `W^MAC_CW = h̃_0 ⊕
//!   h̃_1 ⊕ β·δ` (β public, so `β·⟨δ⟩` is local) are opened together.
//!
//! No glue residual (C): in characteristic 2 the outputs are `y_0 ⊕ y_1`,
//! symmetric in the two servers, so the swap of the glue changes neither the
//! output nor its MAC; for the same reason the leaf needs no tag order (no
//! `Y`, no sign product). The Π_Verify mask `(⟨r⟩, ⟨δr⟩)` for a fresh random
//! r is 128 string triples in preprocessing.
//!
//! Rounds: `max(ν + 3, 42)` for ν < n, `max(n + 3, 41)` for ν = n.

use super::key::{low, MalKey};
use crate::malicious_arith::VerifyMask;
use crate::semi_honest::bin::onpath_leaf_jobs;
use crate::semi_honest::gen::{bit_times_block, precompute, setup, walk, Deviation, Pre, Setup, Shape, Walk};
use crate::{deal_walk_nu, default_nu, leaf_seed};
use dpf_common::aes_tower::Mmo;
use dpf_common::block::{depth_for, Block};
use dpf_common::gf128;
use dpf_common::net::{Channel, CommStats};
use dpf_common::ot::FerretConfig;
use rand::{CryptoRng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use std::time::{Duration, Instant};

/// AES–MMO calls in 2PC of one malicious Gen: two per level below ν, and
/// `F^pay`, `F^mac` on both leaf states.
pub fn mal_calls(n: usize, nu: usize) -> usize {
    2 * (n - nu) + 4
}

/// ANDs of one malicious Gen (all keys public: no Π_KeyExp).
pub fn mal_ands(n: usize, nu: usize) -> usize {
    mal_calls(n, nu) * dpf_common::aes_tower::ANDS_PER_CALL
}

/// Deliberate deviations for the abort tests.
#[derive(Clone, Copy, Debug)]
pub enum Fault {
    /// XOR `err` into this party's share of the word opened at `level` (`<
    /// n`: `CW_{level+1}`, `n`: the payload word, `n + 1`: the payload-MAC
    /// word, `n + 2`: `M_ν`) before opening it.
    Word { level: usize, err: Block },
    /// Flip this party's share of `¬t_{ν,0}` into the glue's 𝓕_COT: the glue
    /// outputs `st_{ν,1}`, so the servers swap their roles below ν.
    Swap,
    /// Flip this party's share of `α_{i+1}` into the one product it enters
    /// (𝓕_COT above ν, (B) below): the keys are honest keys for `α* = α ⊕
    /// e_{i+1}`.
    Alpha(usize),
}

impl Fault {
    /// The deviation in [`walk`] (the leaf words are the caller's).
    pub(crate) fn walk(fault: Option<Fault>, n: usize) -> Deviation {
        match fault {
            Some(Fault::Word { level, err }) if level < n => Deviation { word: Some((level, err)), ..Default::default() },
            Some(Fault::Word { level, err }) if level == n + 2 => Deviation { word: Some((n, err)), ..Default::default() },
            Some(Fault::Swap) => Deviation { flip_switch: true, ..Default::default() },
            Some(Fault::Alpha(i)) => Deviation { flip_alpha: Some(i), ..Default::default() },
            _ => Deviation::default(),
        }
    }

    /// The error on the leaf word `level` (n: payload, n + 1: MAC).
    pub(crate) fn leaf(fault: Option<Fault>, level: usize) -> Block {
        match fault {
            Some(Fault::Word { level: l, err }) if l == level => err,
            _ => Block::ZERO,
        }
    }
}

/// The preprocessing of one malicious Gen: the semi-honest one with (B)'s
/// wide triples, and the key's Π_Verify mask.
pub struct MalPre {
    pub pre: Pre,
    pub mask: VerifyMask<Block>,
}

/// One party's long-lived state.
pub struct MalSession {
    s: Setup,
    /// `δ_b`, this party's share of the persistent payload-MAC key.
    pub delta_mac: Block,
}

impl MalSession {
    /// Π_setup (base OTs, Ferret, ⟨Δ⟩, K, `K^mac`) and δ_b.
    pub fn setup(ch: &mut Channel, seed: [u8; 32], ferret: Option<FerretConfig>) -> Self {
        let mut s = setup(ch, seed, ferret, 1);
        let delta_mac = Block::random(&mut s.rng);
        MalSession { s, delta_mac }
    }

    /// The preprocessing of one Gen of depth n with glue level ν
    /// (`semi_honest::gen::precompute` for [`mal_calls`] AES–MMO calls with
    /// (B), and 128 more string triples), and the Π_Verify mask: a random r
    /// and `⟨δr⟩ = Σ_i r_i·⟨X^i δ⟩` from the 128 triples, one round.
    pub fn precompute(&mut self, ch: &mut Channel, n: usize, nu: usize) -> MalPre {
        let s = &mut self.s;
        let shape = Shape { nu, y: false, one_product: true };
        let mut pre = precompute(ch, s, n, shape, mal_calls(n, nu), 128, 0);
        let at = pre.string_triples.len() - 128;
        let mut mt = pre.string_triples.split_off(at);
        let r = Block::random(&mut s.rng);
        let sel: Vec<(bool, Block)> = (0..128).map(|i| (r.bit(i), gf128::mul(Block(1 << i), self.delta_mac))).collect();
        let mut lane = ch.lane();
        let dr = bit_times_block(ch, &mut lane, &sel, &mut mt.drain(..)).into_iter().fold(Block::ZERO, |a, x| a ^ x);
        ch.join(lane);
        MalPre { pre, mask: VerifyMask { r, dr } }
    }

    /// One generation of a key for the random α of `pre` and the public `β ∈
    /// {0,1}^ℓ`. Returns the key, the ANDs, the key's Π_Verify mask and this
    /// party's share of α.
    pub fn gen(&mut self, ch: &mut Channel, n_size: u64, bits: usize, beta: Block, pre: MalPre, fault: Option<Fault>) -> (MalKey, usize, VerifyMask<Block>, u64) {
        let b = ch.party();
        let n = depth_for(n_size);
        assert_eq!(beta, low(beta, bits), "β must fit in the output width");
        let MalPre { mut pre, mask } = pre;
        assert_eq!(pre.alpha_delta.len(), n, "preprocessing for depth n");

        // The Gen, with F^pay (key 0 = K) and F^mac (key 1 = K^mac) on u_n, u_n ⊕ Δ.
        let jobs = |p: &Pre| {
            let j = onpath_leaf_jobs(p);
            vec![j[0], j[1], (1, j[0].1), (1, j[1].1)]
        };
        let Walk { cws, ms, leaf: w, mut leaf_lane, top_lane, .. } = walk(&mut pre, ch, jobs, Fault::walk(fault, n), false);

        // (A) The leaf words, β public: party 0 adds β, each adds β·δ_b.
        let beta0 = if b == 0 { beta } else { Block::ZERO };
        let w_share = low(w[0] ^ w[1], bits) ^ beta0 ^ low(Fault::leaf(fault, n), bits);
        let wm_share = w[2] ^ w[3] ^ gf128::mul(self.delta_mac, beta) ^ Fault::leaf(fault, n + 1);
        let mut msg = w_share.to_bytes().to_vec();
        msg.extend_from_slice(&wm_share.to_bytes());
        let theirs = ch.exchange_on(&mut leaf_lane, msg);
        assert_eq!(theirs.len(), 32, "malformed payload words");
        ch.join(leaf_lane);
        ch.join(top_lane);
        let w_cw = w_share ^ Block::from_bytes(&theirs[..16]);
        let wm_cw = wm_share ^ Block::from_bytes(&theirs[16..]);
        let mut keys = std::mem::take(&mut pre.keys);
        let mac = keys.pop().unwrap();
        let prf = keys.pop().unwrap();
        let key = MalKey { party: b, n_size, bits, prf, mac, root: pre.root(), nu: pre.shape.nu, cws, ms, w_cw: low(w_cw, bits), wm_cw };
        (key, pre.be.ands, mask, pre.alpha_share)
    }
}

/// Everything one party gets from [`run_mal`].
pub struct MalRun {
    pub key: MalKey,
    /// This party's XOR share of the random index α.
    pub alpha_share: u64,
    /// This party's XOR shares of the on-path states `u_ν, …, u_n` of party 0.
    pub onpath_share: Vec<Block>,
    /// This party's share of the payload-MAC key δ.
    pub delta_share: Block,
    /// This party's share of the key's Π_Verify mask.
    pub mask: VerifyMask<Block>,
    /// Base OTs and the Ferret bootstrap.
    pub setup_stats: CommStats,
    pub setup_time: Duration,
    pub pre_stats: CommStats,
    pub pre_time: Duration,
    pub gen_stats: CommStats,
    pub gen_time: Duration,
    /// ANDs of the AES calls.
    pub ands: usize,
    /// COTs consumed after setup (the OT tower's, 𝓕_COT's, string triples).
    pub cots: usize,
}

/// Setup, preprocessing and generation for one party, glue level `nu ≥ 1`
/// ([`default_nu`] if `None`), public β.
#[allow(clippy::too_many_arguments)]
pub fn run_mal(
    ch: &mut Channel,
    n_size: u64,
    nu: Option<usize>,
    bits: usize,
    beta: Block,
    seed: [u8; 32],
    ferret: Option<FerretConfig>,
    fault: Option<Fault>,
) -> MalRun {
    assert!((1..=128).contains(&bits));
    let mut s = MalSession::setup(ch, seed, ferret);
    let (setup_stats, setup_time) = (s.s.stats, s.s.time);
    let cots_before = s.s.cot.produced;
    let n = depth_for(n_size);
    let t_pre = Instant::now();
    let pre = s.precompute(ch, n, nu.unwrap_or(default_nu(n)));
    let onpath_share = pre.pre.us.clone();
    let pre_stats = ch.stats().since(&setup_stats);
    let pre_time = t_pre.elapsed();
    // Timing only: counted in no phase.
    ch.sync();
    let before = ch.stats();
    let t = Instant::now();
    let (key, ands, mask, alpha_share) = s.gen(ch, n_size, bits, beta, pre, fault);
    MalRun {
        key,
        alpha_share,
        onpath_share,
        delta_share: s.delta_mac,
        mask,
        setup_stats,
        setup_time,
        pre_stats,
        pre_time,
        gen_stats: ch.stats().since(&before),
        gen_time: t.elapsed(),
        ands,
        cots: s.s.cot.produced - cots_before,
    }
}

/// Trusted-dealer generation for given roots (`lsb(root_b) = b`), AES keys K
/// and `K^mac`, glue level ν ≥ 1, on-path states `us = [u_ν, …, u_n]` of party
/// 0 and payload-MAC key δ: the cleartext Gen and the oracle of
/// [`MalSession::gen`].
#[allow(clippy::too_many_arguments)]
pub fn deal(roots: [Block; 2], keys: [[u8; 16]; 2], n_size: u64, nu: usize, bits: usize, alpha: u64, beta: Block, delta_mac: Block, us: &[Block]) -> [MalKey; 2] {
    assert_eq!(beta, low(beta, bits), "β must fit in the output width");
    let n = depth_for(n_size);
    let (prf, mac) = (Mmo::new(keys[0]), Mmo::new(keys[1]));
    let (cws, ms, st) = deal_walk_nu(&prf, roots, n, nu, alpha, us);
    let s = [leaf_seed(st[0]), leaf_seed(st[1])];
    let w_cw = low(prf.h(s[0]) ^ prf.h(s[1]), bits) ^ beta;
    let wm_cw = mac.h(s[0]) ^ mac.h(s[1]) ^ gf128::mul(delta_mac, beta);
    let mk = |party: usize| MalKey { party, n_size, bits, prf: prf.clone(), mac: mac.clone(), root: roots[party], nu, cws: cws.clone(), ms: ms.clone(), w_cw, wm_cw };
    [mk(0), mk(1)]
}

/// Shares of a Π_Verify mask `(r, δr)` in GF(2^128) for a known δ (a dealer's).
pub fn deal_mask<R: RngCore + CryptoRng>(delta_mac: Block, rng: &mut R) -> [VerifyMask<Block>; 2] {
    let (r, r0, d0) = (Block::random(rng), Block::random(rng), Block::random(rng));
    [VerifyMask { r: r0, dr: d0 }, VerifyMask { r: r ^ r0, dr: gf128::mul(delta_mac, r) ^ d0 }]
}

/// Dealer keys from a seed, glue level [`default_nu`], with the δ shares.
pub fn gen_reference(n_size: u64, bits: usize, alpha: u64, beta: Block, seed: [u8; 32]) -> ([MalKey; 2], [Block; 2]) {
    assert!(alpha < n_size);
    let mut rng = ChaCha20Rng::from_seed(seed);
    let n = depth_for(n_size);
    let nu = default_nu(n);
    let roots = [Block::random(&mut rng).with_lsb(false), Block::random(&mut rng).with_lsb(true)];
    let keys = [Block::random(&mut rng).to_bytes(), Block::random(&mut rng).to_bytes()];
    let us: Vec<Block> = (nu..=n).map(|_| Block::random(&mut rng)).collect();
    let d = [Block::random(&mut rng), Block::random(&mut rng)];
    (deal(roots, keys, n_size, nu, bits, alpha, beta, d[0] ^ d[1], &us), d)
}
