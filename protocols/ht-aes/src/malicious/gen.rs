//! Malicious generation with abort: the Gen of [`crate::semi_honest::gen`]
//! (top phase of ν levels, switch, level-independent lower levels joined by
//! `M_ℓ`) on the same preprocessing, extended as in the paper's
//! "Authenticated generation" and its revision for public keys:
//!
//! 0. Fresh public keys per Gen and per level, `K_1, …, K_n` (`K_ℓ` expands
//!    level ℓ − 1), and `K_pay`, `K_mac` for the leaf masks: with one public
//!    K a malicious party could steer the shared state back to an earlier
//!    one, so that one hash masks two correction words.
//! 1. A persistent payload-MAC key `δ = δ_0 ⊕ δ_1 ∈ GF(2^128)`, sampled once
//!    per session and never opened.
//! 2. The masks `F^pay = H_{K_pay}(· ∥ 0)` and `F^mac = H_{K_mac}(· ∥ 0)` on
//!    the two on-path leaf states `Y`, `Y ⊕ Δ`, in the batch of the lower
//!    levels' AES–MMO calls.
//! 3. `⟨δ·β⟩ = Σ_i β_i·⟨X^i δ⟩`: ℓ bit-times-block Beaver products, one round
//!    concurrent with everything else. The Π_Verify mask `(⟨r⟩, ⟨δr⟩)` for a
//!    fresh random r, input-independent, is 128 more in preprocessing.
//! 4. `W_CW = h_pay^(0) ⊕ h_pay^(1) ⊕ β` and `W^MAC_CW = h_mac^(0) ⊕ h_mac^(1)
//!    ⊕ δβ`, opened together after the AES–MMO calls (in a binary payload
//!    group the sign `(−1)^{t_{n,0}}` is 1, so the tag order does not matter).
//!
//! Every deviation in Gen, in the PRF products, the switch, the branch
//! selection or an opening, shows up only in the published key material,
//! which Π_Verify ([`super::verify`]) checks at evaluation time
//! (Propositions "One-Hot" and "MAC Detection" of the paper).
//!
//! Rounds: `max(ν + 3, 42)` for ν < n, `max(n + 3, 41)` for ν = n.

use super::key::{low, MalKey};
use crate::malicious_arith::VerifyMask;
use crate::semi_honest::gen::{bit_times_block, precompute, setup, walk, walk_strings, Pre, Setup, Walk};
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

/// Deliberate deviation for the abort tests: XOR `err` into this party's
/// share of the word opened at `level` (`< n`: `CW_{level+1}`, `n`: the
/// payload word, `n + 1`: the payload-MAC word, `n + 2`: `M_ν`) before
/// opening it.
#[derive(Clone, Copy, Debug)]
pub struct Fault {
    pub level: usize,
    pub err: Block,
}

/// The preprocessing of one malicious Gen: the semi-honest one with per-level
/// keys, `K_pay`, `K_mac` and ℓ more string triples (δ·β), and the key's
/// Π_Verify mask.
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
    /// The semi-honest setup (base OTs, Ferret) and δ_b.
    pub fn setup(ch: &mut Channel, seed: [u8; 32], ferret: Option<FerretConfig>) -> Self {
        let mut s = setup(ch, seed, ferret);
        let delta_mac = Block::random(&mut s.rng);
        MalSession { s, delta_mac }
    }

    /// The preprocessing of one Gen of depth n with switch level ν
    /// (`semi_honest::gen::precompute` for [`mal_calls`] AES–MMO calls, keys
    /// `K_1, …, K_n, K_pay, K_mac`, and ℓ + 128 more string triples), and the
    /// Π_Verify mask: a random r and `⟨δr⟩ = Σ_i r_i·⟨X^i δ⟩` from the last
    /// 128 triples, one round.
    pub fn precompute(&mut self, ch: &mut Channel, n: usize, nu: usize, bits: usize) -> MalPre {
        let s = &mut self.s;
        let mut pre = precompute(ch, &mut s.cot, n, nu, mal_calls(n, nu), true, 2, bits + 128, 0, &mut s.rng);
        let at = pre.string_triples.len() - 128;
        let mut mt = pre.string_triples.split_off(at);
        let r = Block::random(&mut s.rng);
        let sel: Vec<(bool, Block)> = (0..128).map(|i| (r.bit(i), gf128::mul(Block(1 << i), self.delta_mac))).collect();
        let mut lane = ch.lane();
        let dr = bit_times_block(ch, &mut lane, &sel, &mut mt.drain(..)).into_iter().fold(Block::ZERO, |a, x| a ^ x);
        ch.join(lane);
        MalPre { pre, mask: VerifyMask { r, dr } }
    }

    /// One generation of a key for the random α of `pre` and `β ∈ {0,1}^ℓ`
    /// (XOR shares). Returns the key, the ANDs, the key's Π_Verify mask and
    /// this party's share of α.
    pub fn gen(&mut self, ch: &mut Channel, n_size: u64, bits: usize, beta_share: Block, pre: MalPre, fault: Option<Fault>) -> (MalKey, usize, VerifyMask<Block>, u64) {
        let b = ch.party();
        let n = depth_for(n_size);
        let err = |lvl: usize| match fault {
            Some(f) if f.level == lvl => f.err,
            _ => Block::ZERO,
        };
        let MalPre { mut pre, mask } = pre;
        assert_eq!(pre.alpha_delta.len(), n, "preprocessing for depth n");
        let mut dm = pre.string_triples.split_off(walk_strings(n, pre.nu));

        // 3. ⟨δβ⟩, on its own lane.
        let sel: Vec<(bool, Block)> = (0..bits).map(|i| (beta_share.bit(i), gf128::mul(Block(1 << i), self.delta_mac))).collect();
        let mut lane = ch.lane();
        let db = bit_times_block(ch, &mut lane, &sel, &mut dm.drain(..)).into_iter().fold(Block::ZERO, |a, x| a ^ x);

        // The Gen, with F^pay and F^mac on the leaf states Y, Y ⊕ Δ (2).
        let (kp, km) = (pre.extra_key(0), pre.extra_key(1));
        let (s0, s1) = (leaf_seed(pre.y), leaf_seed(pre.y ^ pre.delta));
        let walk_err = fault.and_then(|f| match f.level {
            l if l < n => Some((l, f.err)),
            l if l == n + 2 => Some((n, f.err)),
            _ => None,
        });
        let Walk { cws, ms, leaf: w, mut leaf_lane } = walk(&mut pre, ch, &[(kp, s0), (kp, s1), (km, s0), (km, s1)], walk_err);

        // 4. The leaf words.
        let w_share = low(w[0] ^ w[1], bits) ^ beta_share ^ low(err(n), bits);
        let wm_share = w[2] ^ w[3] ^ db ^ err(n + 1);
        let mut msg = w_share.to_bytes().to_vec();
        msg.extend_from_slice(&wm_share.to_bytes());
        let theirs = ch.exchange_on(&mut leaf_lane, msg);
        assert_eq!(theirs.len(), 32, "malformed payload words");
        ch.join(leaf_lane);
        ch.join(lane);
        let w_cw = w_share ^ Block::from_bytes(&theirs[..16]);
        let wm_cw = wm_share ^ Block::from_bytes(&theirs[16..]);
        let prf = pre.level_keys();
        let (pay, mac) = (pre.keys[kp].clone(), pre.keys[km].clone());
        let key = MalKey { party: b, n_size, bits, prf, pay, mac, root: pre.delta, nu: pre.nu, cws, ms, w_cw: low(w_cw, bits), wm_cw };
        (key, pre.be.ands, mask, pre.alpha_share)
    }
}

/// Everything one party gets from [`run_mal`].
pub struct MalRun {
    pub key: MalKey,
    /// This party's XOR share of the random index α.
    pub alpha_share: u64,
    /// This party's XOR shares of the on-path states `U_ν, …, U_n` of party 0.
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
    /// COTs consumed after setup (the OT tower's, ⟨α_ℓ·Δ⟩, string triples).
    pub cots: usize,
}

/// Setup, preprocessing and generation for one party, switch level `nu`
/// ([`default_nu`] if `None`).
#[allow(clippy::too_many_arguments)]
pub fn run_mal(
    ch: &mut Channel,
    n_size: u64,
    nu: Option<usize>,
    bits: usize,
    beta_share: Block,
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
    let pre = s.precompute(ch, n, nu.unwrap_or(default_nu(n)), bits);
    let onpath_share = pre.pre.us.clone();
    let pre_stats = ch.stats().since(&setup_stats);
    let pre_time = t_pre.elapsed();
    // Timing only: counted in no phase.
    ch.sync();
    let before = ch.stats();
    let t = Instant::now();
    let (key, ands, mask, alpha_share) = s.gen(ch, n_size, bits, beta_share, pre, fault);
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

/// Trusted-dealer generation for given roots (`lsb(root_b) = b`), AES keys
/// `[K_1, …, K_n, K_pay, K_mac]`, switch level ν, on-path states `us = [U_ν,
/// …, U_n]` of party 0 and payload-MAC key δ: the cleartext Gen and the
/// oracle of [`MalSession::gen`].
#[allow(clippy::too_many_arguments)]
pub fn deal(roots: [Block; 2], keys: &[[u8; 16]], n_size: u64, nu: usize, bits: usize, alpha: u64, beta: Block, delta_mac: Block, us: &[Block]) -> [MalKey; 2] {
    assert_eq!(beta, low(beta, bits), "β must fit in the output width");
    let n = depth_for(n_size);
    assert_eq!(keys.len(), n + 2, "K_1, …, K_n, K_pay, K_mac");
    let mut prf: Vec<Mmo> = keys.iter().map(|&k| Mmo::new(k)).collect();
    let mac = prf.pop().unwrap();
    let pay = prf.pop().unwrap();
    let (cws, ms, st) = deal_walk_nu(&prf, roots, n, nu, alpha, us);
    let s = [leaf_seed(st[0]), leaf_seed(st[1])];
    let w_cw = low(pay.h(s[0]) ^ pay.h(s[1]), bits) ^ beta;
    let wm_cw = mac.h(s[0]) ^ mac.h(s[1]) ^ gf128::mul(delta_mac, beta);
    let mk = |party: usize| MalKey {
        party,
        n_size,
        bits,
        prf: prf.clone(),
        pay: pay.clone(),
        mac: mac.clone(),
        root: roots[party],
        nu,
        cws: cws.clone(),
        ms: ms.clone(),
        w_cw,
        wm_cw,
    };
    [mk(0), mk(1)]
}

/// Shares of a Π_Verify mask `(r, δr)` in GF(2^128) for a known δ (a dealer's).
pub fn deal_mask<R: RngCore + CryptoRng>(delta_mac: Block, rng: &mut R) -> [VerifyMask<Block>; 2] {
    let (r, r0, d0) = (Block::random(rng), Block::random(rng), Block::random(rng));
    [VerifyMask { r: r0, dr: d0 }, VerifyMask { r: r ^ r0, dr: gf128::mul(delta_mac, r) ^ d0 }]
}

/// Dealer keys from a seed, switch level [`default_nu`], with the δ shares.
pub fn gen_reference(n_size: u64, bits: usize, alpha: u64, beta: Block, seed: [u8; 32]) -> ([MalKey; 2], [Block; 2]) {
    assert!(alpha < n_size);
    let mut rng = ChaCha20Rng::from_seed(seed);
    let n = depth_for(n_size);
    let nu = default_nu(n);
    let roots = [Block::random(&mut rng).with_lsb(false), Block::random(&mut rng).with_lsb(true)];
    let keys: Vec<[u8; 16]> = (0..n + 2).map(|_| Block::random(&mut rng).to_bytes()).collect();
    let us: Vec<Block> = (nu..=n).map(|_| Block::random(&mut rng)).collect();
    let d = [Block::random(&mut rng), Block::random(&mut rng)];
    (deal(roots, &keys, n_size, nu, bits, alpha, beta, d[0] ^ d[1], &us), d)
}
