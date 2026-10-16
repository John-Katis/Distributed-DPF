//! Duoram's DPF generation: preprocessing at a random target, then the
//! online adjustment to the real (α, β).
//!
//! **Preprocessing** (Protocol 1/2 lines 1–4, `create_dpfs` and
//! `convert_shares` of the reference), for party b ∈ {0, 1}:
//!
//! 1. Pick XOR shares of a random target `r` (`generate_random_targets`) and a
//!    root with flag b.
//! 2. Per level (Duoram App. C, i.e. Doerner–shelat): expand every node, XOR
//!    all left children to `L_b` and all right ones to `R_b`, and open
//!    `CW = r_i ? L : R` (with lsb 0) with compute_CW together with
//!    `cwt_L = lsb(L) ⊕ r_i ⊕ 1` and `cwt_R = lsb(R) ⊕ r_i`.
//! 3. Deferred final CW: `Γ_b = (−1)^b Σ lane0(leaves)`, so
//!    `Γ_0 + Γ_1 = v_0[r] + v_1[r]` (reference: `Gamma[0]`).
//! 4. Flags to additive shares (App. D, as `convert_shares`): `pm_b =
//!    (−1)^b Σ t_b` (so `pm = ±1`), lane 1 of the same leaves as the second
//!    DPF (`Γ'_b`, reference `Gamma[1]`), one Du–Atallah product for `Γ'·pm`,
//!    and one round opening `c = pm + ρ` and `F̄ = Γ'·pm + ρ`.
//! 5. `xor_to_additive`: additive shares `R_b` of r from the bit products
//!    `r_{0,j}·r_{1,j}` (`r_j = r_{0,j} + r_{1,j} − 2r_{0,j}r_{1,j}`). Steps 4
//!    and 5 share one batch of products.
//!
//! **Online** (Protocol 2 lines 5–7, one round): open `S = α − r mod 2^n`
//! and `F = β − (Γ_0 + Γ_1)`.
//!
//! Every ring value (lanes, products, opened words) is a word of the type `R`,
//! the reference's `value_t`: `u64` for an output ring of up to 64 bits,
//! `u128` for up to 128 bits ([`Lanes`]).

use crate::du_atallah::{compute_cw, deal as p2_deal, receive_dealt, Helper};
use crate::key::DuoramKey;
use crate::tree::{CorrectionWord, DuoramTree, Lanes, StoredTree, StreamTree};
use dpf_common::arith::{mask, Ring};
use dpf_common::block::{depth_for, Block};
use dpf_common::net::{Channel, CommStats, Peers};
use dpf_common::ot::CotPair;
use dpf_common::stream::TreeMode;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use std::time::{Duration, Instant};

/// Everything one of P0, P1 gets out of a generation.
pub struct GenOutput<R: Lanes = u64> {
    pub key: DuoramKey<R>,
    pub setup_stats: CommStats,
    /// Preprocessing traffic of this party (all its links).
    pub pre_stats: CommStats,
    /// Online traffic of this party.
    pub online_stats: CommStats,
    /// Bytes received from the helper P2 (3P only).
    pub helper_bytes: usize,
    /// COTs (2P only, both directions).
    pub cots: usize,
    pub setup_time: Duration,
    pub pre_time: Duration,
    pub online_time: Duration,
}

/// The state preprocessing leaves behind, before α and β are known.
pub struct Preprocessed<R: Lanes = u64> {
    party: usize,
    n_size: u64,
    root: Block,
    cws: Vec<CorrectionWord>,
    c: R,
    fbar: R,
    /// `Γ_b`.
    gamma: R,
    /// Additive share of r mod 2^n.
    r_share: u64,
}

/// Correlations one party needs: `n` AND triples and `n + 2` products.
pub fn counts(n_size: u64) -> (usize, usize) {
    let n = depth_for(n_size);
    (n, n + 2)
}

fn signed<R: Ring>(party: usize, x: R) -> R {
    if party == 1 {
        x.neg()
    } else {
        x
    }
}

/// Opens additively shared words.
fn exchange<R: Ring>(ch: &mut Channel, mine: &[R]) -> Vec<R> {
    let mut msg = Vec::with_capacity(R::BYTES * mine.len());
    mine.iter().for_each(|v| v.put(&mut msg));
    ch.send(msg);
    let got = ch.recv();
    assert_eq!(got.len(), R::BYTES * mine.len(), "unexpected message length");
    got.chunks(R::BYTES).zip(mine).map(|(c, v)| v.add(R::get(c))).collect()
}

/// Steps 1–5 for this party, over the link to the other party.
pub fn preprocess<R: Lanes>(ch: &mut Channel, helper: &mut Helper<R>, n_size: u64, rng: &mut ChaCha20Rng) -> Preprocessed<R> {
    preprocess_mode(ch, helper, n_size, rng, TreeMode::Stored)
}

/// [`preprocess`] with the tree held as `mode` says. Both modes send the same
/// messages.
pub fn preprocess_mode<R: Lanes>(ch: &mut Channel, helper: &mut Helper<R>, n_size: u64, rng: &mut ChaCha20Rng, mode: TreeMode) -> Preprocessed<R> {
    match mode {
        TreeMode::Stored => preprocess_with::<StoredTree, R>(ch, helper, n_size, rng, mode),
        TreeMode::Stream { .. } => preprocess_with::<StreamTree, R>(ch, helper, n_size, rng, mode),
    }
}

fn preprocess_with<T: DuoramTree, R: Lanes>(ch: &mut Channel, helper: &mut Helper<R>, n_size: u64, rng: &mut ChaCha20Rng, mode: TreeMode) -> Preprocessed<R> {
    let b = ch.party();
    let n = depth_for(n_size);
    let r_bits = rng.gen::<u64>() & mask(n);
    let corr = helper.cw_corr(ch, n, rng);

    // Steps 1–2.
    let root = Block((rng.gen::<u128>() & !1) | b as u128);
    let mut tree = T::new(root, mode);
    let mut cws = Vec::with_capacity(n);
    for (i, cr) in corr.iter().enumerate() {
        let (l, r) = tree.level_sums();
        let c = (r_bits >> (n - 1 - i)) & 1 == 1;
        let one = b == 1;
        // The CW is opened without its lsb, the flag bit: lsb(CW) would equal
        // the off-path flag CW and so reveal r_i whenever the two differ.
        let (s, t) = compute_cw(ch, cr, l.with_lsb(false), r.with_lsb(false), c, [l.lsb() ^ c ^ one, r.lsb() ^ c]);
        let cw = CorrectionWord { s, t };
        tree.correct(cw);
        cws.push(cw);
    }

    // Steps 3–4: sums over the leaves.
    let (gamma, gamma2, pm) = tree.leaf_sums::<R>();
    let (gamma, gamma2, pm) = (signed(b, gamma), signed(b, gamma2), signed(b, pm));

    // Steps 4–5: one batch of products. Party 0 supplies the left operands.
    let mut mine: Vec<R> = (0..n).map(|j| R::from_u64((r_bits >> j) & 1)).collect();
    mine.extend(if b == 0 { [gamma2, pm] } else { [pm, gamma2] });
    let mut ybits = vec![1; n];
    ybits.extend([R::BITS, R::BITS]);
    let prod = helper.cross(ch, &mine, &ybits, rng);
    let r_share = (0..n).fold(R::ZERO, |acc, j| {
        let d = mine[j].sub(prod[j].mul(R::from_u64(2)));
        acc.add(d.shl(j))
    });
    let r_share = r_share.low_u64() & mask(n);
    let phi = gamma2.mul(pm).add(prod[n]).add(prod[n + 1]);
    let rho = R::random(rng);
    let opened = exchange(ch, &[pm.add(rho), phi.add(rho)]);

    Preprocessed { party: b, n_size, root, cws, c: opened[0], fbar: opened[1], gamma, r_share }
}

/// The online phase: one round.
///
/// * `alpha_share`: additive share of `α < N` mod `2^n`.
/// * `beta_share`: additive share of `β` mod `2^bits`.
pub fn online<R: Lanes>(ch: &mut Channel, pre: Preprocessed<R>, bits: usize, alpha_share: u64, beta_share: R) -> DuoramKey<R> {
    let n = depth_for(pre.n_size);
    let o = exchange(ch, &[R::from_u64(alpha_share.wrapping_sub(pre.r_share)), beta_share.sub(pre.gamma)]);
    DuoramKey {
        party: pre.party,
        n_size: pre.n_size,
        bits,
        root: pre.root,
        cws: pre.cws,
        c: pre.c,
        fbar: pre.fbar,
        shift: o[0].low_u64() & mask(n),
        f: o[1],
    }
}

fn finish<R: Lanes>(
    ch: &mut Channel,
    pre_fn: impl FnOnce(&mut Channel) -> Preprocessed<R>,
    stats: impl Fn(&Channel) -> CommStats,
    bits: usize,
    alpha_share: u64,
    beta_share: R,
) -> (DuoramKey<R>, CommStats, CommStats, Duration, Duration) {
    let s0 = stats(ch);
    let t0 = Instant::now();
    let pre = pre_fn(ch);
    let pre_time = t0.elapsed();
    let s1 = stats(ch);
    let t1 = Instant::now();
    let key = online(ch, pre, bits, alpha_share, beta_share);
    (key, s1.since(&s0), stats(ch).since(&s1), pre_time, t1.elapsed())
}

/// 2P-Duoram: P0 and P1 alone, correlations from IKNP OT.
pub fn gen_2p<R: Lanes>(ch: &mut Channel, n_size: u64, bits: usize, alpha_share: u64, beta_share: R, seed: [u8; 32]) -> GenOutput<R> {
    gen_2p_mode(ch, n_size, bits, alpha_share, beta_share, seed, TreeMode::Stored)
}

/// [`gen_2p`] with the tree held as `mode` says.
pub fn gen_2p_mode<R: Lanes>(ch: &mut Channel, n_size: u64, bits: usize, alpha_share: u64, beta_share: R, seed: [u8; 32], mode: TreeMode) -> GenOutput<R> {
    assert!((1..=R::BITS).contains(&bits), "output ring must be 1..={} bits", R::BITS);
    let t_setup = Instant::now();
    let mut rng = ChaCha20Rng::from_seed(seed);
    let delta = Block::random(&mut rng);
    let mut cot = CotPair::setup(ch, &mut rng, delta, false).expect("semi-honest base OT");
    ch.sync();
    let setup_stats = ch.stats();
    let setup_time = t_setup.elapsed();
    let (key, pre_stats, online_stats, pre_time, online_time) = finish(
        ch,
        |ch| preprocess_mode(ch, &mut Helper::Ot(&mut cot), n_size, &mut rng, mode),
        |ch| ch.stats(),
        bits,
        alpha_share,
        beta_share,
    );
    GenOutput { key, setup_stats, pre_stats, online_stats, helper_bytes: 0, cots: cot.produced, setup_time, pre_time, online_time }
}

/// 3P-Duoram, party P0 or P1: correlations dealt by P2. P2's link is only
/// used for its one message (`helper_bytes`); `pre_stats` is the P0–P1 link.
pub fn gen_3p<R: Lanes>(peers: &mut Peers, n_size: u64, bits: usize, alpha_share: u64, beta_share: R, seed: [u8; 32]) -> GenOutput<R> {
    gen_3p_mode(peers, n_size, bits, alpha_share, beta_share, seed, TreeMode::Stored)
}

/// [`gen_3p`] with the tree held as `mode` says.
pub fn gen_3p_mode<R: Lanes>(peers: &mut Peers, n_size: u64, bits: usize, alpha_share: u64, beta_share: R, seed: [u8; 32], mode: TreeMode) -> GenOutput<R> {
    assert!((1..=R::BITS).contains(&bits), "output ring must be 1..={} bits", R::BITS);
    let b = peers.party();
    assert!(b < 2, "P2 runs gen_3p_helper");
    let mut rng = ChaCha20Rng::from_seed(seed);
    let (levels, crosses) = counts(n_size);
    let t0 = Instant::now();
    let mut helper = receive_dealt::<R>(peers.to(2), levels, crosses);
    let from_p2 = peers.stats_with(2);
    let recv_time = t0.elapsed();
    let (key, pre_stats, online_stats, pre_time, online_time) = finish(
        peers.to(1 - b),
        |ch| preprocess_mode(ch, &mut helper, n_size, &mut rng, mode),
        |ch| ch.stats(),
        bits,
        alpha_share,
        beta_share,
    );
    GenOutput {
        key,
        setup_stats: CommStats::default(),
        pre_stats,
        online_stats,
        helper_bytes: from_p2.bytes_recv,
        cots: 0,
        setup_time: Duration::ZERO,
        pre_time: pre_time + recv_time,
        online_time,
    }
}

/// 3P-Duoram, the helper P2: deals the correlations (products over the word
/// type `R`) and is done.
pub fn gen_3p_helper<R: Lanes>(peers: &mut Peers, n_size: u64, seed: [u8; 32]) -> CommStats {
    let (levels, crosses) = counts(n_size);
    p2_deal::<R, _>(peers, levels, crosses, &mut ChaCha20Rng::from_seed(seed));
    peers.stats()
}

/// Trusted-dealer generation with the same roots, target and blind `ρ`: the
/// cleartext version of preprocessing plus online phase.
pub fn deal<R: Lanes>(roots: [Block; 2], n_size: u64, bits: usize, alpha: u64, beta: R, r: u64, rho: R) -> [DuoramKey<R>; 2] {
    deal_mode(roots, n_size, bits, alpha, beta, r, rho, TreeMode::Stored)
}

/// [`deal`] with the tree held as `mode` says.
#[allow(clippy::too_many_arguments)]
pub fn deal_mode<R: Lanes>(roots: [Block; 2], n_size: u64, bits: usize, alpha: u64, beta: R, r: u64, rho: R, mode: TreeMode) -> [DuoramKey<R>; 2] {
    match mode {
        TreeMode::Stored => deal_with::<StoredTree, R>(roots, n_size, bits, alpha, beta, r, rho, mode),
        TreeMode::Stream { .. } => deal_with::<StreamTree, R>(roots, n_size, bits, alpha, beta, r, rho, mode),
    }
}

#[allow(clippy::too_many_arguments)]
fn deal_with<T: DuoramTree, R: Lanes>(roots: [Block; 2], n_size: u64, bits: usize, alpha: u64, beta: R, r: u64, rho: R, mode: TreeMode) -> [DuoramKey<R>; 2] {
    assert!(alpha < n_size);
    assert!(!roots[0].lsb() && roots[1].lsb(), "the root of party b has flag b");
    let n = depth_for(n_size);
    assert!(r <= mask(n));
    let mut trees = [T::new(roots[0], mode), T::new(roots[1], mode)];
    let mut cws = Vec::with_capacity(n);
    for i in 0..n {
        let (l0, r0) = trees[0].level_sums();
        let (l1, r1) = trees[1].level_sums();
        let (l, rr) = (l0 ^ l1, r0 ^ r1);
        let c = (r >> (n - 1 - i)) & 1 == 1;
        let cw = CorrectionWord { s: if c { l } else { rr }.with_lsb(false), t: [l.lsb() ^ c ^ true, rr.lsb() ^ c] };
        for t in &mut trees {
            t.correct(cw);
        }
        cws.push(cw);
    }
    let (s0, s1) = (trees[0].leaf_sums::<R>(), trees[1].leaf_sums::<R>());
    let gamma = signed(0, s0.0).add(signed(1, s1.0));
    let gamma2 = signed(0, s0.1).add(signed(1, s1.1));
    let pm = signed(0, s0.2).add(signed(1, s1.2));
    assert!(pm == R::ONE || pm == R::ONE.neg(), "pm = ±1");
    let mk = |party: usize| DuoramKey {
        party,
        n_size,
        bits,
        root: roots[party],
        cws: cws.clone(),
        c: pm.add(rho),
        fbar: gamma2.mul(pm).add(rho),
        shift: alpha.wrapping_sub(r) & mask(n),
        f: beta.sub(gamma),
    };
    [mk(0), mk(1)]
}

/// Trusted-dealer keys from a seed.
pub fn gen_reference<R: Lanes>(n_size: u64, bits: usize, alpha: u64, beta: R, seed: [u8; 32]) -> [DuoramKey<R>; 2] {
    gen_reference_mode(n_size, bits, alpha, beta, seed, TreeMode::Stored)
}

/// [`gen_reference`] with the tree held as `mode` says.
pub fn gen_reference_mode<R: Lanes>(n_size: u64, bits: usize, alpha: u64, beta: R, seed: [u8; 32], mode: TreeMode) -> [DuoramKey<R>; 2] {
    let mut rng = ChaCha20Rng::from_seed(seed);
    let roots = [Block(rng.gen::<u128>() & !1), Block(rng.gen::<u128>() | 1)];
    let r = rng.gen::<u64>() & mask(depth_for(n_size));
    let rho = R::random(&mut rng);
    deal_mode(roots, n_size, bits, alpha, beta, r, rho, mode)
}
