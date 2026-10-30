//! Semi-honest dealer-free generation (Figure "DPF.Gen" of the paper) with
//! `F_PRF` = AES–MMO in 2PC on the OT tower ([`OtTower`]).
//!
//! **Setup** (once per session): base OTs and Ferret in both directions,
//! party b's COTs under its Ferret key `Γ_b`. Γ is internal to OT extension:
//! the OT tower runs on party 0's COTs under `Γ_0`, and every other
//! correlation is derived from random COTs; Γ is never the DPF's Δ.
//!
//! **Preprocessing** (input-independent, per Gen; [`precompute`]):
//!
//! * the paper's preprocessing of Figure "DPF.Gen": `⟨α⟩ ← 𝓕_rand({0,1}^n)`,
//!   `⟨Δ⟩ ← 𝓕_rand` with `lsb(Δ) = 1` (party b samples `Δ_b` with
//!   `lsb(Δ_b) = b`), the AES keys `⟨K⟩, ⟨K'⟩ ← 𝓕_rand`, and `⟨α_ℓ·Δ⟩ ←
//!   𝓕_COT(⟨α_ℓ⟩, ⟨Δ⟩)` for every level (`alpha_delta`: in each direction
//!   a COT with the chosen offset `Δ_b`, from Ferret random COTs, one round);
//! * the correlations its functionalities consume: the OT tower's random
//!   COTs ([`COTS_PER_CALL`] per AES–MMO call, [`COTS_PER_KEY`] per key
//!   expansion), n bit-times-block triples for Step C
//!   ([`rot_string_triples`]), and the leaf's daBits and Beaver triple
//!   ([`crate::leaf`]).
//!
//! **Generation**, with `β` additively shared in the payload field `G = F_p`
//! ([`crate::field`]: Babybear in the paper, Goldilocks or `2^127 − 1` for
//! wider payloads; a public β is the sharing `(β, 0)`):
//!
//! 1. Initialization: `st_{0,b} = Δ_b`, so `⟨st_{0,0}⟩ = (Δ_0, 0)` and
//!    `⟨st_{0,1}⟩ = ⟨st_{0,0}⟩ ⊕ ⟨Δ⟩ = (0, Δ_1)`; the key of party b is `Δ_b`.
//! 2. Per level: Step A, two AES–MMO calls `H_K` on `⟨st_{ℓ−1,0}⟩`,
//!    `⟨st_{ℓ−1,0}⟩ ⊕ ⟨Δ⟩` (40 rounds; the level-1 calls also run Π_KeyExp
//!    of every key); Steps B and C in one exchange, carrying the CW share and
//!    the Beaver opening `(α_ℓ ⊕ a, st_{ℓ−1,0} ⊕ B)` of the branch selection;
//!    the new state is local.
//! 3. Leaf: `W_b = H_{K'}(s_{n,b} ∥ 0)` for both b (40 rounds), read in F_p
//!    from their low κ bits; then the paper's leaf ([`arith_leaf`]): B2A of
//!    the 2κ bits by daBits and `W_CW = (1 − 2c)·ρV` with `c = t_{n,0} ⊕ r`,
//!    `ρ = 1 − 2r` for a daBit r and one Beaver triple (three rounds, the
//!    last one also opening K and K').
//!
//! Rounds: `41n + 40 + 3 = 41n + 43`. The output is the key and `⟨α⟩`.

use super::key::ShKey;
use crate::field::Field;
use crate::leaf::{arith_leaf, fp_pre, fp_pre_cots, leaf_dabits, FpPre, Sub};
use crate::{deal_walk, key_bytes, open_keys, sample_keys, SH_KEYS};
use crate::{leaf_seed, sh_calls};
use dpf_common::aes_tower::{bits_of, block_of, mmo_shared, Mmo, OtTower, SharedKey, COTS_PER_CALL, COTS_PER_KEY};
use dpf_common::block::{depth_for, Block};
use dpf_common::bool2pc::rot_string_triples;
use dpf_common::hash::cot_hash;
use dpf_common::net::{Channel, CommStats};
use dpf_common::ot::{CotPair, FerretConfig, RandomCots};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use std::time::{Duration, Instant};

/// Everything one party gets out of [`gen`] (and [`super::bin::gen`]).
pub struct GenOutput<K> {
    pub key: K,
    /// This party's XOR share of the random index α (bit `n − 1 − i` is level
    /// i + 1), sampled in preprocessing.
    pub alpha_share: u64,
    /// Base OTs and the Ferret bootstrap.
    pub setup_stats: CommStats,
    pub pre_stats: CommStats,
    pub gen_stats: CommStats,
    pub setup_time: Duration,
    pub pre_time: Duration,
    pub gen_time: Duration,
    /// ANDs of the AES calls and key expansions.
    pub ands: usize,
    /// COTs consumed after setup (the OT tower's, ⟨α_ℓ·Δ⟩, branch-selection
    /// triples, the leaf's).
    pub cots: usize,
}

/// The preprocessing of one generation.
pub struct Pre {
    /// `⟨α⟩`: this party's share, bit `n − 1 − i` for level i + 1.
    pub alpha_share: u64,
    /// `⟨Δ⟩`: this party's share `Δ_b`, `lsb(Δ_b) = b`.
    pub delta: Block,
    /// `⟨α_ℓ·Δ⟩` for the n levels.
    pub alpha_delta: Vec<Block>,
    /// `⟨K⟩, ⟨K'⟩ (, ⟨K''⟩)`: this party's shares and their sharings.
    pub key_shares: Vec<Block>,
    pub keys: Vec<SharedKey<bool>>,
    /// The OT tower, on its random COTs.
    pub be: OtTower,
    /// `(a, B, a·B)`: n for the branch selections, then any extra ones.
    pub string_triples: Vec<(bool, Block, Block)>,
}

impl Pre {
    /// The bits of α, level 1 first.
    pub(crate) fn alpha_bits(&self) -> Vec<bool> {
        let n = self.alpha_delta.len();
        (0..n).map(|i| (self.alpha_share >> (n - 1 - i)) & 1 == 1).collect()
    }
}

/// `⟨α_ℓ·Δ⟩` for this party's bits `a` and share `Δ_b` (𝓕_COT of the paper):
/// in each direction s, a COT with the chosen offset `Δ_s` from a Ferret
/// random COT `(q, q ⊕ cΓ_s)`, hashed into a random OT `(m_0, m_1)`, `(c,
/// m_c)`. The sender sends `u = m_0 ⊕ m_1 ⊕ Δ_s` and keeps `m_d`, the
/// receiver sends `d = a ⊕ c` and keeps `m_c ⊕ a·u`, so the two differ by
/// `a·Δ_s`. Both directions in one round; the share is `a_b·Δ_b` plus both.
pub(crate) fn alpha_delta<R: rand::RngCore + rand::CryptoRng>(
    ch: &mut Channel,
    cot: &mut CotPair,
    a: &[bool],
    delta: Block,
    rng: &mut R,
) -> Vec<Block> {
    let n = a.len();
    let me = ch.party();
    let gamma = cot.delta();
    let h = |x: Block, i: usize| cot_hash().h(x, (6 << 60) | i as u64);
    let (mut sent, mut recv): (Vec<(Block, Block)>, Vec<(bool, Block)>) = (Vec::new(), Vec::new());
    for s in 0..2 {
        match cot.random_cots(ch, s, n, rng).expect("semi-honest COT") {
            RandomCots::Sender(q) => sent = q.iter().enumerate().map(|(i, &q)| (h(q, i), h(q ^ gamma, i))).collect(),
            RandomCots::Receiver(c, m) => recv = c.iter().zip(&m).enumerate().map(|(i, (&c, &m))| (c, h(m, i))).collect(),
        }
    }
    debug_assert!(sent.len() == n && recv.len() == n && me < 2);
    let mut msg = Vec::with_capacity(17 * n);
    for (&(m0, m1), (&ai, &(c, _))) in sent.iter().zip(a.iter().zip(&recv)) {
        msg.extend_from_slice(&(m0 ^ m1 ^ delta).to_bytes());
        msg.push((ai ^ c) as u8);
    }
    ch.send(msg);
    let theirs = ch.recv();
    assert_eq!(theirs.len(), 17 * n, "malformed 𝓕_COT message");
    (0..n)
        .map(|i| {
            let (u, d) = (Block::from_bytes(&theirs[17 * i..17 * i + 16]), theirs[17 * i + 16] & 1 == 1);
            let (m0, m1) = sent[i];
            let mine = if d { m1 } else { m0 };
            let (_, mc) = recv[i];
            delta.and_bit(a[i]) ^ mine ^ mc ^ u.and_bit(a[i])
        })
        .collect()
}

/// The preprocessing of one Gen of depth n: the paper's (α, Δ, `keys` AES
/// keys, ⟨α_ℓ·Δ⟩) and the OT tower's COTs for `calls` AES–MMO calls and the
/// `keys` key expansions, `strings` bit-times-block triples from Ferret
/// random OTs (n of them for Step C) and `cots` more COTs per direction.
#[allow(clippy::too_many_arguments)]
pub(crate) fn precompute(
    ch: &mut Channel,
    cot: &mut CotPair,
    n: usize,
    calls: usize,
    keys: usize,
    strings: usize,
    cots: usize,
    rng: &mut ChaCha20Rng,
) -> Pre {
    assert!(n >= 1 && strings >= n);
    let b = ch.party();
    let pool = cot.random_cots(ch, 0, calls * COTS_PER_CALL + keys * COTS_PER_KEY, rng).expect("semi-honest COT");
    let be = OtTower::new(b, pool, cot.delta());
    let string_triples = rot_string_triples(ch, cot, strings, rng);
    cot.precompute(ch, n + cots, n + cots, rng).expect("semi-honest COT");
    let alpha_share: u64 = rng.gen::<u64>() & dpf_common::arith::mask(n);
    let delta = Block::random(rng).with_lsb(b == 1);
    let (key_shares, keys) = sample_keys(rng, keys);
    let a: Vec<bool> = (0..n).map(|i| (alpha_share >> (n - 1 - i)) & 1 == 1).collect();
    let alpha_delta = alpha_delta(ch, cot, &a, delta, rng);
    Pre { alpha_share, delta, alpha_delta, key_shares, keys, be, string_triples }
}

/// One party's session state after setup.
pub(crate) struct Setup {
    pub cot: CotPair,
    pub rng: ChaCha20Rng,
    pub stats: CommStats,
    pub time: Duration,
}

/// Base OTs and Ferret, party b's COTs under its Ferret key `Γ_b`.
pub(crate) fn setup(ch: &mut Channel, seed: [u8; 32], ferret: Option<FerretConfig>) -> Setup {
    let t_setup = Instant::now();
    let mut rng = ChaCha20Rng::from_seed(seed);
    let gamma = Block::random(&mut rng);
    let mut cot = CotPair::setup(ch, &mut rng, gamma, false).expect("semi-honest base OT");
    if let Some(cfg) = ferret {
        cot.enable_ferret(ch, cfg, &mut rng).expect("semi-honest Ferret");
    }
    ch.sync();
    Setup { cot, rng, stats: ch.stats(), time: t_setup.elapsed() }
}

/// What [`walk`] leaves: this party's share of `st_{n,0}`, the n level
/// words, and the peer's `extra`.
pub(crate) struct Walk {
    pub st: Block,
    pub cws: Vec<Block>,
    pub reply: Vec<u8>,
}

/// Initialization and the n levels of Figure "DPF.Gen" under `F = H_K` with
/// `pre.keys[0] = ⟨K⟩`; every key in `pre.keys` is expanded during level 1.
/// `extra` rides with the level-1 message and the other party's `extra` (of
/// the same length) is returned. `cw_err = Some((ℓ, ε))` XORs ε into this
/// party's CW share at level ℓ (a deliberate deviation, for the malicious
/// abort tests).
pub(crate) fn walk(pre: &mut Pre, ch: &mut Channel, extra: &[u8], cw_err: Option<(usize, Block)>) -> Walk {
    let b = ch.party();
    let n = pre.alpha_delta.len();
    let delta = pre.delta;
    let a = pre.alpha_bits();
    // Initialization: ⟨st_{0,0}⟩ = (Δ_0, 0).
    let mut st = if b == 0 { delta } else { Block::ZERO };
    let mut cws = Vec::with_capacity(n);
    let mut reply = Vec::new();
    for i in 0..n {
        // Step A: L_0, L_1.
        let l = mmo_shared(&mut pre.be, ch, &mut pre.keys, &[(0, bits_of(st)), (0, bits_of(st ^ delta))]);
        let (l0, l1) = (block_of(&l[0]), block_of(&l[1]));
        // Step B: ⟨CW_ℓ⟩ = ⟨L_0⟩ ⊕ ⟨L_1⟩ ⊕ ⟨Δ⟩ ⊕ ⟨α_ℓ·Δ⟩, opened with Step C's Beaver masks.
        let mut cw_share = l0 ^ l1 ^ delta ^ pre.alpha_delta[i];
        if let Some((lvl, e)) = cw_err {
            if lvl == i {
                cw_share ^= e;
            }
        }
        let (ta, tb, tc) = pre.string_triples[i];
        let (e, f) = (a[i] ^ ta, st ^ tb);
        let x = if i == 0 { extra.len() } else { 0 };
        let mut msg = Vec::with_capacity(33 + x);
        msg.extend_from_slice(&cw_share.to_bytes());
        msg.extend_from_slice(&f.to_bytes());
        msg.push(e as u8);
        msg.extend_from_slice(&extra[..x]);
        ch.send(msg);
        let mut theirs = ch.recv();
        assert_eq!(theirs.len(), 33 + x, "malformed level message");
        if i == 0 {
            reply = theirs.split_off(33);
        }
        let cw = cw_share ^ Block::from_bytes(&theirs[..16]);
        let (f, e) = (f ^ Block::from_bytes(&theirs[16..32]), e ^ (theirs[32] & 1 == 1));
        // Step C: ⟨P_ℓ⟩ = ⟨α_ℓ·st_{ℓ−1,0}⟩ = e·f ⊕ e·B ⊕ f·a ⊕ C, then
        // ⟨st_{ℓ,0}⟩ = ⟨L_0⟩ ⊕ ⟨P_ℓ⟩ ⊕ ⟨t_{ℓ−1,0}⟩·CW_ℓ.
        let prod = f.and_bit(e && b == 0) ^ tb.and_bit(e) ^ f.and_bit(ta) ^ tc;
        st = l0 ^ prod ^ cw.and_bit(st.lsb());
        cws.push(cw);
    }
    Walk { st, cws, reply }
}

fn gen_with<F: Field>(mut pre: Pre, fpre: &mut FpPre<F, F>, ch: &mut Channel, n_size: u64, beta_share: F) -> (ShKey<F>, usize) {
    let b = ch.party();
    let Walk { st, cws, .. } = walk(&mut pre, ch, &[], None);
    let delta = pre.delta;

    // Leaf word, with the key reveal.
    let w = mmo_shared(&mut pre.be, ch, &mut pre.keys, &[(1, bits_of(leaf_seed(st))), (1, bits_of(leaf_seed(st ^ delta)))]);
    let (ws, theirs) = arith_leaf(
        ch,
        &[[vec![block_of(&w[0])], vec![block_of(&w[1])]]],
        &[1],
        &[Sub::Share(beta_share)],
        st.lsb(),
        fpre,
        &[F::ZERO],
        &key_bytes(&pre.key_shares),
    );
    let mut prf = open_keys(&pre.key_shares, &theirs).into_iter();
    let (prf, pay) = (prf.next().unwrap(), prf.next().unwrap());
    (ShKey { party: b, n_size, prf, pay, root: delta, cws, w_cw: ws[0] }, pre.be.ands)
}

/// Runs this party's side of setup, preprocessing and generation of a key for
/// a random index α (its share is in the output) and payload β.
///
/// * `beta_share`: additive share of `β ∈ F_p`.
/// * `ferret`: the silent-OT parameters (`Some(FerretConfig::B13)` for
///   benchmarks); `None` keeps IKNP, for tests.
pub fn gen<F: Field>(ch: &mut Channel, n_size: u64, beta_share: F, seed: [u8; 32], ferret: Option<FerretConfig>) -> GenOutput<ShKey<F>> {
    let n = depth_for(n_size);
    let (dabits, triples) = (leaf_dabits::<F>(&[1]), 1);
    drive(
        ch,
        seed,
        ferret,
        n,
        fp_pre_cots::<F, F>(dabits, triples),
        |cot, rng, ch| fp_pre::<F, F, _>(ch, cot, dabits, triples, &[], rng),
        |pre, mut fpre, ch| gen_with(pre, &mut fpre, ch, n_size, beta_share),
    )
}

/// Setup, then preprocessing ([`precompute`] for [`sh_calls`]`(n)` AES–MMO
/// calls, two keys, n string triples and `cots` COTs per direction, then
/// `extra`), then `body`, the generation proper, each phase timed and counted
/// on its own.
pub(crate) fn drive<K, P>(
    ch: &mut Channel,
    seed: [u8; 32],
    ferret: Option<FerretConfig>,
    n: usize,
    cots: usize,
    extra: impl FnOnce(&mut CotPair, &mut ChaCha20Rng, &mut Channel) -> P,
    body: impl FnOnce(Pre, P, &mut Channel) -> (K, usize),
) -> GenOutput<K> {
    let Setup { mut cot, mut rng, stats: setup_stats, time: setup_time } = setup(ch, seed, ferret);
    let cots_before = cot.produced;

    let t_pre = Instant::now();
    let pre = precompute(ch, &mut cot, n, sh_calls(n), SH_KEYS, n, cots, &mut rng);
    let alpha_share = pre.alpha_share;
    let more = extra(&mut cot, &mut rng, ch);
    let pre_stats = ch.stats().since(&setup_stats);
    let pre_time = t_pre.elapsed();
    // Timing only: neither party's gen time includes waiting for the other's
    // preprocessing. Counted in no phase.
    ch.sync();
    let gen_start = ch.stats();
    let t_gen = Instant::now();
    let (key, ands) = body(pre, more, ch);
    GenOutput {
        key,
        alpha_share,
        gen_stats: ch.stats().since(&gen_start),
        setup_stats,
        pre_stats,
        setup_time,
        pre_time,
        gen_time: t_gen.elapsed(),
        ands,
        cots: cot.produced - cots_before,
    }
}

/// Trusted-dealer generation for given roots (`lsb(root_b) = b`, the root
/// share `Δ_b`) and AES keys `[K, K']`: the cleartext Gen, and the bit-exact
/// oracle of [`gen`]. `α < 2^n` (n = [`depth_for`]`(n_size)`).
pub fn deal<F: Field>(roots: [Block; 2], keys: [[u8; 16]; SH_KEYS], n_size: u64, alpha: u64, beta: F) -> [ShKey<F>; 2] {
    let (prf, pay) = (Mmo::new(keys[0]), Mmo::new(keys[1]));
    let (cws, st) = deal_walk(&prf, roots, depth_for(n_size), alpha);
    let w = |s: Block| F::from_block(pay.h(leaf_seed(s)));
    let v = w(st[0]).sub(w(st[1])).sub(beta);
    let w_cw = if st[0].lsb() { v.neg() } else { v };
    let mk = |party: usize| ShKey { party, n_size, prf: prf.clone(), pay: pay.clone(), root: roots[party], cws: cws.clone(), w_cw };
    [mk(0), mk(1)]
}

/// Trusted-dealer generation from a seed.
pub fn gen_reference<F: Field>(n_size: u64, alpha: u64, beta: F, seed: [u8; 32]) -> [ShKey<F>; 2] {
    assert!(alpha < n_size);
    let mut rng = ChaCha20Rng::from_seed(seed);
    let roots = [Block::random(&mut rng).with_lsb(false), Block::random(&mut rng).with_lsb(true)];
    let keys: [[u8; 16]; SH_KEYS] = std::array::from_fn(|_| Block::random(&mut rng).to_bytes());
    deal(roots, keys, n_size, alpha, beta)
}
