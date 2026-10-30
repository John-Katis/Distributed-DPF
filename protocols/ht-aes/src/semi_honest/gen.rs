//! Semi-honest dealer-free generation (Figure "DPF.Gen" of the paper) with
//! `F_PRF` = AES–MMO in 2PC on the OT tower ([`OtTower`]).
//!
//! **Setup** (once per session): each party picks `Δ_b` with `lsb(Δ_b) = b`
//! and runs the base OTs of a COT instance keyed by `Δ_b` in each direction,
//! then bootstraps Ferret on it.
//!
//! **Preprocessing** (before α and β are known): the OT tower's random Ferret
//! COTs ([`COTS_PER_CALL`] per AES–MMO call, party 0 the sender), n
//! bit-times-block triples for the branch selection from Ferret random OTs
//! ([`rot_string_triples`]), Ferret COTs for the n α-bits, and the leaf's
//! 2κ + 1 daBits and one Beaver triple over F_p ([`crate::leaf`]).
//!
//! **Generation**, with `α` XOR-shared (bit `n − 1 − i` is level i + 1) and
//! `β` additively shared in `G = F_p` ([`crate::field`]):
//!
//! 0. Fresh XOR-shared AES keys K (state) and K' (payload), `𝓕_rand`; their
//!    round keys are expanded on shares (Π_KeyExp, 40 S-boxes each) in the
//!    rounds of the level-1 calls, and both are opened with the last message.
//!
//! 1. `⟨α_ℓ·Δ⟩` for all levels from the derandomised COTs (one round):
//!    `α_{ℓ,b}·Δ_b ⊕ M_b[α_{ℓ,b}] ⊕ K_b[α_{ℓ,1−b}]`.
//! 2. A fresh root per Gen: party 0 samples `R` (lsb 0) as `st_{0,0}` and
//!    sends `R ⊕ Δ_0` with the level-1 message, party 1 sets
//!    `st_{0,1} = R ⊕ Δ_0 ⊕ Δ_1`; `⟨st_{0,0}⟩ = (R, 0)`, `⟨Δ⟩ = (Δ_0, Δ_1)`.
//!    Δ is the session's COT key, so roots `Δ_b` would repeat across Gens and
//!    two keys would reveal Δ (hence α) by `CW_ℓ ⊕ CW'_ℓ`.
//! 3. Per level: two AES–MMO calls `H_K` on `⟨st_{ℓ−1,0}⟩`, `⟨st_{ℓ−1,0}⟩ ⊕
//!    ⟨Δ⟩` (40 rounds), then one exchange carrying the CW share and the Beaver opening
//!    `(α_ℓ ⊕ a, st_{ℓ−1,0} ⊕ B)` of the branch selection; the new state is
//!    local.
//! 4. Leaf: `W_b = H_{K'}(s_{n,b} ∥ 0)` for both b (40 rounds), read in F_p
//!    from their low κ bits; then the paper's leaf ([`arith_leaf`]): B2A of
//!    the 2κ bits by daBits and `W_CW = (1 − 2c)·ρV` with `c = t_{n,0} ⊕ r`,
//!    `ρ = 1 − 2r` for a daBit r and one Beaver triple (three rounds, the
//!    last one also opening K and K').
//!
//! Rounds: `1 + 41n + 40 + 3 = 41n + 44`.

use super::key::ShKey;
use crate::field::Field;
use crate::leaf::{arith_leaf, fp_pre, fp_pre_cots, leaf_dabits, FpPre, Sub};
use crate::{deal_walk, key_bytes, open_keys, sample_keys, SH_KEYS};
use crate::{leaf_seed, sh_calls};
use dpf_common::aes_tower::{bits_of, block_of, mmo_shared, Mmo, OtTower, SharedKey, COTS_PER_CALL, COTS_PER_KEY};
use dpf_common::block::{depth_for, Block};
use dpf_common::bool2pc::rot_string_triples;
use dpf_common::net::{Channel, CommStats};
use dpf_common::ot::{CotPair, FerretConfig};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::time::{Duration, Instant};

/// Everything one party gets out of [`gen`] (and [`super::bin::gen`]).
pub struct GenOutput<K> {
    pub key: K,
    /// Base OTs and the Ferret bootstrap.
    pub setup_stats: CommStats,
    pub pre_stats: CommStats,
    pub gen_stats: CommStats,
    pub setup_time: Duration,
    pub pre_time: Duration,
    pub gen_time: Duration,
    /// ANDs of the AES calls.
    pub ands: usize,
    /// COTs consumed after setup (the OT tower's, α-bits, branch-selection
    /// triples, the leaf's).
    pub cots: usize,
}

/// The correlations one generation consumes.
pub struct Pre {
    pub be: OtTower,
    /// `(a, B, a·B)` for the n branch selections.
    pub string_triples: Vec<(bool, Block, Block)>,
}

/// The OT tower's COTs for `calls` AES–MMO calls and `keys` key expansions,
/// `strings` bit-times-block triples from Ferret random OTs and `cots` COTs
/// per direction.
pub(crate) fn precompute_counts(
    ch: &mut Channel,
    cot: &mut CotPair,
    calls: usize,
    keys: usize,
    strings: usize,
    cots: usize,
    rng: &mut ChaCha20Rng,
) -> Pre {
    let pool = cot.random_cots(ch, 0, calls * COTS_PER_CALL + keys * COTS_PER_KEY, rng).expect("semi-honest COT");
    let be = OtTower::new(ch.party(), pool, cot.delta());
    let string_triples = rot_string_triples(ch, cot, strings, rng);
    cot.precompute(ch, cots, cots, rng).expect("semi-honest COT");
    Pre { be, string_triples }
}

/// One party's session state after setup.
pub(crate) struct Setup {
    pub cot: CotPair,
    pub rng: ChaCha20Rng,
    pub stats: CommStats,
    pub time: Duration,
}

/// Base OTs keyed by `Δ_b` (`lsb(Δ_b) = b`) and Ferret.
pub(crate) fn setup(ch: &mut Channel, seed: [u8; 32], ferret: Option<FerretConfig>) -> Setup {
    let t_setup = Instant::now();
    let mut rng = ChaCha20Rng::from_seed(seed);
    let party = ch.party();
    let delta = Block::random(&mut rng).with_lsb(party == 1);
    let mut cot = CotPair::setup(ch, &mut rng, delta, false).expect("semi-honest base OT");
    if let Some(cfg) = ferret {
        cot.enable_ferret(ch, cfg, &mut rng).expect("semi-honest Ferret");
    }
    ch.sync();
    Setup { cot, rng, stats: ch.stats(), time: t_setup.elapsed() }
}

/// Steps 1–3: `⟨α_ℓ·Δ⟩`, then the n levels under `F = H_K` with `keys[0] =
/// ⟨K⟩`; every key in `keys` is expanded during level 1. `extra` rides with the level-0
/// message (n ≥ 1) and the other party's `extra` (of the same length) is
/// returned. `cw_err = Some((ℓ, ε))` XORs ε into this party's CW share at
/// level ℓ (a deliberate deviation, for the malicious abort tests). Returns
/// this party's share of `st_{n,0}`, the words, the reply.
/// What [`walk`] leaves: this party's root `st_{0,b}`, its share of
/// `st_{n,0}`, the n level words, and the peer's `extra`.
pub(crate) struct Walk {
    pub root: Block,
    pub st: Block,
    pub cws: Vec<Block>,
    pub reply: Vec<u8>,
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn walk(
    be: &mut OtTower,
    string_triples: &[(bool, Block, Block)],
    keys: &mut [SharedKey<bool>],
    cot: &mut CotPair,
    rng: &mut ChaCha20Rng,
    ch: &mut Channel,
    n: usize,
    alpha_share: u64,
    extra: &[u8],
    cw_err: Option<(usize, Block)>,
) -> Walk {
    assert!(n >= 1);
    let b = ch.party();
    let delta = cot.delta();

    // 1. ⟨α_ℓ·Δ⟩.
    let a: Vec<bool> = (0..n).map(|i| (alpha_share >> (n - 1 - i)) & 1 == 1).collect();
    let (k, m) = cot.extend(ch, &a, n, rng).expect("semi-honest COT");
    let a_delta: Vec<Block> = (0..n).map(|i| delta.and_bit(a[i]) ^ m[i] ^ k[i]).collect();

    // 2. A fresh root per Gen: party 0 takes `R` (lsb 0), party 1 gets
    //    `R ⊕ Δ_0 ⊕ Δ_1` from `R ⊕ Δ_0`, sent with the level-1 message, so
    //    `⟨st_{0,0}⟩ = (R, 0)`. Roots equal to `Δ_b` would repeat across the
    //    Gens of a session, and two keys on the same roots give
    //    `CW_ℓ ⊕ CW'_ℓ = Δ` at the first level where α and α' differ.
    let r0 = Block::random(rng).with_lsb(false);
    let mut root = r0;
    let mut st = if b == 0 { r0 } else { Block::ZERO };
    let mut cws = Vec::with_capacity(n);
    let mut reply = Vec::new();
    for i in 0..n {
        // 3A. L_0, L_1.
        let l = mmo_shared(be, ch, keys, &[(0, bits_of(st)), (0, bits_of(st ^ delta))]);
        let (l0, l1) = (block_of(&l[0]), block_of(&l[1]));
        // 3B + C opening.
        let mut cw_share = l0 ^ l1 ^ delta ^ a_delta[i];
        if let Some((lvl, e)) = cw_err {
            if lvl == i {
                cw_share ^= e;
            }
        }
        let (ta, tb, tc) = string_triples[i];
        let (e, f) = (a[i] ^ ta, st ^ tb);
        let x = if i == 0 { extra.len() } else { 0 };
        // Level 1 also carries `R ⊕ Δ_0`, from party 0 to party 1.
        let (rx_out, rx_in) = match (i, b) {
            (0, 0) => (16, 0),
            (0, _) => (0, 16),
            _ => (0, 0),
        };
        let mut msg = Vec::with_capacity(33 + x + rx_out);
        msg.extend_from_slice(&cw_share.to_bytes());
        msg.extend_from_slice(&f.to_bytes());
        msg.push(e as u8);
        msg.extend_from_slice(&extra[..x]);
        if rx_out > 0 {
            msg.extend_from_slice(&(r0 ^ delta).to_bytes());
        }
        ch.send(msg);
        let mut theirs = ch.recv();
        assert_eq!(theirs.len(), 33 + x + rx_in, "malformed level message");
        if rx_in > 0 {
            root = Block::from_bytes(&theirs.split_off(33 + x)) ^ delta;
        }
        if i == 0 {
            reply = theirs.split_off(33);
        }
        let cw = cw_share ^ Block::from_bytes(&theirs[..16]);
        let (f, e) = (f ^ Block::from_bytes(&theirs[16..32]), e ^ (theirs[32] & 1 == 1));
        // α·st = e·f ⊕ e·B ⊕ f·a ⊕ C.
        let prod = f.and_bit(e && b == 0) ^ tb.and_bit(e) ^ f.and_bit(ta) ^ tc;
        st = l0 ^ prod ^ cw.and_bit(st.lsb());
        cws.push(cw);
    }
    Walk { root, st, cws, reply }
}

fn gen_with<F: Field>(
    cot: &mut CotPair,
    pre: Pre,
    fpre: &mut FpPre<F>,
    rng: &mut ChaCha20Rng,
    ch: &mut Channel,
    n_size: u64,
    alpha_share: u64,
    beta_share: F,
) -> (ShKey<F>, usize) {
    let b = ch.party();
    let n = depth_for(n_size);
    let Pre { mut be, string_triples } = pre;
    let delta = cot.delta();
    // 0. ⟨K⟩, ⟨K'⟩.
    let (ks, mut keys) = sample_keys(rng, SH_KEYS);
    let Walk { root, st, cws, .. } = walk(&mut be, &string_triples, &mut keys, cot, rng, ch, n, alpha_share, &[], None);

    // 4. Leaf word, with the key reveal.
    let w = mmo_shared(&mut be, ch, &mut keys, &[(1, bits_of(leaf_seed(st))), (1, bits_of(leaf_seed(st ^ delta)))]);
    let (ws, theirs) = arith_leaf(ch, &[[block_of(&w[0]), block_of(&w[1])]], &[Sub::Share(beta_share)], st.lsb(), fpre, &[F::ZERO], &key_bytes(&ks));
    let mut prf = open_keys(&ks, &theirs).into_iter();
    let (prf, pay) = (prf.next().unwrap(), prf.next().unwrap());
    (ShKey { party: b, n_size, prf, pay, root, cws, w_cw: ws[0] }, be.ands)
}

/// Runs this party's side of setup, preprocessing and generation.
///
/// * `alpha_share`: XOR share of `α < N`; `beta_share`: additive share of
///   `β ∈ F_p`.
/// * `ferret`: the silent-OT parameters (`Some(FerretConfig::B13)` for
///   benchmarks); `None` keeps IKNP, for tests.
pub fn gen<F: Field>(
    ch: &mut Channel,
    n_size: u64,
    alpha_share: u64,
    beta_share: F,
    seed: [u8; 32],
    ferret: Option<FerretConfig>,
) -> GenOutput<ShKey<F>> {
    let n = depth_for(n_size);
    let (dabits, triples) = (leaf_dabits::<F>(1), 1);
    drive(
        ch,
        seed,
        ferret,
        n,
        n + fp_pre_cots::<F>(dabits, triples),
        |cot, rng, ch| fp_pre::<F, _>(ch, cot, dabits, triples, rng),
        |cot, pre, mut fpre, rng, ch| gen_with(cot, pre, &mut fpre, rng, ch, n_size, alpha_share, beta_share),
    )
}

/// Setup, then preprocessing (the OT tower's COTs for [`sh_calls`]`(n)`
/// AES–MMO calls, n string triples, `cots` COTs per direction, then `extra`),
/// then `body`, the generation proper, each phase timed and counted on its own.
pub(crate) fn drive<K, P>(
    ch: &mut Channel,
    seed: [u8; 32],
    ferret: Option<FerretConfig>,
    n: usize,
    cots: usize,
    extra: impl FnOnce(&mut CotPair, &mut ChaCha20Rng, &mut Channel) -> P,
    body: impl FnOnce(&mut CotPair, Pre, P, &mut ChaCha20Rng, &mut Channel) -> (K, usize),
) -> GenOutput<K> {
    let Setup { mut cot, mut rng, stats: setup_stats, time: setup_time } = setup(ch, seed, ferret);
    let cots_before = cot.produced;

    let t_pre = Instant::now();
    let pre = precompute_counts(ch, &mut cot, sh_calls(n), SH_KEYS, n, cots, &mut rng);
    let more = extra(&mut cot, &mut rng, ch);
    let pre_stats = ch.stats().since(&setup_stats);
    let pre_time = t_pre.elapsed();
    // Timing only: neither party's gen time includes waiting for the other's
    // preprocessing. Counted in no phase.
    ch.sync();
    let gen_start = ch.stats();
    let t_gen = Instant::now();
    let (key, ands) = body(&mut cot, pre, more, &mut rng, ch);
    GenOutput {
        key,
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

/// Trusted-dealer generation for given roots (`lsb(root_b) = b`) and AES keys
/// `[K, K']`: the cleartext Gen, and the bit-exact oracle of [`gen`].
pub fn deal<F: Field>(roots: [Block; 2], keys: [[u8; 16]; SH_KEYS], n_size: u64, alpha: u64, beta: F) -> [ShKey<F>; 2] {
    assert!(alpha < n_size);
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
    let mut rng = ChaCha20Rng::from_seed(seed);
    let roots = [Block::random(&mut rng).with_lsb(false), Block::random(&mut rng).with_lsb(true)];
    let keys: [[u8; 16]; SH_KEYS] = std::array::from_fn(|_| Block::random(&mut rng).to_bytes());
    deal(roots, keys, n_size, alpha, beta)
}
