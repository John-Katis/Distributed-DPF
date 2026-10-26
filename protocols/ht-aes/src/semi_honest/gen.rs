//! Semi-honest dealer-free generation (Figure "DPF.Gen" of the paper) with
//! `F_PRF` = AES–MMO in 2PC and F4 triples from FOLEAGE.
//!
//! **Setup** (once per session): each party picks `Δ_b` with `lsb(Δ_b) = b`
//! and runs the base OTs of a COT instance keyed by `Δ_b` in each direction,
//! then bootstraps Ferret on it. The FOLEAGE seeds for `3^N` F4-OLEs are then
//! generated without a dealer ([`dpf_common::foleage::seedgen`]); N is the
//! smallest (≥ 12) that covers the Gen's [`crate::sh_products`] triples.
//!
//! **Preprocessing** (before α and β are known): FOLEAGE expansion and the F4
//! triples, n bit-times-block triples for the branch selection from Ferret
//! random OTs ([`rot_string_triples`]), Ferret COTs for the n α-bits, and the
//! leaf's 2κ + 1 daBits and one Beaver triple over F_p ([`crate::leaf`]).
//!
//! **Generation**, with `α` XOR-shared (bit `n − 1 − i` is level i + 1) and
//! `β` additively shared in `G = F_p` ([`crate::field`]):
//!
//! 1. `⟨α_ℓ·Δ⟩` for all levels from the derandomised COTs (one round):
//!    `α_{ℓ,b}·Δ_b ⊕ M_b[α_{ℓ,b}] ⊕ K_b[α_{ℓ,1−b}]`.
//! 2. `⟨st_{0,0}⟩ = (Δ_0, 0)`, `⟨Δ⟩ = (Δ_0, Δ_1)`, so `⟨st_{0,1}⟩ = (0, Δ_1)`.
//! 3. Per level: two AES–MMO calls on `⟨st_{ℓ−1,0}⟩`, `⟨st_{ℓ−1,0}⟩ ⊕ ⟨Δ⟩` (40
//!    rounds), then one exchange carrying the CW share and the Beaver opening
//!    `(α_ℓ ⊕ a, st_{ℓ−1,0} ⊕ B)` of the branch selection; the new state is
//!    local.
//! 4. Leaf: `W_b = F^pay(s_{n,b} ∥ 0)` for both b (40 rounds), read in F_p
//!    from their low κ bits; then the paper's leaf ([`arith_leaf`]): B2A of
//!    the 2κ bits by daBits and `W_CW = (1 − 2c)·ρV` with `c = t_{n,0} ⊕ r`,
//!    `ρ = 1 − 2r` for a daBit r and one Beaver triple (three rounds).
//!
//! Rounds: `1 + 41n + 40 + 3 = 41n + 44`.

use super::key::ShKey;
use crate::field::Field;
use crate::leaf::{arith_leaf, fp_pre, fp_pre_cots, leaf_dabits, FpPre, Sub};
use crate::{leaf_seed, pay_hash, sh_products, state_hash};
use dpf_common::aes_tower::{bits_of, block_of, mmo_shared, BeaverF4, Mmo, Shared128};
use dpf_common::block::{depth_for, Block};
use dpf_common::bool2pc::rot_string_triples;
use dpf_common::foleage::{self, seedgen::seed_gen, Params};
use dpf_common::net::{Channel, CommStats};
use dpf_common::ot::{CotPair, FerretConfig};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::time::{Duration, Instant};

/// Everything one party gets out of [`gen`] (and [`super::bin::gen`]).
pub struct GenOutput<K> {
    pub key: K,
    /// Base OTs, Ferret bootstrap and the FOLEAGE seed generation.
    pub setup_stats: CommStats,
    pub pre_stats: CommStats,
    pub gen_stats: CommStats,
    pub setup_time: Duration,
    pub pre_time: Duration,
    pub gen_time: Duration,
    /// F4 products (Beaver triples) used by the AES calls.
    pub products: usize,
    /// COTs consumed after setup (α-bits, MUXes, branch-selection triples).
    pub cots: usize,
    /// The FOLEAGE instance: `3^N` OLEs.
    pub foleage: Params,
    /// FOLEAGE seed generation alone (part of setup).
    pub seedgen_stats: CommStats,
    pub seedgen_time: Duration,
}

/// The correlations one generation consumes.
pub struct Pre {
    pub be: BeaverF4,
    /// `(a, B, a·B)` for the n branch selections.
    pub string_triples: Vec<(bool, Block, Block)>,
}

/// `products` F4 triples from the FOLEAGE seed, `strings` bit-times-block
/// triples from Ferret random OTs and `cots` COTs per direction.
pub(crate) fn precompute_counts(ch: &mut Channel, cot: &mut CotPair, seed: &foleage::Seed, products: usize, strings: usize, cots: usize, rng: &mut ChaCha20Rng) -> Pre {
    let ole = seed.expand();
    let be = BeaverF4::new(ch.party(), foleage::triples(&ole, ch.party(), products));
    drop(ole);
    let string_triples = rot_string_triples(ch, cot, strings, rng);
    cot.precompute(ch, cots, cots, rng).expect("semi-honest COT");
    Pre { be, string_triples }
}

/// One party's session state after setup.
pub(crate) struct Setup {
    pub cot: CotPair,
    pub rng: ChaCha20Rng,
    pub fseed: foleage::Seed,
    pub stats: CommStats,
    pub time: Duration,
    pub seedgen_stats: CommStats,
    pub seedgen_time: Duration,
}

/// Base OTs keyed by `Δ_b` (`lsb(Δ_b) = b`), Ferret, FOLEAGE seed generation.
pub(crate) fn setup(ch: &mut Channel, seed: [u8; 32], ferret: Option<FerretConfig>, foleage: Params) -> Setup {
    let t_setup = Instant::now();
    let mut rng = ChaCha20Rng::from_seed(seed);
    let party = ch.party();
    let delta = Block::random(&mut rng).with_lsb(party == 1);
    let mut cot = CotPair::setup(ch, &mut rng, delta, false).expect("semi-honest base OT");
    if let Some(cfg) = ferret {
        cot.enable_ferret(ch, cfg, &mut rng).expect("semi-honest Ferret");
    }
    let before_seed = ch.stats();
    let t_seed = Instant::now();
    let fseed = seed_gen(ch, &mut cot, foleage, &mut rng);
    let seedgen_stats = ch.stats().since(&before_seed);
    let seedgen_time = t_seed.elapsed();
    ch.sync();
    Setup { cot, rng, fseed, stats: ch.stats(), time: t_setup.elapsed(), seedgen_stats, seedgen_time }
}

/// Steps 1–3: `⟨α_ℓ·Δ⟩`, then the n levels. `extra` rides with the level-0
/// message (n ≥ 1) and the other party's `extra` (of the same length) is
/// returned. `cw_err = Some((ℓ, ε))` XORs ε into this party's CW share at
/// level ℓ (a deliberate deviation, for the malicious abort tests). Returns
/// this party's share of `st_{n,0}`, the words, the reply.
#[allow(clippy::too_many_arguments)]
pub(crate) fn walk(
    be: &mut BeaverF4,
    string_triples: &[(bool, Block, Block)],
    cot: &mut CotPair,
    rng: &mut ChaCha20Rng,
    ch: &mut Channel,
    n: usize,
    alpha_share: u64,
    extra: &[u8],
    cw_err: Option<(usize, Block)>,
) -> (Block, Vec<Block>, Vec<u8>) {
    assert!(n >= 1);
    let b = ch.party();
    let delta = cot.delta();
    let fs = state_hash();

    // 1. ⟨α_ℓ·Δ⟩.
    let a: Vec<bool> = (0..n).map(|i| (alpha_share >> (n - 1 - i)) & 1 == 1).collect();
    let (k, m) = cot.extend(ch, &a, n, rng).expect("semi-honest COT");
    let a_delta: Vec<Block> = (0..n).map(|i| delta.and_bit(a[i]) ^ m[i] ^ k[i]).collect();

    // 2. Root shares.
    let mut st = if b == 0 { delta } else { Block::ZERO };
    let mut cws = Vec::with_capacity(n);
    let mut reply = Vec::new();
    for i in 0..n {
        // 3A. L_0, L_1.
        let jobs: [(&Mmo, Shared128<bool>); 2] = [(fs, bits_of(st)), (fs, bits_of(st ^ delta))];
        let l = mmo_shared(be, ch, &jobs);
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
        // α·st = e·f ⊕ e·B ⊕ f·a ⊕ C.
        let prod = f.and_bit(e && b == 0) ^ tb.and_bit(e) ^ f.and_bit(ta) ^ tc;
        st = l0 ^ prod ^ cw.and_bit(st.lsb());
        cws.push(cw);
    }
    (st, cws, reply)
}

fn gen_with<F: Field>(cot: &mut CotPair, pre: Pre, fpre: &mut FpPre<F>, rng: &mut ChaCha20Rng, ch: &mut Channel, n_size: u64, alpha_share: u64, beta_share: F) -> (ShKey<F>, usize) {
    let b = ch.party();
    let n = depth_for(n_size);
    let Pre { mut be, string_triples } = pre;
    let delta = cot.delta();
    let fp = pay_hash();
    let (st, cws, _) = walk(&mut be, &string_triples, cot, rng, ch, n, alpha_share, &[], None);

    // 4. Leaf word.
    let jobs: [(&Mmo, Shared128<bool>); 2] = [(fp, bits_of(leaf_seed(st))), (fp, bits_of(leaf_seed(st ^ delta)))];
    let w = mmo_shared(&mut be, ch, &jobs);
    let w_cw = arith_leaf(ch, &[[block_of(&w[0]), block_of(&w[1])]], &[Sub::Share(beta_share)], st.lsb(), fpre, &[F::ZERO])[0];
    let products = be.products;
    (ShKey { party: b, n_size, root: delta, cws, w_cw }, products)
}

/// Runs this party's side of setup, preprocessing and generation.
///
/// * `alpha_share`: XOR share of `α < N`; `beta_share`: additive share of
///   `β ∈ F_p`.
/// * `ferret`: the silent-OT parameters (`Some(FerretConfig::B13)` for
///   benchmarks); `None` keeps IKNP, for tests.
/// * `foleage`: the PCG instance, at least [`foleage_for`]`(n)`.
#[allow(clippy::too_many_arguments)]
pub fn gen<F: Field>(ch: &mut Channel, n_size: u64, alpha_share: u64, beta_share: F, seed: [u8; 32], ferret: Option<FerretConfig>, foleage: Params) -> GenOutput<ShKey<F>> {
    let n = depth_for(n_size);
    let (dabits, triples) = (leaf_dabits::<F>(1), 1);
    drive(
        ch,
        seed,
        ferret,
        foleage,
        n,
        n + fp_pre_cots::<F>(dabits, triples),
        |cot, rng, ch| fp_pre::<F, _>(ch, cot, dabits, triples, rng),
        |cot, pre, mut fpre, rng, ch| gen_with(cot, pre, &mut fpre, rng, ch, n_size, alpha_share, beta_share),
    )
}

/// Setup, then preprocessing ([`sh_products`]`(n)` F4 triples, n string
/// triples, `cots` COTs per direction, then `extra`), then `body`, the
/// generation proper, each phase timed and counted on its own.
#[allow(clippy::too_many_arguments)]
pub(crate) fn drive<K, P>(
    ch: &mut Channel,
    seed: [u8; 32],
    ferret: Option<FerretConfig>,
    foleage: Params,
    n: usize,
    cots: usize,
    extra: impl FnOnce(&mut CotPair, &mut ChaCha20Rng, &mut Channel) -> P,
    body: impl FnOnce(&mut CotPair, Pre, P, &mut ChaCha20Rng, &mut Channel) -> (K, usize),
) -> GenOutput<K> {
    let Setup { mut cot, mut rng, fseed, stats: setup_stats, time: setup_time, seedgen_stats, seedgen_time } = setup(ch, seed, ferret, foleage);
    let cots_before = cot.produced;

    let t_pre = Instant::now();
    assert!(2 * sh_products(n) <= foleage.oles(), "FOLEAGE instance too small for depth {n}");
    let pre = precompute_counts(ch, &mut cot, &fseed, sh_products(n), n, cots, &mut rng);
    drop(fseed);
    let more = extra(&mut cot, &mut rng, ch);
    let pre_stats = ch.stats().since(&setup_stats);
    let pre_time = t_pre.elapsed();
    // Timing only: neither party's gen time includes waiting for the other's
    // preprocessing. Counted in no phase.
    ch.sync();
    let gen_start = ch.stats();
    let t_gen = Instant::now();
    let (key, products) = body(&mut cot, pre, more, &mut rng, ch);
    GenOutput {
        key,
        gen_stats: ch.stats().since(&gen_start),
        setup_stats,
        pre_stats,
        setup_time,
        pre_time,
        gen_time: t_gen.elapsed(),
        products,
        cots: cot.produced - cots_before,
        foleage,
        seedgen_stats,
        seedgen_time,
    }
}

/// The FOLEAGE instance a Gen of depth n needs (two OLEs per F4 triple).
pub fn foleage_for(n: usize) -> Params {
    Params::for_oles(2 * sh_products(n))
}

/// Trusted-dealer generation for given roots (`lsb(root_b) = b`): the cleartext
/// Gen, and the bit-exact oracle of [`gen`].
pub fn deal<F: Field>(roots: [Block; 2], n_size: u64, alpha: u64, beta: F) -> [ShKey<F>; 2] {
    assert!(alpha < n_size);
    assert!(!roots[0].lsb() && roots[1].lsb(), "lsb(Δ_b) = b");
    let n = depth_for(n_size);
    let delta = roots[0] ^ roots[1];
    let mut st = roots;
    let mut cws = Vec::with_capacity(n);
    for i in 0..n {
        let a = (alpha >> (n - 1 - i)) & 1 == 1;
        let l = [state_hash().h(st[0]), state_hash().h(st[1])];
        let cw = l[0] ^ l[1] ^ delta.and_bit(!a);
        st = [crate::child(st[0], cw, a), crate::child(st[1], cw, a)];
        cws.push(cw);
    }
    debug_assert_eq!(st[0] ^ st[1], delta);
    let w = |s: Block| F::from_block(pay_hash().h(leaf_seed(s)));
    let v = w(st[0]).sub(w(st[1])).sub(beta);
    let w_cw = if st[0].lsb() { v.neg() } else { v };
    let mk = |party: usize| ShKey { party, n_size, root: roots[party], cws: cws.clone(), w_cw };
    [mk(0), mk(1)]
}

/// Trusted-dealer generation from a seed.
pub fn gen_reference<F: Field>(n_size: u64, alpha: u64, beta: F, seed: [u8; 32]) -> [ShKey<F>; 2] {
    let mut rng = ChaCha20Rng::from_seed(seed);
    let roots = [Block::random(&mut rng).with_lsb(false), Block::random(&mut rng).with_lsb(true)];
    deal(roots, n_size, alpha, beta)
}
