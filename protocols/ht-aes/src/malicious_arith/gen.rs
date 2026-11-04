//! Malicious generation with abort, arithmetic payload: the paper's "Full
//! protocols in the malicious setting" (Figure "Additions to DPF.Gen") for a
//! payload field F (Babybear) and a MAC field E ⊇ F (`F_{q^4}`), on the
//! semi-honest Gen of [`crate::semi_honest::gen`] in its session (one public
//! K, one global ⟨Δ⟩, a public W per Gen, glue level ν ≥ 1), with
//!
//! * Setup: the persistent payload-MAC key `⟦δ⟧`, δ ∈ E, never opened, and
//!   public keys `K^mac_1, …, K^mac_c`, `c = ⌈d(κ)/128⌉` ([`mask_blocks`]).
//! * (B) One product per bottom level: `(⟨α_ℓ·Δ⟩, ⟨P_ℓ⟩)` from one
//!   bit-times-2-block product of `⟨α_ℓ⟩` with `⟨Δ⟩ ∥ ⟨u_{ℓ−1}⟩`.
//! * (C) The glue residual `⟦ω⟧` ([`glue_residual`]), after the glue, on the
//!   top phase's lane; kept with the key and checked by Π_Verify.
//! * (A) The MAC word: `F^mac(s)`, the coordinates read from `H_{K^mac_1}(s ∥
//!   0) ∥ … ∥ H_{K^mac_c}(s ∥ 0)`, on the leaf states `u_n`, `u_n ⊕ Δ`
//!   (indexed by server), in the batch of the lower levels' AES–MMO calls
//!   with the payload masks on `Y`, `Y ⊕ Δ`; then [`mal_leaf`]: `W_CW` as in
//!   the semi-honest Gen and `W^MAC_CW = 𝓕_mul(1 − 2σ, W̃_0 − W̃_1 − β·δ)`.
//!
//! β is public, so `β·⟦δ⟧` is local. Π_Verify's mask `(⟦ρ⟧, ⟦δρ⟧)` is one
//! more triple over E with `v = δ` (preprocessing). Nothing in Gen is checked;
//! every deviation shows up only in the outputs or in ω, which Π_Verify
//! ([`super::verify`]) checks after evaluation, up to the one-bit
//! selective-failure leak of the paper's paragraph "Selective failure".
//!
//! Rounds: `max(ν + 7, 44)`.

use super::key::{ArithMalKey, VerifyMask};
use crate::field::{mask_blocks, mask_value, Ext, Field};
use crate::leaf::{fp_pre, fp_pre_cots, glue_residual, leaf_dabits, mal_leaf, FpPre, RESIDUAL_DABITS};
use crate::malicious::Fault;
use crate::semi_honest::gen::{precompute, setup, walk, Pre, Setup, Shape, Walk};
use crate::{deal_walk_nu, default_nu_mal_arith, leaf_seed};
use dpf_common::aes_tower::{Mmo, ANDS_PER_CALL};
use dpf_common::block::{depth_for, Block};
use dpf_common::net::{Channel, CommStats};
use dpf_common::ot::FerretConfig;
use rand::{CryptoRng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use std::time::{Duration, Instant};

/// AES–MMO calls in 2PC of one Gen: two per level below ν, two for `F^pay`
/// and c for `F^mac` on each of the two leaf states.
pub fn arith_mal_calls<F: Field, E: Ext<F>>(n: usize, nu: usize) -> usize {
    2 * (n - nu) + 2 + 2 * mask_blocks::<F, E>()
}

/// ANDs of one Gen (all keys public: no Π_KeyExp).
pub fn arith_mal_ands<F: Field, E: Ext<F>>(n: usize, nu: usize) -> usize {
    arith_mal_calls::<F, E>(n, nu) * ANDS_PER_CALL
}

/// Correlations over the fields: daBits for the payload word (one
/// coordinate), the MAC word (`E::DEG`) and the glue residual
/// ([`RESIDUAL_DABITS`]); Beaver triples over E for the Π_Verify mask, the
/// MAC word's sign and the residual's two squares.
pub fn leaf_counts<F: Field, E: Ext<F>>() -> (usize, usize) {
    (leaf_dabits::<F>(&[1, E::DEG]) + RESIDUAL_DABITS, 4)
}

/// One party's long-lived state.
pub struct ArithMalSession<F: Field, E: Ext<F>> {
    s: Setup,
    /// `δ_b`, this party's share of the persistent payload-MAC key.
    pub delta_mac: E,
    _f: std::marker::PhantomData<F>,
}

/// One party's output of [`ArithMalSession::gen`].
pub struct ArithMalGen<F: Field, E: Ext<F>> {
    pub key: ArithMalKey<F, E>,
    pub ands: usize,
    /// The key's Π_Verify mask.
    pub mask: VerifyMask<E>,
    /// This party's share of the glue residual ω, kept with the key.
    pub omega: E,
    /// This party's share of α.
    pub alpha_share: u64,
}

impl<F: Field, E: Ext<F>> ArithMalSession<F, E> {
    /// Π_setup (base OTs, Ferret, ⟨Δ⟩, K and the `K^mac_j`) and δ_b.
    pub fn setup(ch: &mut Channel, seed: [u8; 32], ferret: Option<FerretConfig>) -> Self {
        let mut s = setup(ch, seed, ferret, mask_blocks::<F, E>());
        let delta_mac = E::random(&mut s.rng);
        ArithMalSession { s, delta_mac, _f: std::marker::PhantomData }
    }

    /// The preprocessing of one Gen of depth n with glue level ν
    /// (`semi_honest::gen::precompute` for [`arith_mal_calls`] AES–MMO calls
    /// with (B) and a tag-indexed leaf), and the daBits over F and Beaver
    /// triples over E ([`leaf_counts`]), the first one the Π_Verify mask
    /// `(ρ, δρ)`.
    pub fn precompute(&mut self, ch: &mut Channel, n: usize, nu: usize) -> (Pre, FpPre<F, E>) {
        let s = &mut self.s;
        let (dabits, triples) = leaf_counts::<F, E>();
        let shape = Shape { nu, y: true, one_product: true };
        let pre = precompute(ch, s, n, shape, arith_mal_calls::<F, E>(n, nu), 0, fp_pre_cots::<F, E>(dabits, triples));
        let fpre = fp_pre(ch, &mut s.cot, dabits, triples, &[self.delta_mac], &mut s.rng);
        (pre, fpre)
    }

    /// One generation of a key for the random α of `pre` and the public `β ∈
    /// F`. A fault [`Fault::Word`] at level `< n` hits `CW_{level+1}`, at `n`
    /// the payload word, at `n + 1` the MAC word (its error read as an element
    /// of E), at `n + 2` `M_ν`.
    pub fn gen(&mut self, ch: &mut Channel, n_size: u64, beta: F, pre: (Pre, FpPre<F, E>), fault: Option<Fault>) -> ArithMalGen<F, E> {
        let n = depth_for(n_size);
        let err = |lvl: usize| E::from_u128(Fault::leaf(fault, lvl).0);
        let (mut pre, mut fpre): (Pre, FpPre<F, E>) = pre;
        let (r, _, dr) = fpre.triples.remove(0);
        assert_eq!(pre.alpha_delta.len(), n, "preprocessing for depth n");

        // F^pay (key 0 = K) on Y, Y ⊕ Δ; F^mac (keys 1..=c) on u_n, u_n ⊕ Δ.
        let mb = mask_blocks::<F, E>();
        let jobs = |p: &Pre| {
            let mut j = vec![(0, leaf_seed(p.y)), (0, leaf_seed(p.y ^ p.delta))];
            for x in [leaf_seed(p.un()), leaf_seed(p.un() ^ p.delta)] {
                j.extend((1..=mb).map(|k| (k, x)));
            }
            j
        };
        let Walk { cws, ms, leaf: w, mut leaf_lane, mut top_lane, glue, frontier } = walk(&mut pre, ch, jobs, Fault::walk(fault, n), true);

        // (A) The leaf: W_CW and W^MAC_CW.
        let mac = [w[2..2 + mb].to_vec(), w[2 + mb..].to_vec()];
        let (w_cw, wm_cw) = mal_leaf(ch, &mut leaf_lane, [w[0], w[1]], &mac, pre.t_leaf, beta, self.delta_mac, &mut fpre, (err(n).coord(0), err(n + 1)));
        // (C) The glue residual, on the top phase's lane.
        let omega = glue_residual(ch, &mut top_lane, glue, pre.delta, &frontier, &mut fpre, &mut self.s.rng);
        ch.join(leaf_lane);
        ch.join(top_lane);
        let mut keys = std::mem::take(&mut pre.keys);
        let prf = keys.remove(0);
        let key = ArithMalKey { party: ch.party(), n_size, prf, mac: keys, root: pre.root(), nu: pre.shape.nu, cws, ms, w_cw, wm_cw };
        ArithMalGen { key, ands: pre.be.ands, mask: VerifyMask { r, dr }, omega, alpha_share: pre.alpha_share }
    }
}

/// Everything one party gets from [`run_mal_arith`].
pub struct ArithMalRun<F: Field, E: Ext<F>> {
    pub key: ArithMalKey<F, E>,
    /// This party's XOR share of the random index α.
    pub alpha_share: u64,
    /// This party's XOR shares of the on-path states `u_ν, …, u_n` of party 0.
    pub onpath_share: Vec<Block>,
    /// This party's share of the payload-MAC key δ.
    pub delta_share: E,
    /// This party's share of the key's Π_Verify mask.
    pub mask: VerifyMask<E>,
    /// This party's share of the key's glue residual ω.
    pub omega: E,
    /// Base OTs and the Ferret bootstrap.
    pub setup_stats: CommStats,
    pub setup_time: Duration,
    pub pre_stats: CommStats,
    pub pre_time: Duration,
    pub gen_stats: CommStats,
    pub gen_time: Duration,
    /// ANDs of the AES calls.
    pub ands: usize,
    /// COTs consumed after setup (the OT tower's, 𝓕_COT's, string triples,
    /// leaf OLEs).
    pub cots: usize,
}

/// Setup, preprocessing and generation for one party, glue level `nu ≥ 1`
/// ([`default_nu_mal_arith`] if `None`), public β.
#[allow(clippy::too_many_arguments)]
pub fn run_mal_arith<F: Field, E: Ext<F>>(
    ch: &mut Channel,
    n_size: u64,
    nu: Option<usize>,
    beta: F,
    seed: [u8; 32],
    ferret: Option<FerretConfig>,
    fault: Option<Fault>,
) -> ArithMalRun<F, E> {
    let mut s = ArithMalSession::<F, E>::setup(ch, seed, ferret);
    let (setup_stats, setup_time) = (s.s.stats, s.s.time);
    let cots_before = s.s.cot.produced;
    let n = depth_for(n_size);
    let t_pre = Instant::now();
    let pre = s.precompute(ch, n, nu.unwrap_or(default_nu_mal_arith(n)));
    let onpath_share = pre.0.us.clone();
    let pre_stats = ch.stats().since(&setup_stats);
    let pre_time = t_pre.elapsed();
    // Timing only: counted in no phase.
    ch.sync();
    let before = ch.stats();
    let t = Instant::now();
    let g = s.gen(ch, n_size, beta, pre, fault);
    ArithMalRun {
        key: g.key,
        alpha_share: g.alpha_share,
        onpath_share,
        delta_share: s.delta_mac,
        mask: g.mask,
        omega: g.omega,
        setup_stats,
        setup_time,
        pre_stats,
        pre_time,
        gen_stats: ch.stats().since(&before),
        gen_time: t.elapsed(),
        ands: g.ands,
        cots: s.s.cot.produced - cots_before,
    }
}

/// `F^mac(s)` in the clear: the coordinates read from `H_{K^mac_1}(s) ∥ … ∥
/// H_{K^mac_c}(s)` ([`mask_value`]), `s` the leaf seed (`∥ 0`).
pub(crate) fn mac_mask<F: Field, E: Ext<F>>(mac: &[Mmo], seed: Block) -> E {
    let blocks: Vec<Block> = mac.iter().map(|k| k.h(seed)).collect();
    mask_value::<F, E>(&blocks)
}

/// Trusted-dealer generation for given roots (`lsb(root_b) = b`), AES keys `K`
/// and `K^mac_1, …, K^mac_c`, glue level ν ≥ 1, on-path states `us = [u_ν, …,
/// u_n]` of party 0 and payload-MAC key δ: the cleartext Gen and the oracle
/// of [`ArithMalSession::gen`] (whose glue residual is a sharing of 0).
#[allow(clippy::too_many_arguments)]
pub fn deal<F: Field, E: Ext<F>>(
    roots: [Block; 2],
    key: [u8; 16],
    mac_keys: &[[u8; 16]],
    n_size: u64,
    nu: usize,
    alpha: u64,
    beta: F,
    delta_mac: E,
    us: &[Block],
) -> [ArithMalKey<F, E>; 2] {
    let n = depth_for(n_size);
    assert_eq!(mac_keys.len(), mask_blocks::<F, E>(), "K^mac_1, …, K^mac_c");
    let prf = Mmo::new(key);
    let mac: Vec<Mmo> = mac_keys.iter().map(|&k| Mmo::new(k)).collect();
    let (cws, ms, st) = deal_walk_nu(&prf, roots, n, nu, alpha, us);
    let s = [leaf_seed(st[0]), leaf_seed(st[1])];
    let f = |x: Block| F::from_block(prf.h(x));
    let v = f(s[0]).sub(f(s[1])).sub(beta);
    let vm = mac_mask::<F, E>(&mac, s[0]).sub(mac_mask::<F, E>(&mac, s[1])).sub(delta_mac.mul(E::embed(beta)));
    let (w_cw, wm_cw) = if st[0].lsb() { (v.neg(), vm.neg()) } else { (v, vm) };
    let mk = |party: usize| ArithMalKey { party, n_size, prf: prf.clone(), mac: mac.clone(), root: roots[party], nu, cws: cws.clone(), ms: ms.clone(), w_cw, wm_cw };
    [mk(0), mk(1)]
}

/// Shares of a Π_Verify mask `(ρ, δρ)` for a known δ (a dealer's).
pub fn deal_mask<E: Field, R: RngCore + CryptoRng>(delta_mac: E, rng: &mut R) -> [VerifyMask<E>; 2] {
    let (r, r0, d0) = (E::random(rng), E::random(rng), E::random(rng));
    let dr = delta_mac.mul(r);
    [VerifyMask { r: r0, dr: d0 }, VerifyMask { r: r.sub(r0), dr: dr.sub(d0) }]
}

/// Dealer keys from a seed, glue level [`default_nu_mal_arith`], with the δ shares.
pub fn gen_reference<F: Field, E: Ext<F>>(n_size: u64, alpha: u64, beta: F, seed: [u8; 32]) -> ([ArithMalKey<F, E>; 2], [E; 2]) {
    assert!(alpha < n_size);
    let mut rng = ChaCha20Rng::from_seed(seed);
    let n = depth_for(n_size);
    let nu = default_nu_mal_arith(n);
    let roots = [Block::random(&mut rng).with_lsb(false), Block::random(&mut rng).with_lsb(true)];
    let key = Block::random(&mut rng).to_bytes();
    let mac: Vec<[u8; 16]> = (0..mask_blocks::<F, E>()).map(|_| Block::random(&mut rng).to_bytes()).collect();
    let us: Vec<Block> = (nu..=n).map(|_| Block::random(&mut rng)).collect();
    let d = [E::random(&mut rng), E::random(&mut rng)];
    (deal(roots, key, &mac, n_size, nu, alpha, beta, d[0].add(d[1]), &us), d)
}
