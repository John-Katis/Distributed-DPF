//! Malicious generation with abort with an arithmetic payload: the paper's
//! "Authenticated generation" for a payload field F (Babybear) and a MAC
//! field E ⊇ F (`F_{q^4}`), on the Gen of [`crate::semi_honest::gen`] with
//! switch level ν = 0: no top phase, since with a malicious top phase the
//! switch could swap the roles of the parties, which negates an arithmetic
//! output and its MAC together, undetected. The lower levels stay level
//! independent (pre-sampled `U_ℓ` joined by `M_ℓ`), with fresh public keys
//! per Gen and per level as in [`crate::malicious`].
//!
//! 1. A persistent payload-MAC key `δ = δ_0 + δ_1 ∈ E`, sampled once per
//!    session and never opened.
//! 2. `F^pay = H_{K_pay}(s ∥ 0)` (one block, κ bits) and `F^mac`, the
//!    [`mask_blocks`] blocks `H_{K_mac}(s ∥ 0 ⊕ tweak(j))` ([`mask_tweak`],
//!    κ bits per coordinate of E), on both on-path leaf seeds `U_n`, `U_n ⊕
//!    Δ` (indexed by party), in the batch of the lower levels' AES–MMO calls.
//! 3. The paper's arithmetic leaf ([`arith_leaf`], three rounds after the
//!    calls, concurrent with Step B and `M_ℓ`) on the two words `V = W_0 −
//!    W_1 − β` (in F) and `Ṽ = W̃_0 − W̃_1 − δβ` (in E): B2A of the mask
//!    bits by daBits, `⟦δβ⟧` by a Beaver product over E (β is secret-shared),
//!    and the sign `(1 − 2t_{n,0})` by the tag's daBit and one triple per word.
//! 4. Π_Verify's mask `(⟦r⟧, ⟦δr⟧)` for this key, from one more triple over
//!    E with `v = δ` (preprocessing).
//!
//! Every deviation shows up only in the published key material, which
//! Π_Verify ([`super::verify`]) checks at evaluation time, up to the one-bit
//! selective-failure leak of the paper's paragraph "Selective failure".
//!
//! Rounds: 43.

use super::key::{ArithMalKey, VerifyMask};
use crate::field::{mask_blocks, mask_value, Ext, Field};
use crate::leaf::{arith_leaf, fp_pre, fp_pre_cots, leaf_dabits, FpPre, Sub};
use crate::malicious::Fault;
use crate::semi_honest::gen::{precompute, setup, walk, Pre, Setup, Walk};
use crate::{deal_walk_nu, leaf_seed, mask_tweak};
use dpf_common::aes_tower::{Mmo, ANDS_PER_CALL};
use dpf_common::block::{depth_for, Block};
use dpf_common::net::{Channel, CommStats};
use dpf_common::ot::FerretConfig;
use rand::{CryptoRng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use std::time::{Duration, Instant};

/// AES–MMO calls in 2PC of one Gen: two per level, two for `F^pay` and two
/// per block of `F^mac`.
pub fn arith_mal_calls<F: Field, E: Ext<F>>(n: usize) -> usize {
    2 * n + 2 + 2 * mask_blocks::<F, E>()
}

/// ANDs of one Gen (all keys public: no Π_KeyExp).
pub fn arith_mal_ands<F: Field, E: Ext<F>>(n: usize) -> usize {
    arith_mal_calls::<F, E>(n) * ANDS_PER_CALL
}

/// Leaf correlations: daBits for the payload word (one coordinate) and the
/// MAC word (`E::DEG`), Beaver triples over E for the two signs, `δβ` and
/// the Π_Verify mask.
pub fn leaf_counts<F: Field, E: Ext<F>>() -> (usize, usize) {
    (leaf_dabits::<F>(&[1, E::DEG]), 4)
}

/// One party's long-lived state.
pub struct ArithMalSession<F: Field, E: Ext<F>> {
    s: Setup,
    /// `δ_b`, this party's share of the persistent payload-MAC key.
    pub delta_mac: E,
    _f: std::marker::PhantomData<F>,
}

impl<F: Field, E: Ext<F>> ArithMalSession<F, E> {
    /// The semi-honest setup (base OTs, Ferret) and δ_b.
    pub fn setup(ch: &mut Channel, seed: [u8; 32], ferret: Option<FerretConfig>) -> Self {
        let mut s = setup(ch, seed, ferret);
        let delta_mac = E::random(&mut s.rng);
        ArithMalSession { s, delta_mac, _f: std::marker::PhantomData }
    }

    /// The preprocessing of one Gen of depth n with ν = 0
    /// (`semi_honest::gen::precompute` for [`arith_mal_calls`] AES–MMO calls
    /// and keys `K_1, …, K_n, K_pay, K_mac`), and the leaf's daBits over F
    /// and Beaver triples over E ([`leaf_counts`]), the first one the
    /// Π_Verify mask `(r, δr)`.
    pub fn precompute(&mut self, ch: &mut Channel, n: usize) -> (Pre, FpPre<F, E>) {
        let s = &mut self.s;
        let (dabits, triples) = leaf_counts::<F, E>();
        let pre = precompute(ch, &mut s.cot, n, 0, arith_mal_calls::<F, E>(n), true, 2, 0, fp_pre_cots::<F, E>(dabits, triples), &mut s.rng);
        let fpre = fp_pre(ch, &mut s.cot, dabits, triples, &[self.delta_mac], &mut s.rng);
        (pre, fpre)
    }

    /// One generation of a key for the random α of `pre` and `β ∈ F`
    /// (additive shares). Returns the key, the ANDs, this key's Π_Verify mask
    /// and this party's share of α. A fault at level `< n` hits
    /// `CW_{level+1}`, at `n` the payload word, at `n + 1` the MAC word (its
    /// error read as an element of E), at `n + 2` `M_0`.
    pub fn gen(
        &mut self,
        ch: &mut Channel,
        n_size: u64,
        beta_share: F,
        pre: (Pre, FpPre<F, E>),
        fault: Option<Fault>,
    ) -> (ArithMalKey<F, E>, usize, VerifyMask<E>, u64) {
        let b = ch.party();
        let n = depth_for(n_size);
        let err = |lvl: usize| match fault {
            Some(f) if f.level == lvl => E::from_u128(f.err.0),
            _ => E::ZERO,
        };
        let (mut pre, mut fpre): (Pre, FpPre<F, E>) = pre;
        let (r, _, dr) = fpre.triples.remove(0);
        assert_eq!(pre.alpha_delta.len(), n, "preprocessing for depth n");

        // 2. Leaf masks on U_n, U_n ⊕ Δ, XOR-shared; the public tweaks are party 0's.
        let un = pre.us[n];
        let seeds = [leaf_seed(un), leaf_seed(un ^ pre.delta)];
        let mb = mask_blocks::<F, E>();
        let tw = |j: usize| if b == 0 { mask_tweak(j) } else { Block::ZERO };
        let (kp, km) = (pre.extra_key(0), pre.extra_key(1));
        let mut jobs: Vec<(usize, Block)> = seeds.iter().map(|&x| (kp, x)).collect();
        for x in seeds {
            jobs.extend((0..mb).map(|j| (km, x ^ tw(j))));
        }
        let walk_err = fault.and_then(|f| match f.level {
            l if l < n => Some((l, f.err)),
            l if l == n + 2 => Some((n, f.err)),
            _ => None,
        });
        let Walk { cws, ms, leaf: w, mut leaf_lane } = walk(&mut pre, ch, &jobs, walk_err);

        // 3. The leaf: W_CW and W^MAC_CW.
        let masks = [[vec![w[0]], vec![w[1]]], [w[2..2 + mb].to_vec(), w[2 + mb..].to_vec()]];
        let subs = [Sub::Share(E::embed(beta_share)), Sub::Product(self.delta_mac, E::embed(beta_share))];
        let words = arith_leaf(ch, &mut leaf_lane, &masks, &[1, E::DEG], &subs, un.lsb(), &mut fpre, &[err(n), err(n + 1)]);
        ch.join(leaf_lane);
        let (w_cw, wm_cw) = (words[0].coord(0), words[1]);
        let prf = pre.level_keys();
        let (pay, mac) = (pre.keys[kp].clone(), pre.keys[km].clone());
        let key = ArithMalKey { party: b, n_size, prf, pay, mac, root: pre.delta, nu: 0, cws, ms, w_cw, wm_cw };
        (key, pre.be.ands, VerifyMask { r, dr }, pre.alpha_share)
    }
}

/// Everything one party gets from [`run_mal_arith`].
pub struct ArithMalRun<F: Field, E: Ext<F>> {
    pub key: ArithMalKey<F, E>,
    /// This party's XOR share of the random index α.
    pub alpha_share: u64,
    /// This party's XOR shares of the on-path states `U_ν, …, U_n` of party 0.
    pub onpath_share: Vec<Block>,
    /// This party's share of the payload-MAC key δ.
    pub delta_share: E,
    /// This party's share of the key's Π_Verify mask.
    pub mask: VerifyMask<E>,
    /// Base OTs and the Ferret bootstrap.
    pub setup_stats: CommStats,
    pub setup_time: Duration,
    pub pre_stats: CommStats,
    pub pre_time: Duration,
    pub gen_stats: CommStats,
    pub gen_time: Duration,
    /// ANDs of the AES calls and key expansions.
    pub ands: usize,
    /// COTs consumed after setup (the OT tower's, ⟨α_ℓ·Δ⟩, string triples,
    /// leaf OLEs).
    pub cots: usize,
}

/// Setup, preprocessing and generation for one party.
#[allow(clippy::too_many_arguments)]
pub fn run_mal_arith<F: Field, E: Ext<F>>(
    ch: &mut Channel,
    n_size: u64,
    beta_share: F,
    seed: [u8; 32],
    ferret: Option<FerretConfig>,
    fault: Option<Fault>,
) -> ArithMalRun<F, E> {
    let mut s = ArithMalSession::<F, E>::setup(ch, seed, ferret);
    let (setup_stats, setup_time) = (s.s.stats, s.s.time);
    let cots_before = s.s.cot.produced;
    let n = depth_for(n_size);
    let t_pre = Instant::now();
    let pre = s.precompute(ch, n);
    let onpath_share = pre.0.us.clone();
    let pre_stats = ch.stats().since(&setup_stats);
    let pre_time = t_pre.elapsed();
    // Timing only: counted in no phase.
    ch.sync();
    let before = ch.stats();
    let t = Instant::now();
    let (key, ands, mask, alpha_share) = s.gen(ch, n_size, beta_share, pre, fault);
    ArithMalRun {
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

/// `F^mac(s)` in the clear: the [`mask_blocks`] blocks `H_{K_mac}(s ∥ 0 ⊕
/// tweak(j))` read as an element of E.
pub(crate) fn mac_mask<F: Field, E: Ext<F>>(mac: &Mmo, seed: Block) -> E {
    let blocks: Vec<Block> = (0..mask_blocks::<F, E>()).map(|j| mac.h(seed ^ mask_tweak(j))).collect();
    mask_value::<F, E>(&blocks)
}

/// Trusted-dealer generation for given roots (`lsb(root_b) = b`), AES keys
/// `[K_1, …, K_n, K_pay, K_mac]`, on-path states `us = [U_0, …, U_n]` of
/// party 0 (ν = 0) and payload-MAC key δ: the cleartext Gen and the oracle
/// of [`ArithMalSession::gen`].
pub fn deal<F: Field, E: Ext<F>>(
    roots: [Block; 2],
    keys: &[[u8; 16]],
    n_size: u64,
    alpha: u64,
    beta: F,
    delta_mac: E,
    us: &[Block],
) -> [ArithMalKey<F, E>; 2] {
    let n = depth_for(n_size);
    assert_eq!(keys.len(), n + 2, "K_1, …, K_n, K_pay, K_mac");
    let mut prf: Vec<Mmo> = keys.iter().map(|&k| Mmo::new(k)).collect();
    let mac = prf.pop().unwrap();
    let pay = prf.pop().unwrap();
    let (cws, ms, st) = deal_walk_nu(&prf, roots, n, 0, alpha, us);
    let s = [leaf_seed(st[0]), leaf_seed(st[1])];
    let f = |x: Block| F::from_block(pay.h(x));
    let v = f(s[0]).sub(f(s[1])).sub(beta);
    let vm = mac_mask::<F, E>(&mac, s[0]).sub(mac_mask::<F, E>(&mac, s[1])).sub(delta_mac.mul(E::embed(beta)));
    let (w_cw, wm_cw) = if st[0].lsb() { (v.neg(), vm.neg()) } else { (v, vm) };
    let mk = |party: usize| ArithMalKey {
        party,
        n_size,
        prf: prf.clone(),
        pay: pay.clone(),
        mac: mac.clone(),
        root: roots[party],
        nu: 0,
        cws: cws.clone(),
        ms: ms.clone(),
        w_cw,
        wm_cw,
    };
    [mk(0), mk(1)]
}

/// Shares of a Π_Verify mask `(r, δr)` for a known δ (a dealer's).
pub fn deal_mask<E: Field, R: RngCore + CryptoRng>(delta_mac: E, rng: &mut R) -> [VerifyMask<E>; 2] {
    let (r, r0, d0) = (E::random(rng), E::random(rng), E::random(rng));
    let dr = delta_mac.mul(r);
    [VerifyMask { r: r0, dr: d0 }, VerifyMask { r: r.sub(r0), dr: dr.sub(d0) }]
}

/// Dealer keys from a seed, with the δ shares.
pub fn gen_reference<F: Field, E: Ext<F>>(n_size: u64, alpha: u64, beta: F, seed: [u8; 32]) -> ([ArithMalKey<F, E>; 2], [E; 2]) {
    assert!(alpha < n_size);
    let mut rng = ChaCha20Rng::from_seed(seed);
    let n = depth_for(n_size);
    let roots = [Block::random(&mut rng).with_lsb(false), Block::random(&mut rng).with_lsb(true)];
    let keys: Vec<[u8; 16]> = (0..n + 2).map(|_| Block::random(&mut rng).to_bytes()).collect();
    let us: Vec<Block> = (0..=n).map(|_| Block::random(&mut rng)).collect();
    let d = [E::random(&mut rng), E::random(&mut rng)];
    (deal(roots, &keys, n_size, alpha, beta, d[0].add(d[1]), &us), d)
}
