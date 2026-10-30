//! Malicious generation with abort on the semi-honest preprocessing, with an
//! arithmetic payload: the paper's "Authenticated generation" for a payload
//! field F (Babybear) and a MAC field E ⊇ F (`F_{q^4}`).
//!
//! As [`crate::malicious`] (the binary instance), extended at the leaf with
//! the arithmetic steps of Figure "DPF.Gen":
//!
//! 1. A persistent payload-MAC key `δ = δ_0 + δ_1 ∈ E`, sampled once per
//!    session and never opened.
//! 2. `F^pay = H_{K'}(s ∥ 0)` (one block, κ bits) and `F^mac`, the
//!    [`mask_blocks`] blocks `H_{K''}(s ∥ 0 ⊕ tweak(j))` ([`mask_tweak`], κ
//!    bits per coordinate of E), on both leaf seeds, all in one batch of MMO
//!    calls (40 rounds); K, K', K'' are shared, expanded at level 1 and
//!    opened in the last round.
//! 3. The paper's arithmetic leaf ([`arith_leaf`], three rounds) on the two
//!    words `V = W_0 − W_1 − β` (in F) and `Ṽ = W̃_0 − W̃_1 − δβ` (in E): B2A
//!    of the mask bits by daBits, `⟦δβ⟧` by a Beaver product over E (β is
//!    secret-shared), and the sign `(1 − 2t_{n,0})` by the tag's daBit and one
//!    triple per word; both words are opened together.
//! 4. Π_Verify's mask `(⟦r⟧, ⟦δr⟧)` for this key, from one more triple over
//!    E with `v = δ` (preprocessing).
//!
//! The products in the AES calls, the branch selection and the leaf are the
//! semi-honest ones (the OT tower, daBits and triples from COTs); every
//! deviation shows up only in the published key material, which Π_Verify
//! ([`super::verify`]) checks at evaluation time, up to the one-bit
//! selective-failure leak of the paper's paragraph "Selective failure".
//!
//! Rounds: `1 + 41n + 40 + 3 = 41n + 44`.

use super::key::{ArithMalKey, VerifyMask};
use crate::field::{mask_blocks, mask_value, Ext, Field};
use crate::leaf::{arith_leaf, fp_pre, fp_pre_cots, leaf_dabits, FpPre, Sub};
use crate::malicious::Fault;
use crate::semi_honest::gen::{precompute_counts, setup, walk, Pre, Setup, Walk};
use crate::{deal_walk, key_bytes, leaf_seed, mask_tweak, open_keys, sample_keys, MAL_KEYS};
use dpf_common::aes_tower::{bits_of, block_of, mmo_shared, Mmo, Shared128, ANDS_PER_CALL, ANDS_PER_KEY};
use dpf_common::block::{depth_for, Block};
use dpf_common::net::{Channel, CommStats};
use dpf_common::ot::FerretConfig;
use rand::{CryptoRng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use std::time::{Duration, Instant};

/// AES–MMO calls of one Gen: two per level, two for `F^pay` and two per
/// block of `F^mac`.
pub fn arith_mal_calls<F: Field, E: Ext<F>>(n: usize) -> usize {
    2 * n + 2 + 2 * mask_blocks::<F, E>()
}

/// ANDs of one Gen: the calls and Π_KeyExp of K, K', K''.
pub fn arith_mal_ands<F: Field, E: Ext<F>>(n: usize) -> usize {
    arith_mal_calls::<F, E>(n) * ANDS_PER_CALL + MAL_KEYS * ANDS_PER_KEY
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

    /// The OT tower's COTs for [`arith_mal_calls`] AES–MMO calls and three
    /// key expansions, n string triples (branch selection), n COTs per
    /// direction, and the leaf's daBits over F and Beaver triples over E
    /// ([`leaf_counts`]), the first one the Π_Verify mask `(r, δr)`.
    pub fn precompute(&mut self, ch: &mut Channel, n: usize) -> (Pre, FpPre<F, E>) {
        let s = &mut self.s;
        let (dabits, triples) = leaf_counts::<F, E>();
        let pre = precompute_counts(ch, &mut s.cot, arith_mal_calls::<F, E>(n), MAL_KEYS, n, n + fp_pre_cots::<F, E>(dabits, triples), &mut s.rng);
        let fpre = fp_pre(ch, &mut s.cot, dabits, triples, &[self.delta_mac], &mut s.rng);
        (pre, fpre)
    }

    /// One generation: XOR shares of α, additive shares of `β ∈ F`. Returns
    /// the key, the ANDs and this key's Π_Verify mask. A fault at level `n`
    /// hits the payload word, at `n + 1` the MAC word (its error read as an
    /// element of E), at `n + 2` the share of K opened.
    pub fn gen(
        &mut self,
        ch: &mut Channel,
        n_size: u64,
        alpha_share: u64,
        beta_share: F,
        pre: (Pre, FpPre<F, E>),
        fault: Option<Fault>,
    ) -> (ArithMalKey<F, E>, usize, VerifyMask<E>) {
        let b = ch.party();
        let n = depth_for(n_size);
        let err = |lvl: usize| match fault {
            Some(f) if f.level == lvl => E::from_u128(f.err.0),
            _ => E::ZERO,
        };
        let (Pre { mut be, string_triples }, mut fpre) = pre;
        let (r, _, dr) = fpre.triples.remove(0);
        let s = &mut self.s;
        let (ks, mut keys) = sample_keys(&mut s.rng, MAL_KEYS);
        let cw_err = fault.filter(|f| f.level < n).map(|f| (f.level, f.err));
        let Walk { root, st, cws, .. } = walk(&mut be, &string_triples, &mut keys, &mut s.cot, &mut s.rng, ch, n, alpha_share, &[], cw_err);

        // 2. Leaf masks, XOR-shared; the public tweaks are party 0's.
        let delta = s.cot.delta();
        let seeds = [leaf_seed(st), leaf_seed(st ^ delta)];
        let mb = mask_blocks::<F, E>();
        let tw = |j: usize| if b == 0 { mask_tweak(j) } else { Block::ZERO };
        let mut jobs: Vec<(usize, Shared128<bool>)> = seeds.iter().map(|&x| (1, bits_of(x))).collect();
        for x in seeds {
            jobs.extend((0..mb).map(|j| (2, bits_of(x ^ tw(j)))));
        }
        let w: Vec<Block> = mmo_shared(&mut be, ch, &mut keys, &jobs).iter().map(block_of).collect();

        // 3. The leaf: W_CW and W^MAC_CW, with the key reveal.
        let masks = [[vec![w[0]], vec![w[1]]], [w[2..2 + mb].to_vec(), w[2 + mb..].to_vec()]];
        let subs = [Sub::Share(E::embed(beta_share)), Sub::Product(self.delta_mac, E::embed(beta_share))];
        let mut ks = ks;
        ks[0] ^= fault.filter(|f| f.level == n + 2).map_or(Block::ZERO, |f| f.err);
        let (words, theirs) = arith_leaf(ch, &masks, &[1, E::DEG], &subs, st.lsb(), &mut fpre, &[err(n), err(n + 1)], &key_bytes(&ks));
        let [prf, pay, mac]: [Mmo; MAL_KEYS] = open_keys(&ks, &theirs).try_into().unwrap();
        let (w_cw, wm_cw) = (words[0].coord(0), words[1]);
        (ArithMalKey { party: b, n_size, prf, pay, mac, root, cws, w_cw, wm_cw }, be.ands, VerifyMask { r, dr })
    }
}

/// Everything one party gets from [`run_mal_arith`].
pub struct ArithMalRun<F: Field, E: Ext<F>> {
    pub key: ArithMalKey<F, E>,
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
    /// COTs consumed after setup (the OT tower's, α-bits, string triples,
    /// leaf OLEs).
    pub cots: usize,
}

/// Setup, preprocessing and generation for one party.
#[allow(clippy::too_many_arguments)]
pub fn run_mal_arith<F: Field, E: Ext<F>>(
    ch: &mut Channel,
    n_size: u64,
    alpha_share: u64,
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
    let pre_stats = ch.stats().since(&setup_stats);
    let pre_time = t_pre.elapsed();
    // Timing only: counted in no phase.
    ch.sync();
    let before = ch.stats();
    let t = Instant::now();
    let (key, ands, mask) = s.gen(ch, n_size, alpha_share, beta_share, pre, fault);
    ArithMalRun {
        key,
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

/// `F^mac(s)` in the clear: the [`mask_blocks`] blocks `H_{K''}(s ∥ 0 ⊕
/// tweak(j))` read as an element of E.
pub(crate) fn mac_mask<F: Field, E: Ext<F>>(mac: &Mmo, seed: Block) -> E {
    let blocks: Vec<Block> = (0..mask_blocks::<F, E>()).map(|j| mac.h(seed ^ mask_tweak(j))).collect();
    mask_value::<F, E>(&blocks)
}

/// Trusted-dealer generation for given roots (`lsb(root_b) = b`), AES keys
/// `[K, K', K'']` and payload-MAC key δ: the cleartext Gen and the oracle of
/// [`ArithMalSession::gen`].
pub fn deal<F: Field, E: Ext<F>>(
    roots: [Block; 2],
    keys: [[u8; 16]; MAL_KEYS],
    n_size: u64,
    alpha: u64,
    beta: F,
    delta_mac: E,
) -> [ArithMalKey<F, E>; 2] {
    assert!(alpha < n_size);
    let [prf, pay, mac] = keys.map(Mmo::new);
    let (cws, st) = deal_walk(&prf, roots, depth_for(n_size), alpha);
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
        cws: cws.clone(),
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
    let mut rng = ChaCha20Rng::from_seed(seed);
    let roots = [Block::random(&mut rng).with_lsb(false), Block::random(&mut rng).with_lsb(true)];
    let keys: [[u8; 16]; MAL_KEYS] = std::array::from_fn(|_| Block::random(&mut rng).to_bytes());
    let d = [E::random(&mut rng), E::random(&mut rng)];
    (deal(roots, keys, n_size, alpha, beta, d[0].add(d[1])), d)
}
