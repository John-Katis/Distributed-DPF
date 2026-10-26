//! Malicious generation with abort on the semi-honest preprocessing, with an
//! arithmetic payload: the paper's "Authenticated generation" for G = F_p.
//!
//! As [`crate::malicious`] (the binary instance), extended at the leaf with
//! the arithmetic steps of Figure "DPF.Gen":
//!
//! 1. A persistent payload-MAC key `δ = δ_0 + δ_1 ∈ F_p`, sampled once per
//!    session and never opened; Π_Verify opens the outputs before it uses δ,
//!    so δ only ever enters linearly.
//! 2. `F^pay`, `F^mac` on both leaf seeds (four MMO calls, 40 rounds), each
//!    read as the integer of its low κ bits mod p.
//! 3. The paper's arithmetic leaf ([`arith_leaf`], three rounds) on the two
//!    words `V = W_0 − W_1 − β` and `Ṽ = W̃_0 − W̃_1 − δβ`: B2A of the 4κ mask
//!    bits by daBits, `⟦δβ⟧` by a Beaver product (β is secret-shared), and
//!    the sign `(1 − 2t_{n,0})` by the tag's daBit and one triple per word;
//!    both words are opened together.
//!
//! The products in the AES calls, the branch selection and the leaf are the
//! semi-honest ones (plain FOLEAGE triples, daBits and triples from COTs);
//! every deviation shows up only in the published key material, which
//! Π_Verify ([`super::verify`]) checks at evaluation time, up to the
//! selective-failure leak of the paper's Proposition "Selective-failure
//! channel".
//!
//! Rounds: `1 + 41n + 40 + 3 = 41n + 44`.

use super::key::ArithMalKey;
use crate::field::Field;
use crate::leaf::{arith_leaf, fp_pre, fp_pre_cots, leaf_dabits, FpPre, Sub};
use crate::malicious::{mal_products, Fault};
use crate::semi_honest::gen::{precompute_counts, setup, walk, Pre, Setup};
use crate::{child, leaf_seed, mac_hash, pay_hash, state_hash};
use dpf_common::aes_tower::{bits_of, block_of, mmo_shared, Mmo, Shared128};
use dpf_common::block::{depth_for, Block};
use dpf_common::foleage::Params;
use dpf_common::net::{Channel, CommStats};
use dpf_common::ot::FerretConfig;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::time::{Duration, Instant};

/// Leaf correlations: daBits for two words, Beaver triples for the two signs
/// and `δβ`.
pub fn leaf_counts<F: Field>() -> (usize, usize) {
    (leaf_dabits::<F>(2), 3)
}

/// One party's long-lived state.
pub struct ArithMalSession<F: Field> {
    s: Setup,
    /// `δ_b`, this party's share of the persistent payload-MAC key.
    pub delta_mac: F,
}

impl<F: Field> ArithMalSession<F> {
    /// The semi-honest setup (base OTs, Ferret, FOLEAGE seed generation) and δ_b.
    pub fn setup(ch: &mut Channel, seed: [u8; 32], ferret: Option<FerretConfig>, foleage: Params) -> Self {
        let mut s = setup(ch, seed, ferret, foleage);
        let delta_mac = F::random(&mut s.rng);
        ArithMalSession { s, delta_mac }
    }

    /// FOLEAGE expansion into [`mal_products`] triples, n string triples
    /// (branch selection), n COTs per direction, and the leaf's daBits and
    /// Beaver triples over F_p ([`leaf_counts`]).
    pub fn precompute(&mut self, ch: &mut Channel, n: usize) -> (Pre, FpPre<F>) {
        assert!(2 * mal_products(n) <= self.s.fseed.params.oles(), "FOLEAGE instance too small for depth {n}");
        let s = &mut self.s;
        let (dabits, triples) = leaf_counts::<F>();
        let pre = precompute_counts(ch, &mut s.cot, &s.fseed, mal_products(n), n, n + fp_pre_cots::<F>(dabits, triples), &mut s.rng);
        let fpre = fp_pre(ch, &mut s.cot, dabits, triples, &mut s.rng);
        (pre, fpre)
    }

    /// One generation: XOR shares of α, additive shares of `β ∈ F_p`. A
    /// fault at level `n` hits the payload word, at `n + 1` the MAC word (its
    /// error read as an element of F_p).
    pub fn gen(&mut self, ch: &mut Channel, n_size: u64, alpha_share: u64, beta_share: F, pre: (Pre, FpPre<F>), fault: Option<Fault>) -> (ArithMalKey<F>, usize) {
        let b = ch.party();
        let n = depth_for(n_size);
        let err = |lvl: usize| match fault {
            Some(f) if f.level == lvl => F::from_u128(f.err.0),
            _ => F::ZERO,
        };
        let (Pre { mut be, string_triples }, mut fpre) = pre;
        let s = &mut self.s;
        let cw_err = fault.filter(|f| f.level < n).map(|f| (f.level, f.err));
        let (st, cws, _) = walk(&mut be, &string_triples, &mut s.cot, &mut s.rng, ch, n, alpha_share, &[], cw_err);

        // 2. Leaf masks, XOR-shared.
        let delta = s.cot.delta();
        let (s0, s1) = (bits_of(leaf_seed(st)), bits_of(leaf_seed(st ^ delta)));
        let (fp, fm): (&Mmo, &Mmo) = (pay_hash(), mac_hash());
        let jobs: [(&Mmo, Shared128<bool>); 4] = [(fp, s0), (fp, s1), (fm, s0), (fm, s1)];
        let w: Vec<Block> = mmo_shared(&mut be, ch, &jobs).iter().map(block_of).collect();

        // 3. The leaf: W_CW and W^MAC_CW.
        let masks = [[w[0], w[1]], [w[2], w[3]]];
        let subs = [Sub::Share(beta_share), Sub::Product(self.delta_mac, beta_share)];
        let words = arith_leaf(ch, &masks, &subs, st.lsb(), &mut fpre, &[err(n), err(n + 1)]);
        let (w_cw, wm_cw) = (words[0], words[1]);
        let products = be.products;
        (ArithMalKey { party: b, n_size, root: delta, cws, w_cw, wm_cw }, products)
    }
}

/// Everything one party gets from [`run_mal_arith`].
pub struct ArithMalRun<F: Field> {
    pub key: ArithMalKey<F>,
    /// This party's share of the payload-MAC key δ.
    pub delta_share: F,
    /// Base OTs, Ferret bootstrap and the FOLEAGE seed generation.
    pub setup_stats: CommStats,
    pub setup_time: Duration,
    pub pre_stats: CommStats,
    pub pre_time: Duration,
    pub gen_stats: CommStats,
    pub gen_time: Duration,
    pub products: usize,
    /// COTs consumed after setup (α-bits, string triples, leaf OLEs).
    pub cots: usize,
    pub foleage: Params,
    pub seedgen_stats: CommStats,
    pub seedgen_time: Duration,
}

/// Setup, preprocessing and generation for one party. `foleage`: at least
/// [`crate::malicious::mal_foleage_for`]`(n)`.
#[allow(clippy::too_many_arguments)]
pub fn run_mal_arith<F: Field>(ch: &mut Channel, n_size: u64, alpha_share: u64, beta_share: F, seed: [u8; 32], ferret: Option<FerretConfig>, foleage: Params, fault: Option<Fault>) -> ArithMalRun<F> {
    let mut s = ArithMalSession::<F>::setup(ch, seed, ferret, foleage);
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
    let (key, products) = s.gen(ch, n_size, alpha_share, beta_share, pre, fault);
    ArithMalRun {
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
        foleage,
        seedgen_stats: s.s.seedgen_stats,
        seedgen_time: s.s.seedgen_time,
    }
}

/// Trusted-dealer generation for given roots (`lsb(root_b) = b`) and
/// payload-MAC key δ: the cleartext Gen and the oracle of [`ArithMalSession::gen`].
pub fn deal<F: Field>(roots: [Block; 2], n_size: u64, alpha: u64, beta: F, delta_mac: F) -> [ArithMalKey<F>; 2] {
    assert!(alpha < n_size);
    assert!(!roots[0].lsb() && roots[1].lsb(), "lsb(root_b) = b");
    let n = depth_for(n_size);
    let delta = roots[0] ^ roots[1];
    let mut st = roots;
    let mut cws = Vec::with_capacity(n);
    for i in 0..n {
        let a = (alpha >> (n - 1 - i)) & 1 == 1;
        let cw = state_hash().h(st[0]) ^ state_hash().h(st[1]) ^ delta.and_bit(!a);
        st = [child(st[0], cw, a), child(st[1], cw, a)];
        cws.push(cw);
    }
    let s = [leaf_seed(st[0]), leaf_seed(st[1])];
    let f = |h: &Mmo, x: Block| F::from_block(h.h(x));
    let v = f(pay_hash(), s[0]).sub(f(pay_hash(), s[1])).sub(beta);
    let vm = f(mac_hash(), s[0]).sub(f(mac_hash(), s[1])).sub(delta_mac.mul(beta));
    let sign = |x: F| if st[0].lsb() { x.neg() } else { x };
    let (w_cw, wm_cw) = (sign(v), sign(vm));
    let mk = |party: usize| ArithMalKey { party, n_size, root: roots[party], cws: cws.clone(), w_cw, wm_cw };
    [mk(0), mk(1)]
}

/// Dealer keys from a seed, with the δ shares.
pub fn gen_reference<F: Field>(n_size: u64, alpha: u64, beta: F, seed: [u8; 32]) -> ([ArithMalKey<F>; 2], [F; 2]) {
    let mut rng = ChaCha20Rng::from_seed(seed);
    let roots = [Block::random(&mut rng).with_lsb(false), Block::random(&mut rng).with_lsb(true)];
    let d = [F::random(&mut rng), F::random(&mut rng)];
    (deal(roots, n_size, alpha, beta, d[0].add(d[1])), d)
}
