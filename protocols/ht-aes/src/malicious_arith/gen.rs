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
//! 3. One batch of COT OLEs ([`ole`], two rounds): the B2A of those 4κ bits
//!    (`⟨h⟩ = h_b − 2h_0h_1`, the cross term from one OLE per bit), and the
//!    cross terms of `⟨δβ⟩ = δ_b·β_b + δ_0·β_1 + δ_1·β_0` (Gilboa, one OLE per
//!    bit of `β_b`).
//! 4. `V = W_0 − W_1 − β`, `Ṽ = W̃_0 − W̃_1 − δβ`, and the sign
//!    `(1 − 2σ)·V`, `(1 − 2σ)·Ṽ` for `σ = t_{n,0}` from two more OLEs
//!    (`σ·D = σ_0D_0 + σ_1D_1 + σ_1(1 − 2σ_0)D_0 + σ_0(1 − 2σ_1)D_1`, two
//!    rounds).
//! 5. Both words opened together.
//!
//! The products in the AES calls, the branch selection and the OLEs are the
//! semi-honest ones; every deviation shows up only in the published key
//! material, which Π_Verify ([`super::verify`]) checks at evaluation time.
//!
//! Rounds: `1 + 41n + 40 + 2 + 2 + 1 = 41n + 46`.

use super::key::ArithMalKey;
use crate::field::{ole, Field};
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

/// COT OLEs per direction at the leaf: the B2A of the four masks, the bits of
/// `β_b` for `δβ`, the two signs.
pub fn leaf_oles<F: Field>() -> usize {
    4 * F::KAPPA + F::P_BITS + 2
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
    /// (branch selection) and `n + `[`leaf_oles`] COTs per direction.
    pub fn precompute(&mut self, ch: &mut Channel, n: usize) -> Pre {
        assert!(2 * mal_products(n) <= self.s.fseed.params.oles(), "FOLEAGE instance too small for depth {n}");
        let s = &mut self.s;
        precompute_counts(ch, &mut s.cot, &s.fseed, mal_products(n), n, n + leaf_oles::<F>(), &mut s.rng)
    }

    /// One generation: XOR shares of α, additive shares of `β ∈ F_p`. A
    /// fault at level `n` hits the payload word, at `n + 1` the MAC word (its
    /// error read as an element of F_p).
    pub fn gen(&mut self, ch: &mut Channel, n_size: u64, alpha_share: u64, beta_share: F, pre: Pre, fault: Option<Fault>) -> (ArithMalKey<F>, usize) {
        let b = ch.party();
        let n = depth_for(n_size);
        let err = |lvl: usize| match fault {
            Some(f) if f.level == lvl => F::from_u128(f.err.0),
            _ => F::ZERO,
        };
        let Pre { mut be, string_triples } = pre;
        let s = &mut self.s;
        let cw_err = fault.filter(|f| f.level < n).map(|f| (f.level, f.err));
        let (st, cws, _) = walk(&mut be, &string_triples, &mut s.cot, &mut s.rng, ch, n, alpha_share, &[], cw_err);

        // 2. Leaf masks, XOR-shared.
        let delta = s.cot.delta();
        let (s0, s1) = (bits_of(leaf_seed(st)), bits_of(leaf_seed(st ^ delta)));
        let (fp, fm): (&Mmo, &Mmo) = (pay_hash(), mac_hash());
        let jobs: [(&Mmo, Shared128<bool>); 4] = [(fp, s0), (fp, s1), (fm, s0), (fm, s1)];
        let w: Vec<Block> = mmo_shared(&mut be, ch, &jobs).iter().map(block_of).collect();

        // 3. B2A of the masks and the cross terms of δβ, in one OLE batch.
        let kappa = F::KAPPA;
        let pow2: Vec<F> = (0..kappa.max(F::P_BITS)).map(F::pow2).collect();
        let beta_int = beta_share.to_u128();
        let mut g = Vec::with_capacity(leaf_oles::<F>() - 2);
        let mut c = Vec::with_capacity(g.capacity());
        for wj in &w {
            for k in 0..kappa {
                let h = wj.bit(k);
                g.push(h);
                c.push(if h { pow2[k] } else { F::ZERO });
            }
        }
        for k in 0..F::P_BITS {
            g.push((beta_int >> k) & 1 == 1);
            c.push(self.delta_mac.mul(pow2[k]));
        }
        let z = ole(ch, &mut s.cot, &g, &c, &mut s.rng);
        let masks: Vec<F> = (0..4).map(|j| (0..kappa).fold(F::ZERO, |acc, k| acc.add(c[j * kappa + k]).sub(z[j * kappa + k]))).collect();
        let db = z[4 * kappa..].iter().fold(self.delta_mac.mul(beta_share), |acc, &x| acc.add(x));

        // 4. V, Ṽ and their signs.
        let v = [masks[0].sub(masks[1]).sub(beta_share), masks[2].sub(masks[3]).sub(db)];
        let t = st.lsb();
        let corr: Vec<F> = v.iter().map(|&d| if t { d.neg() } else { d }).collect();
        let z = ole(ch, &mut s.cot, &[t, t], &corr, &mut s.rng);
        let signed: Vec<F> = (0..2).map(|i| {
            let sd = (if t { v[i] } else { F::ZERO }).add(z[i]); // ⟨σ·D⟩
            v[i].sub(sd.add(sd))
        }).collect();

        // 5. Open both words.
        let mine = [signed[0].add(err(n)), signed[1].add(err(n + 1))];
        let mut msg = Vec::with_capacity(2 * F::BYTES);
        mine.iter().for_each(|x| x.put(&mut msg));
        ch.send(msg);
        let theirs = ch.recv();
        assert_eq!(theirs.len(), 2 * F::BYTES, "malformed payload words");
        let w_cw = mine[0].add(F::get(&theirs[..F::BYTES]));
        let wm_cw = mine[1].add(F::get(&theirs[F::BYTES..]));
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
