//! Malicious generation with abort, arithmetic payload: Figure `Π_GenMal` of the
//! paper for a payload field F (Babybear) and a MAC field E ⊇ F (`F_{q^4}`), on
//! the semi-honest Gen of [`crate::semi_honest::gen`] in its session, with
//!
//! * Setup: the persistent payload-MAC key `⟦δ⟧`, δ ∈ E, never opened.
//! * (A) The leaf MAC. The leaf hash has `τ = ⌈(d + 1)κ/λ⌉` blocks
//!   ([`crate::field::tau`]): the first is `L^b_{n+1}` and each further one its
//!   own pair `(X^{j,0}, X^{j,1})`, joined to the leaf states by the public `C^j
//!   = Δ ⊕ X^{j,0} ⊕ X^{j,1}` and `N^j = u^0_n ⊕ X^{j,0} ⊕ r_n·(C_n ⊕ C^j)`.
//!   `W_CW` and `W^MAC_CW` come from one vector `𝓕_Mul(1 − 2σ, ·)`
//!   ([`mal_pair_leaf`]).
//! * (B) The glue residual `⟦ω⟧` over `𝔽' = F_{2^127−1}` ([`glue_residual`]),
//!   kept with the key and checked by Π_Verify.
//!
//! κ is [`Field::MAL_KAPPA`], `ℓ_q + 40` as in the figure, so a mask over
//! `2^127 − 1` takes 167 bits and spans two blocks, and τ = 3.
//!
//! Nothing in Gen is checked; every deviation shows up only in the outputs or in
//! ω, which Π_Verify ([`crate::verify`]) checks after evaluation. (A) and (B)
//! add no rounds to the semi-honest Gen: the leaf runs on its lane in rounds
//! 21–23 and the residual takes the two rounds after the glue. Rounds: `max(ν +
//! 3, 23)`.

use super::key::ArithMalKey;
use crate::field::{mac_mask, mask_at, tau, Ext, Field, M127};
use crate::leaf::{fp_pre, fp_pre_cots, glue_residual, mal_leaf_dabits, mal_pair_leaf, vec_triple, vec_triple_cots, FpPre, Triple, VecTriple, RESIDUAL_DABITS};
use crate::semi_honest::gen::{drive, reference_params, setup, walk_pairs, Fault, GenOutput, PairPre, PairWalk, PreSpec, Setup, Word};
use crate::verify::VerifyMask;
use crate::{deal_leaf_words, deal_pairs, default_nu_mal_arith, mal_ands};
use dpf_common::aes_tower::Mmo;
use dpf_common::block::{depth_for, Block};
use dpf_common::net::{Channel, CommStats};
use dpf_common::ot::FerretConfig;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::time::Duration;

/// Calls of `𝓕_PRFPair` of one Gen.
pub fn arith_mal_calls<F: Field, E: Ext<F>>(n: usize, nu: usize) -> usize {
    crate::mal_calls(n, nu, tau::<F, E>())
}

/// ANDs of one Gen.
pub fn arith_mal_ands<F: Field, E: Ext<F>>(n: usize, nu: usize) -> usize {
    mal_ands(n, nu, tau::<F, E>())
}

/// One party's long-lived state.
pub struct ArithMalSession<F: Field, E: Ext<F>> {
    s: Setup,
    /// `δ_b`, this party's share of the persistent payload-MAC key.
    pub delta_mac: E,
    _f: std::marker::PhantomData<F>,
}

/// The field correlations of one Gen and its Π_Verify.
struct Correlations<F: Field, E: Ext<F>> {
    /// The leaf's daBits over F, then over E the mask `(ρ, δρ)` and the triple
    /// that masks μ.
    fpre: FpPre<F, E>,
    leaf: VecTriple<F, E>,
    /// The residual's daBits, its two squares and the triple that masks μ′.
    glue: FpPre<M127, M127>,
}

/// What a Gen leaves besides the key.
struct Extras<E> {
    mask: VerifyMask<E>,
    glue: Triple<M127>,
    omega: M127,
}

/// Everything one party gets from a Gen.
pub struct ArithMalRun<F: Field, E: Ext<F>> {
    pub key: ArithMalKey<F, E>,
    /// This party's XOR share of the random index α.
    pub alpha_share: u64,
    /// This party's XOR shares of the pair inputs: `[X^0_ℓ, X^1_ℓ]`, `ν ≤ ℓ ≤ n`,
    /// then `[X^{j,0}, X^{j,1}]`, `2 ≤ j ≤ τ`.
    pub pairs: Vec<[Block; 2]>,
    /// This party's XOR shares of the bits `r_ν, …, r_n`.
    pub rs: Vec<bool>,
    /// This party's share of the payload-MAC key δ.
    pub delta_share: E,
    /// This party's share of the key's Π_Verify mask.
    pub mask: VerifyMask<E>,
    /// This party's share of the triple that masks μ′ in Π_Verify.
    pub glue_triple: Triple<M127>,
    /// This party's share of the key's glue residual ω.
    pub omega: M127,
    /// Base OTs and the Ferret bootstrap.
    pub setup_stats: CommStats,
    pub setup_time: Duration,
    pub pre_stats: CommStats,
    pub pre_time: Duration,
    pub gen_stats: CommStats,
    pub gen_time: Duration,
    /// ANDs of the AES calls.
    pub ands: usize,
    /// COTs consumed after setup.
    pub cots: usize,
}

impl<F: Field, E: Ext<F>> ArithMalSession<F, E> {
    /// Π_setup (base OTs, Ferret, ⟨Δ⟩, K) and δ_b.
    pub fn setup(ch: &mut Channel, seed: [u8; 32], ferret: Option<FerretConfig>) -> Self {
        let mut s = setup(ch, seed, ferret);
        let delta_mac = E::random(&mut s.rng);
        ArithMalSession { s, delta_mac, _f: std::marker::PhantomData }
    }

    /// Preprocessing and one generation of a key for a random α and the public
    /// `β ∈ F`, glue level `nu ≥ 1` ([`default_nu_mal_arith`] if `None`), with
    /// the deviation `fault` of this party.
    pub fn gen(&mut self, ch: &mut Channel, n_size: u64, nu: Option<usize>, beta: F, fault: Option<Fault>) -> ArithMalRun<F, E> {
        let n = depth_for(n_size);
        let delta_mac = self.delta_mac;
        let dabits = mal_leaf_dabits::<F>(E::DEG);
        let spec = PreSpec {
            binary: false,
            cots: fp_pre_cots::<F, E>(dabits, 2) + vec_triple_cots::<F>() + fp_pre_cots::<M127, M127>(RESIDUAL_DABITS, 3),
            leaf_pairs: tau::<F, E>() - 1,
            flip_alpha: match fault {
                Some(Fault::Alpha(i)) => Some(i),
                _ => None,
            },
        };
        let out = drive(
            ch,
            &mut self.s,
            n,
            nu.unwrap_or(default_nu_mal_arith(n)),
            spec,
            |cot, rng, ch| Correlations {
                fpre: fp_pre::<F, E, _>(ch, cot, dabits, 2, &[delta_mac], rng),
                leaf: vec_triple(ch, cot, rng),
                glue: fp_pre::<M127, M127, _>(ch, cot, RESIDUAL_DABITS, 3, &[], rng),
            },
            |pre, corr, ch| body(pre, corr, ch, n_size, beta, delta_mac, fault),
        );
        let GenOutput { key: (key, x), alpha_share, pairs, rs, setup_stats, pre_stats, gen_stats, setup_time, pre_time, gen_time, ands, cots } = out;
        ArithMalRun { key, alpha_share, pairs, rs, delta_share: delta_mac, mask: x.mask, glue_triple: x.glue, omega: x.omega, setup_stats, setup_time, pre_stats, pre_time, gen_stats, gen_time, ands, cots }
    }
}

#[allow(clippy::type_complexity)]
fn body<F: Field, E: Ext<F>>(
    mut pre: PairPre,
    corr: Correlations<F, E>,
    ch: &mut Channel,
    n_size: u64,
    beta: F,
    delta_mac: E,
    fault: Option<Fault>,
) -> ((ArithMalKey<F, E>, Extras<E>), usize, Vec<[Block; 2]>) {
    let b = ch.party();
    let Correlations { fpre, leaf, glue } = corr;
    let FpPre { dabits, triples } = fpre;
    let mask = VerifyMask { r: triples[0].0, dr: triples[0].2, blind: triples[1] };
    let FpPre { dabits: gd, triples: gt } = glue;
    let PairWalk { cws, bottom, hs, xs, leaf_words, leaf_hs, mut leaf_lane, glue: a, frontier, mut glue_lane } = walk_pairs(&mut pre, ch, fault, true);

    // (A) The leaf words, on the hashes of the two servers' leaf states.
    let side = |s: usize| -> Vec<Block> { std::iter::once(hs[s]).chain(leaf_hs.iter().map(|x| x[s])).collect() };
    let (h0, h1) = (side(0), side(1));
    let sigma = *pre.rs.last().unwrap() ^ matches!(fault, Some(Fault::Sigma));
    let err = (F::from_u128(Fault::at(fault, Word::Payload).0), E::from_u128(Fault::at(fault, Word::Mac).0));
    let (w_cw, wm_cw) = mal_pair_leaf(ch, &mut leaf_lane, [&h0, &h1], sigma, beta, delta_mac, &dabits, leaf, err);

    // (B) The glue residual, in the two rounds after the glue.
    let omega = glue_residual(ch, &mut glue_lane, a, pre.delta, &frontier, &gd, &gt[..2]).add(M127::from_u128(Fault::at(fault, Word::Omega).0));
    ch.join(leaf_lane);
    ch.join(glue_lane);

    let root = pre.root();
    let key = ArithMalKey { party: b, n_size, prf: pre.key, root, cws, bottom, leaf_words, w_cw, wm_cw };
    ((key, Extras { mask, glue: gt[2], omega }), pre.be.ands, xs)
}

/// One session setup and one [`ArithMalSession::gen`].
pub fn run_mal_arith<F: Field, E: Ext<F>>(
    ch: &mut Channel,
    n_size: u64,
    nu: Option<usize>,
    beta: F,
    seed: [u8; 32],
    ferret: Option<FerretConfig>,
    fault: Option<Fault>,
) -> ArithMalRun<F, E> {
    ArithMalSession::<F, E>::setup(ch, seed, ferret).gen(ch, n_size, nu, beta, fault)
}

/// Trusted-dealer generation for given roots, K, glue level ν ≥ 1, pair inputs
/// and bits of levels ν..=n, the leaf pairs `[X^{j,0}, X^{j,1}]` and δ: the
/// cleartext Gen and the bit-exact oracle of [`ArithMalSession::gen`] (whose glue
/// residual is a sharing of 0).
#[allow(clippy::too_many_arguments)]
pub fn deal<F: Field, E: Ext<F>>(
    roots: [Block; 2],
    key: [u8; 16],
    n_size: u64,
    nu: usize,
    alpha: u64,
    beta: F,
    delta_mac: E,
    pairs: &[[Block; 2]],
    leaf_pairs: &[[Block; 2]],
    rs: &[bool],
) -> [ArithMalKey<F, E>; 2] {
    assert_eq!(leaf_pairs.len(), tau::<F, E>() - 1, "τ − 1 leaf pairs");
    let prf = Mmo::new(key);
    let (cws, bottom, h) = deal_pairs(&prf, roots, depth_for(n_size), nu, alpha, pairs, rs, false);
    let r_n = *rs.last().unwrap();
    let un0 = pairs.last().unwrap()[0].with_lsb(r_n);
    let leaf_words = deal_leaf_words(roots[0] ^ roots[1], un0, *bottom.c.last().unwrap(), r_n, leaf_pairs);
    let side = |s: usize| -> Vec<Block> { std::iter::once(h[s]).chain(leaf_pairs.iter().map(|p| prf.h(p[s]))).collect() };
    let (h0, h1) = (side(0), side(1));
    let v = mask_at::<F>(&h0, 0).sub(mask_at::<F>(&h1, 0)).sub(beta);
    let vm = mac_mask::<F, E>(&h0).sub(mac_mask::<F, E>(&h1)).sub(delta_mac.mul(E::embed(beta)));
    let (w_cw, wm_cw) = if r_n { (v.neg(), vm.neg()) } else { (v, vm) };
    let mk = |party: usize| ArithMalKey { party, n_size, prf: prf.clone(), root: roots[party], cws: cws.clone(), bottom: bottom.clone(), leaf_words: leaf_words.clone(), w_cw, wm_cw };
    [mk(0), mk(1)]
}

/// Dealer keys from a seed, with the δ shares.
pub fn gen_reference<F: Field, E: Ext<F>>(n_size: u64, alpha: u64, beta: F, seed: [u8; 32]) -> ([ArithMalKey<F, E>; 2], [E; 2]) {
    assert!(alpha < n_size);
    let mut rng = ChaCha20Rng::from_seed(seed);
    let (roots, key, nu, pairs, rs) = reference_params(n_size, &mut rng);
    let leaf_pairs: Vec<[Block; 2]> = (1..tau::<F, E>()).map(|_| [Block::random(&mut rng), Block::random(&mut rng)]).collect();
    let d = [E::random(&mut rng), E::random(&mut rng)];
    (deal(roots, key, n_size, nu, alpha, beta, d[0].add(d[1]), &pairs, &leaf_pairs, &rs), d)
}
