//! The malicious Gen with an arithmetic payload: correctness against the
//! dealer, Π_Verify, that deviations in Gen are caught by Π_Verify (the swap
//! of the glue through the glue residual ω), and that a flipped share of α is
//! a consistent choice of α*. The paper's fields (Babybear payload, MAC in
//! F_{q^4}) and, for wider payloads, Goldilocks and 2^127 − 1 in both roles.

use dpf_common::block::Block;
use dpf_common::coin::Abort;
use dpf_common::net::run_two_party;
use ht_aes::field::{tau, BabyBear, BabyBear4, Ext, Field, Gold, M127};
use ht_aes::leaf::Triple;
use ht_aes::malicious::{Fault, Word};
use ht_aes::malicious_arith::{
    arith_mal_ands, deal, deal_mask, deal_triple, gen_reference, open_checked, run_mal_arith, verify, ArithMalKey, ArithMalRun, VerifyMask,
};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;

/// One Gen of a key for the public β (α is sampled in preprocessing: α_0 ⊕ α_1).
fn run<F: Field, E: Ext<F>>(n: u64, nu: Option<usize>, beta: F, seed: u64, faults: [Option<Fault>; 2]) -> [ArithMalRun<F, E>; 2] {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let seeds: [[u8; 32]; 2] = [rng.gen(), rng.gen()];
    let (r0, r1) = run_two_party(
        move |c| run_mal_arith::<F, E>(c, n, nu, beta, seeds[0], None, faults[0]),
        move |c| run_mal_arith::<F, E>(c, n, nu, beta, seeds[1], None, faults[1]),
    );
    [r0, r1]
}

/// The keys, δ shares, masks, the triples that mask μ′ and the glue residuals of a run.
#[derive(Clone)]
struct Parts<F: Field, E: Ext<F>> {
    keys: [ArithMalKey<F, E>; 2],
    d: [E; 2],
    masks: [VerifyMask<E>; 2],
    glue: [Triple<M127>; 2],
    omegas: [M127; 2],
}

fn parts<F: Field, E: Ext<F>>(r: [ArithMalRun<F, E>; 2]) -> Parts<F, E> {
    let [r0, r1] = r;
    Parts { d: [r0.delta_share, r1.delta_share], masks: [r0.mask, r1.mask], glue: [r0.glue_triple, r1.glue_triple], omegas: [r0.omega, r1.omega], keys: [r0.key, r1.key] }
}

/// Where a party falsifies its output share: in Π_Verify, or only when the
/// outputs are opened after it.
#[derive(Clone, Copy, PartialEq)]
enum Tamper {
    No,
    Verify,
    Open,
}

/// Evaluates both keys at xs and runs the output pipeline (Π_Verify, then the
/// checked opening); returns each party's result.
fn eval_and_verify<F: Field, E: Ext<F>>(p: &Parts<F, E>, xs: Vec<u64>, tamper: Tamper) -> [Result<Vec<F>, Abort>; 2] {
    let party = |b: usize| {
        let outs: Vec<(F, E)> = xs.iter().map(|&x| p.keys[b].eval_point(x)).collect();
        let (d, mask, glue, omega) = (p.d[b], p.masks[b], p.glue[b], p.omegas[b]);
        move |c: &mut dpf_common::net::Channel| {
            let mut rng = ChaCha20Rng::seed_from_u64(b as u64);
            let mut bad = outs.clone();
            bad[0].0 = bad[0].0.add(F::ONE);
            let pick = |t: Tamper| if b == 1 && tamper == t { &bad } else { &outs };
            verify(c, pick(Tamper::Verify), &[omega], d, mask, glue, &mut rng)?;
            open_checked(c, pick(Tamper::Open), d, &mut rng)
        }
    };
    let (a, b) = run_two_party(party(0), party(1));
    [a, b]
}

/// The XOR of two parties' pair shares.
fn xor_pairs(a: &[[Block; 2]], b: &[[Block; 2]]) -> Vec<[Block; 2]> {
    a.iter().zip(b).map(|(x, y)| [x[0] ^ y[0], x[1] ^ y[1]]).collect()
}

fn gen_matches_dealer_and_verifies<F: Field, E: Ext<F>>(seed: u64) {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    for (i, (n, nu)) in [(2u64, None), (8, None), (13, Some(1)), (16, Some(2)), (16, Some(4)), (1 << 9, Some(5)), (1 << 24, Some(21))].into_iter().enumerate() {
        let beta = F::random(&mut rng);
        let [r0, r1] = run::<F, E>(n, nu, beta, seed + i as u64, [None, None]);
        let alpha = r0.alpha_share ^ r1.alpha_share;
        let (depth, nu) = (r0.key.depth(), r0.key.nu());
        assert!(nu >= 1);
        // As the semi-honest Gen: (A) and (B) add no rounds.
        assert_eq!(r0.gen_stats.rounds.max(r1.gen_stats.rounds), (nu + 3).max(23), "n={depth} ν={nu}");
        assert_eq!(r0.ands, arith_mal_ands::<F, E>(depth, nu));
        let delta = r0.delta_share.add(r1.delta_share);
        let levels = depth - nu + 1;
        let pairs = xor_pairs(&r0.pairs, &r1.pairs);
        assert_eq!(pairs.len(), levels + tau::<F, E>() - 1);
        let rs: Vec<bool> = r0.rs.iter().zip(&r1.rs).map(|(&a, &b)| a ^ b).collect();
        let dealt = deal([r0.key.root, r1.key.root], r0.key.prf.key(), n, nu, alpha, beta, delta, &pairs[..levels], &pairs[levels..], &rs);
        assert_eq!(dealt, [r0.key.clone(), r1.key.clone()]);
        assert_eq!(r0.omega.add(r1.omega), M127::ZERO, "ω = 0 in an honest run");
        if depth > 12 {
            continue; // a large glue level: only Gen and its rounds
        }
        let xs: Vec<u64> = (0..n).collect();
        let p = parts([r0, r1]);
        let [a, b] = eval_and_verify(&p, xs.clone(), Tamper::No);
        let ys = a.unwrap();
        assert_eq!(b.unwrap(), ys, "both parties open the same outputs");
        for x in 0..n {
            assert_eq!(ys[x as usize], if x == alpha { beta } else { F::ZERO });
        }
        // A falsified output share is caught.
        let [a, b] = eval_and_verify(&p, xs.clone(), Tamper::Verify);
        assert!(a.is_err() && b.is_err());
        // A share falsified only at the opening is caught too.
        let [a, b] = eval_and_verify(&p, xs, Tamper::Open);
        assert_eq!(a.err(), Some(Abort("opened output MAC check failed")));
        assert_eq!(b.err(), Some(Abort("opened output MAC check failed")));
    }
}

#[test]
fn mal_arith_gen_matches_dealer_and_verifies_babybear() {
    gen_matches_dealer_and_verifies::<BabyBear, BabyBear4>(21);
}

#[test]
fn mal_arith_gen_matches_dealer_and_verifies_gold() {
    gen_matches_dealer_and_verifies::<Gold, Gold>(1);
}

#[test]
fn mal_arith_gen_matches_dealer_and_verifies_m127() {
    gen_matches_dealer_and_verifies::<M127, M127>(11);
}

/// Every public word of Gen at depth 4 with ν = 2 and τ = 3.
fn word_faults(rng: &mut ChaCha20Rng) -> Vec<Fault> {
    let mut w: Vec<Word> = (0..4).map(Word::Cw).collect();
    w.extend([Word::Payload, Word::Mac, Word::Omega, Word::LeafC(0), Word::LeafC(1), Word::LeafN(0), Word::LeafN(1)]);
    w.extend((0..3).flat_map(|j| [Word::M0(j), Word::C(j), Word::BTau(j, 0), Word::BTau(j, 1)]));
    w.into_iter().map(|word| Fault::Word(word, Block(1 << rng.gen_range(1..16)).with_lsb(matches!(word, Word::BTau(..))))).collect()
}

/// A wrong share of any public word in Gen, the swap of the glue or a flipped
/// σ: Gen completes, and Π_Verify over the whole domain aborts.
#[test]
fn faults_in_gen_are_caught_by_verify() {
    let mut rng = ChaCha20Rng::seed_from_u64(2);
    let n = 16u64;
    let mut faults = word_faults(&mut rng);
    faults.extend([Fault::Swap, Fault::Sigma]);
    for (i, fault) in faults.into_iter().enumerate() {
        for cheater in [0, 1] {
            let mut f = [None, None];
            f[cheater] = Some(fault);
            let p = parts(run::<BabyBear, BabyBear4>(n, Some(2), BabyBear(77), 10 + i as u64, f));
            let [a, b] = eval_and_verify(&p, (0..n).collect(), Tamper::No);
            assert_eq!(a.err(), Some(Abort("output MAC check failed")), "{fault:?} cheater {cheater}");
            assert_eq!(b.err(), Some(Abort("output MAC check failed")), "{fault:?} cheater {cheater}");
        }
    }
}

/// The swap negates every output and its MAC, which no MAC check sees: only
/// the glue residual catches it. Without ω, Π_Verify accepts the outputs −f.
#[test]
fn swap_is_caught_only_by_the_glue_residual() {
    let n = 1u64 << 6;
    let beta = BabyBear(1234);
    for cheater in [0, 1] {
        let mut f = [None, None];
        f[cheater] = Some(Fault::Swap);
        let p = parts(run::<BabyBear, BabyBear4>(n, Some(3), beta, 60 + cheater as u64, f));
        assert_ne!(p.omegas[0].add(p.omegas[1]), M127::ZERO, "ω ≠ 0 after a swap");
        let mut blind = p.clone();
        blind.omegas = [M127::ZERO; 2];
        let [a, _] = eval_and_verify(&blind, (0..n).collect(), Tamper::No);
        let ys = a.expect("the MAC alone accepts the swapped outputs");
        assert_eq!(ys.iter().filter(|y| **y != BabyBear::ZERO).count(), 1);
        assert!(ys.contains(&beta.neg()), "the output at α is negated");
        let [a, b] = eval_and_verify(&p, (0..n).collect(), Tamper::No);
        assert!(a.is_err() && b.is_err());
    }
}

/// A flipped σ gives outputs that are consistently wrong, so its MAC check is
/// what catches it: the check rejects even though ω = 0.
#[test]
fn flipped_sigma_fails_the_mac() {
    let n = 1u64 << 6;
    for cheater in [0, 1] {
        let mut f = [None, None];
        f[cheater] = Some(Fault::Sigma);
        let p = parts(run::<BabyBear, BabyBear4>(n, Some(3), BabyBear(5), 80 + cheater as u64, f));
        assert_eq!(p.omegas[0].add(p.omegas[1]), M127::ZERO, "the glue is intact");
        let [a, b] = eval_and_verify(&p, (0..n).collect(), Tamper::No);
        assert_eq!(a.err(), Some(Abort("output MAC check failed")));
        assert_eq!(b.err(), Some(Abort("output MAC check failed")));
    }
}

/// A flipped share of α_ℓ into its one product (𝓕_COT above ν, Step A below):
/// the keys are honest keys for α* = α ⊕ e_ℓ, ω = 0, and Π_Verify accepts.
#[test]
fn flipped_alpha_share_is_a_consistent_alpha_star() {
    let n = 1u64 << 6;
    let depth = 6;
    for (i, level) in [1usize, 4].into_iter().enumerate() {
        let mut f = [None, None];
        f[i] = Some(Fault::Alpha(level));
        let beta = BabyBear(99);
        let r = run::<BabyBear, BabyBear4>(n, Some(3), beta, 70 + level as u64, f);
        let alpha_star = (r[0].alpha_share ^ r[1].alpha_share) ^ (1 << (depth - 1 - level));
        let p = parts(r);
        assert_eq!(p.omegas[0].add(p.omegas[1]), M127::ZERO);
        let [a, b] = eval_and_verify(&p, (0..n).collect(), Tamper::No);
        let ys = a.unwrap();
        assert_eq!(b.unwrap(), ys);
        for x in 0..n {
            assert_eq!(ys[x as usize], if x == alpha_star { beta } else { BabyBear::ZERO }, "level {level} x={x}");
        }
    }
}

/// Dealer keys with a dealer's Π_Verify masks verify; a mask that does not
/// match δ is rejected.
#[test]
fn dealer_keys_verify() {
    let mut rng = ChaCha20Rng::seed_from_u64(4);
    let n = 32u64;
    let (keys, d) = gen_reference::<BabyBear, BabyBear4>(n, 7, BabyBear::random(&mut rng), rng.gen());
    let glue = deal_triple::<M127, _>(&mut rng);
    let p = Parts { keys, d, masks: deal_mask(d[0].add(d[1]), &mut rng), glue, omegas: [M127::ZERO; 2] };
    let [a, b] = eval_and_verify(&p, (0..n).collect(), Tamper::No);
    assert!(a.is_ok() && b.is_ok());
    let bad = Parts { masks: deal_mask(d[0], &mut rng), ..p };
    let [a, _] = eval_and_verify(&bad, (0..n).collect(), Tamper::No);
    assert!(a.is_err());
}

fn full_eval_matches_point_eval<F: Field, E: Ext<F>>() {
    let mut rng = ChaCha20Rng::seed_from_u64(3);
    for n in [2u64, 13, 64, 1000] {
        let (keys, _) = gen_reference::<F, E>(n, rng.gen_range(0..n), F::random(&mut rng), rng.gen());
        for k in &keys {
            let points: Vec<(F, E)> = (0..n).map(|x| k.eval_point(x)).collect();
            assert_eq!(k.eval_full(), points);
            for batch in [2, 4, 1 << 10] {
                let mut streamed = Vec::new();
                k.eval_full_stream(batch, |x0, outs| {
                    assert_eq!(x0, streamed.len() as u64);
                    streamed.extend_from_slice(outs);
                });
                assert_eq!(streamed, points, "n={n} batch={batch}");
            }
        }
    }
}

#[test]
fn full_eval_matches_point_eval_babybear() {
    full_eval_matches_point_eval::<BabyBear, BabyBear4>();
}

#[test]
fn full_eval_matches_point_eval_m127() {
    full_eval_matches_point_eval::<M127, M127>();
}
