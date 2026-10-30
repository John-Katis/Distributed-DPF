//! The malicious Gen with an arithmetic payload: correctness against the
//! dealer, Π_Verify, and that deviations in Gen are caught by Π_Verify. The
//! paper's fields (Babybear payload, MAC in F_{q^4}) and, for wider payloads,
//! Goldilocks and 2^127 − 1 in both roles.

use dpf_common::block::Block;
use dpf_common::coin::Abort;
use dpf_common::net::run_two_party;
use ht_aes::field::{BabyBear, BabyBear4, Ext, Field, Gold, M127};
use ht_aes::malicious::Fault;
use ht_aes::malicious_arith::{
    arith_mal_ands, deal, deal_mask, gen_reference, open_checked, run_mal_arith, verify, ArithMalKey, ArithMalRun, VerifyMask,
};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;

fn run<F: Field, E: Ext<F>>(n: u64, alpha: u64, beta: F, seed: u64, faults: [Option<Fault>; 2]) -> [ArithMalRun<F, E>; 2] {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let a0: u64 = rng.gen::<u64>() % n.next_power_of_two();
    let b0 = F::random(&mut rng);
    let seeds: [[u8; 32]; 2] = [rng.gen(), rng.gen()];
    let (r0, r1) = run_two_party(
        move |c| run_mal_arith::<F, E>(c, n, a0, b0, seeds[0], None, faults[0]),
        move |c| run_mal_arith::<F, E>(c, n, alpha ^ a0, beta.sub(b0), seeds[1], None, faults[1]),
    );
    [r0, r1]
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
fn eval_and_verify<F: Field, E: Ext<F>>(
    keys: [ArithMalKey<F, E>; 2],
    d: [E; 2],
    masks: [VerifyMask<E>; 2],
    xs: Vec<u64>,
    tamper: Tamper,
) -> [Result<Vec<F>, Abort>; 2] {
    let party = |p: usize| {
        let outs: Vec<(F, E)> = xs.iter().map(|&x| keys[p].eval_point(x)).collect();
        move |c: &mut dpf_common::net::Channel| {
            let mut rng = ChaCha20Rng::seed_from_u64(p as u64);
            let mut bad = outs.clone();
            bad[0].0 = bad[0].0.add(F::ONE);
            let pick = |t: Tamper| if p == 1 && tamper == t { &bad } else { &outs };
            verify(c, pick(Tamper::Verify), d[p], masks[p], &mut rng)?;
            open_checked(c, pick(Tamper::Open), d[p], &mut rng)
        }
    };
    let (a, b) = run_two_party(party(0), party(1));
    [a, b]
}

fn gen_matches_dealer_and_verifies<F: Field, E: Ext<F>>(seed: u64) {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    for (i, n) in [8u64, 13, 16].into_iter().enumerate() {
        let alpha = rng.gen_range(0..n);
        let beta = F::random(&mut rng);
        let [r0, r1] = run::<F, E>(n, alpha, beta, seed + i as u64, [None, None]);
        let depth = r0.key.depth();
        assert_eq!(r0.gen_stats.rounds.max(r1.gen_stats.rounds), 41 * depth + 44);
        assert_eq!(r0.ands, arith_mal_ands::<F, E>(depth));
        let delta = r0.delta_share.add(r1.delta_share);
        let dealt = deal([r0.key.root, r1.key.root], [r0.key.prf.key(), r0.key.pay.key(), r0.key.mac.key()], n, alpha, beta, delta);
        assert_eq!(dealt, [r0.key.clone(), r1.key.clone()]);
        let xs: Vec<u64> = (0..n).collect();
        let (d, m) = ([r0.delta_share, r1.delta_share], [r0.mask, r1.mask]);
        let [a, b] = eval_and_verify([r0.key.clone(), r1.key.clone()], d, m, xs.clone(), Tamper::No);
        let ys = a.unwrap();
        assert_eq!(b.unwrap(), ys, "both parties open the same outputs");
        for x in 0..n {
            assert_eq!(ys[x as usize], if x == alpha { beta } else { F::ZERO });
        }
        // A falsified output share is caught.
        let [a, b] = eval_and_verify([r0.key.clone(), r1.key.clone()], d, m, xs.clone(), Tamper::Verify);
        assert!(a.is_err() && b.is_err());
        // A share falsified only at the opening is caught too.
        let [a, b] = eval_and_verify([r0.key, r1.key], d, m, xs, Tamper::Open);
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

/// A wrong CW share, payload word, MAC word or share of K in Gen: the run of
/// Gen completes, and Π_Verify over the whole domain aborts.
#[test]
fn faults_in_gen_are_caught_by_verify() {
    let mut rng = ChaCha20Rng::seed_from_u64(2);
    let n = 8u64;
    for level in [0usize, 2, 3, 4, 5] {
        for cheater in [0, 1] {
            let err = Block(1 << rng.gen_range(0..16));
            let mut faults = [None, None];
            faults[cheater] = Some(Fault { level, err });
            let [r0, r1] = run::<BabyBear, BabyBear4>(n, 5, BabyBear(77), 10 + level as u64, faults);
            let [a, b] = eval_and_verify([r0.key, r1.key], [r0.delta_share, r1.delta_share], [r0.mask, r1.mask], (0..n).collect(), Tamper::No);
            assert_eq!(a.err(), Some(Abort("output MAC check failed")), "level {level} cheater {cheater}");
            assert_eq!(b.err(), Some(Abort("output MAC check failed")));
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
    let m = deal_mask(d[0].add(d[1]), &mut rng);
    let [a, b] = eval_and_verify(keys.clone(), d, m, (0..n).collect(), Tamper::No);
    assert!(a.is_ok() && b.is_ok());
    let bad = deal_mask(d[0], &mut rng);
    let [a, _] = eval_and_verify(keys, d, bad, (0..n).collect(), Tamper::No);
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
