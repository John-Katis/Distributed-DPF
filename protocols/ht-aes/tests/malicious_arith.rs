//! The malicious Gen with an arithmetic payload in F_p: correctness against
//! the dealer, Π_Verify, and that deviations in Gen are caught by Π_Verify.

use dpf_common::block::Block;
use dpf_common::coin::Abort;
use dpf_common::net::run_two_party;
use ht_aes::field::{Field, Gold, M127};
use ht_aes::malicious::{mal_foleage_for, mal_products, Fault};
use ht_aes::malicious_arith::{deal, gen_reference, run_mal_arith, verify, ArithMalKey, ArithMalRun};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;

fn run<F: Field>(n: u64, alpha: u64, beta: F, seed: u64, faults: [Option<Fault>; 2]) -> [ArithMalRun<F>; 2] {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let a0: u64 = rng.gen::<u64>() % n.next_power_of_two();
    let b0 = F::random(&mut rng);
    let seeds: [[u8; 32]; 2] = [rng.gen(), rng.gen()];
    let p = mal_foleage_for(dpf_common::block::depth_for(n));
    let (r0, r1) = run_two_party(
        move |c| run_mal_arith(c, n, a0, b0, seeds[0], None, p, faults[0]),
        move |c| run_mal_arith(c, n, alpha ^ a0, beta.sub(b0), seeds[1], None, p, faults[1]),
    );
    [r0, r1]
}

fn eval_and_verify<F: Field>(keys: [ArithMalKey<F>; 2], d: [F; 2], xs: Vec<u64>, tamper: bool) -> [Result<Vec<F>, Abort>; 2] {
    let party = |p: usize, k: ArithMalKey<F>| {
        let xs = xs.clone();
        move |c: &mut dpf_common::net::Channel| {
            let mut outs: Vec<(F, F)> = xs.iter().map(|&x| k.eval_point(x)).collect();
            if tamper && p == 1 {
                outs[0].0 = outs[0].0.add(F::ONE);
            }
            verify(c, &outs, d[p], &mut ChaCha20Rng::seed_from_u64(p as u64))
        }
    };
    let [k0, k1] = keys;
    let (a, b) = run_two_party(party(0, k0), party(1, k1));
    [a, b]
}

fn gen_matches_dealer_and_verifies<F: Field>(seed: u64) {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    for (i, n) in [8u64, 13, 16].into_iter().enumerate() {
        let alpha = rng.gen_range(0..n);
        let beta = F::random(&mut rng);
        let [r0, r1] = run(n, alpha, beta, seed + i as u64, [None, None]);
        let depth = r0.key.depth();
        assert_eq!(r0.gen_stats.rounds.max(r1.gen_stats.rounds), 41 * depth + 44);
        assert_eq!(r0.products, mal_products(depth));
        let delta = r0.delta_share.add(r1.delta_share);
        let dealt = deal([r0.key.root, r1.key.root], n, alpha, beta, delta);
        assert_eq!(dealt, [r0.key.clone(), r1.key.clone()]);
        let xs: Vec<u64> = (0..n).collect();
        let [y0, y1] = eval_and_verify([r0.key.clone(), r1.key.clone()], [r0.delta_share, r1.delta_share], xs.clone(), false);
        let (y0, y1) = (y0.unwrap(), y1.unwrap());
        assert_eq!(y0, y1);
        for x in 0..n {
            assert_eq!(y0[x as usize], if x == alpha { beta } else { F::ZERO });
        }
        // A falsified output share is caught.
        let [a, b] = eval_and_verify([r0.key, r1.key], [r0.delta_share, r1.delta_share], xs, true);
        assert!(a.is_err() && b.is_err());
    }
}

#[test]
fn mal_arith_gen_matches_dealer_and_verifies_gold() {
    gen_matches_dealer_and_verifies::<Gold>(1);
}

#[test]
fn mal_arith_gen_matches_dealer_and_verifies_m127() {
    gen_matches_dealer_and_verifies::<M127>(11);
}

/// A wrong CW share, payload word or MAC word in Gen: the honest run of Gen
/// completes, and Π_Verify over the whole domain aborts.
#[test]
fn faults_in_gen_are_caught_by_verify() {
    let mut rng = ChaCha20Rng::seed_from_u64(2);
    let n = 8u64;
    for level in [0usize, 2, 3, 4] {
        for cheater in [0, 1] {
            let err = Block(1 << rng.gen_range(0..16));
            let mut faults = [None, None];
            faults[cheater] = Some(Fault { level, err });
            let [r0, r1] = run::<Gold>(n, 5, Gold(77), 10 + level as u64, faults);
            let [a, b] = eval_and_verify([r0.key, r1.key], [r0.delta_share, r1.delta_share], (0..n).collect(), false);
            assert_eq!(a.err(), Some(Abort("output MAC check failed")), "level {level} cheater {cheater}");
            assert_eq!(b.err(), Some(Abort("output MAC check failed")));
        }
    }
}

#[test]
fn full_eval_matches_point_eval() {
    let mut rng = ChaCha20Rng::seed_from_u64(3);
    for n in [2u64, 13, 64, 1000] {
        let (keys, _) = gen_reference::<M127>(n, rng.gen_range(0..n), M127::random(&mut rng), rng.gen());
        for k in &keys {
            let points: Vec<(M127, M127)> = (0..n).map(|x| k.eval_point(x)).collect();
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
