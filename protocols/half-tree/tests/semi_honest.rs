//! Semi-honest Half-Tree DPF against the cleartext point function
//! `f_{α,β}(x) = β if x = α, else 0`.

use dpf_common::block::xor_blocks;
use dpf_common::testing::{point_fn as f, random_beta};
use half_tree::semi_honest::{deal, gen_reference, HtKey};
use half_tree::{run_gen, Block, FullEval};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;

const SIZES: &[u64] = &[2, 3, 5, 7, 1000, 1024, (1 << 12) + 3];
const OUT_BITS: &[usize] = &[1, 32, 127, 128, 256, 384];

fn check_against_cleartext(keys: &[HtKey; 2], fulls: &[FullEval; 2], n: u64, alpha: u64, beta: &[Block]) {
    let ctx = format!("N={n} alpha={alpha} out_bits={}", keys[0].conv.out_bits);
    assert_eq!(keys[0].public_part(), keys[1].public_part(), "public key parts differ: {ctx}");
    let evals = [keys[0].eval_full(), keys[1].eval_full()];
    for x in 0..n {
        let want = f(alpha, beta, x);
        let p0 = keys[0].eval_point(x);
        let p1 = keys[1].eval_point(x);
        assert_eq!(xor_blocks(&p0, &p1), want, "eval_point reconstructs wrong at x={x}: {ctx}");
        assert_eq!(xor_blocks(&fulls[0].get(x as usize), &fulls[1].get(x as usize)), want, "gen output wrong at x={x}: {ctx}");
        assert_eq!(evals[0].get(x as usize), p0, "eval_full != eval_point (p0) at x={x}: {ctx}");
        assert_eq!(evals[1].get(x as usize), p1, "eval_full != eval_point (p1) at x={x}: {ctx}");
    }
    assert_eq!(&evals[0], &fulls[0], "eval_full differs from gen output: {ctx}");
    assert_eq!(&evals[1], &fulls[1], "eval_full differs from gen output: {ctx}");
}

#[test]
fn two_party_gen_matches_cleartext_function() {
    let mut rng = ChaCha20Rng::seed_from_u64(2024);
    let mut seed = 0u64;
    for &n in SIZES {
        for &out_bits in OUT_BITS {
            let mut alphas = vec![0, n - 1, rng.gen_range(0..n)];
            alphas.dedup();
            for alpha in alphas {
                let beta = random_beta(&mut rng, out_bits);
                seed += 1;
                let run = run_gen(n, out_bits, alpha, &beta, seed);
                let [o0, o1] = run.outs;
                assert_ne!(o0.key.eval_point(alpha), beta, "a single share equals beta");
                let keys = [o0.key.clone(), o1.key.clone()];
                check_against_cleartext(&keys, &[o0.full.clone(), o1.full.clone()], n, alpha, &beta);

                // Bit-exact against the dealer on the protocol's roots and hash key.
                let (rk, rf) = deal(&keys[0].hash, [keys[0].root, keys[1].root], n, out_bits, alpha, &beta);
                for (k, r) in keys.iter().zip(&rk) {
                    assert_eq!(k.public_part(), r.public_part());
                }
                assert_eq!(o0.full, rf[0]);
                assert_eq!(o1.full, rf[1]);
            }
        }
    }
}

#[test]
fn reference_dealer_matches_cleartext_function() {
    let mut rng = ChaCha20Rng::seed_from_u64(7);
    for &n in SIZES {
        for &out_bits in OUT_BITS {
            let alpha = rng.gen_range(0..n);
            let beta = random_beta(&mut rng, out_bits);
            let (keys, fulls) = gen_reference(n, out_bits, alpha, &beta, rng.gen());
            check_against_cleartext(&keys, &fulls, n, alpha, &beta);
        }
    }
}

#[test]
fn every_alpha_small_domain() {
    let n = 11;
    for alpha in 0..n {
        let beta = vec![Block(0xdead_beef_0000 + alpha as u128)];
        let run = run_gen(n, 64, alpha, &beta, 1000 + alpha);
        let [o0, o1] = run.outs;
        check_against_cleartext(&[o0.key, o1.key], &[o0.full, o1.full], n, alpha, &beta);
    }
}

#[test]
fn zero_payload_gives_zero_everywhere() {
    let beta = vec![Block::ZERO; 2];
    let run = run_gen(77, 200, 31, &beta, 99);
    let [o0, o1] = run.outs;
    for x in 0..77 {
        assert_eq!(xor_blocks(&o0.key.eval_point(x), &o1.key.eval_point(x)), vec![Block::ZERO; 2]);
    }
}

#[test]
fn flights_are_n_plus_3() {
    let n = 1u64 << 10;
    let run = run_gen(n, 128, 5, &[Block(1)], 3);
    let [o0, o1] = &run.outs;
    // COT columns, n-1 levels, (μ,d), CW_n, CW_{n+1}: n+3 flights. Party 0 sent
    // the last setup sync message, so the counter merges its first gen flight
    // into setup.
    assert_eq!(o0.gen_stats.flights, 10 + 2);
    assert_eq!(o1.gen_stats.flights, 10 + 3);
}

#[test]
fn hcw_pseudorandom_when_sibling_is_skipped() {
    // N = 5, α = 4: α's last-level sibling (leaf 5) has no leaf below N, but it
    // still enters the sums, so HCW is not publicly zero.
    let mut rng = ChaCha20Rng::seed_from_u64(17);
    for _ in 0..32 {
        let beta = random_beta(&mut rng, 64);
        let (keys, fulls) = gen_reference(5, 64, 4, &beta, rng.gen());
        assert_ne!(keys[0].hcw, Block::ZERO, "HCW is publicly zero");
        check_against_cleartext(&keys, &fulls, 5, 4, &beta);
    }
}
