//! End-to-end tests against the cleartext point function
//! `f_{α,β}(x) = β if x = α, else 0`.
//!
//! Each case runs the two-party CPRG generation (garbled circuit + IKNP over the
//! simulated network) with α and β given as random XOR shares. It then checks
//! that every way of evaluating the resulting shares reconstructs to `f`.

use dpf_common::block::xor_blocks;
use dpf_common::testing::{point_fn as f, random_beta};
use floram_cprg::{gen_reference, run_gen, Block, DpfKey, FullEval};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;

const SIZES: &[u64] = &[2, 3, 5, 7, 1000, 1024, (1 << 12) + 3];
const OUT_BITS: &[usize] = &[32, 128, 256, 384];

/// Checks keys and full-domain outputs against the cleartext function.
fn check_against_cleartext(keys: &[DpfKey; 2], fulls: &[FullEval; 2], n: u64, alpha: u64, beta: &[Block]) {
    let ctx = format!("N={n} alpha={alpha} bm={}", beta.len());
    assert_eq!(keys[0].public_part(), keys[1].public_part(), "public key parts differ: {ctx}");
    let evals = [keys[0].eval_full(), keys[1].eval_full()];
    for x in 0..n {
        let want = f(alpha, beta, x);
        // Point evaluation of both keys.
        let p0 = keys[0].eval_point(x);
        let p1 = keys[1].eval_point(x);
        assert_eq!(xor_blocks(&p0, &p1), want, "eval_point reconstructs wrong at x={x}: {ctx}");
        // Full-domain output produced during Gen (Floram's blockvector).
        let g0 = fulls[0].get(x as usize);
        let g1 = fulls[1].get(x as usize);
        assert_eq!(xor_blocks(&g0, &g1), want, "gen output reconstructs wrong at x={x}: {ctx}");
        // Non-interactive full-domain eval of the keys, which must also match point eval.
        assert_eq!(evals[0].get(x as usize), p0, "eval_full != eval_point for party 0 at x={x}: {ctx}");
        assert_eq!(evals[1].get(x as usize), p1, "eval_full != eval_point for party 1 at x={x}: {ctx}");
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

                // Payload positions really hold β, and a single share does not.
                let at = xor_blocks(&o0.key.eval_point(alpha), &o1.key.eval_point(alpha));
                assert_eq!(at, beta, "f(alpha) != beta");
                assert_ne!(o0.key.eval_point(alpha), beta, "a single share equals beta");

                check_against_cleartext(&[o0.key.clone(), o1.key.clone()], &[o0.full.clone(), o1.full.clone()], n, alpha, &beta);

                // Bit-exact against the plaintext reference driver with the same seeds.
                let (rk, rf) = gen_reference(n, out_bits, alpha, &beta, run.seeds);
                for (k, r) in [&o0.key, &o1.key].iter().zip(&rk) {
                    assert_eq!(k.root, r.root);
                    assert_eq!(k.cws, r.cws);
                    assert_eq!(k.gamma, r.gamma);
                }
                assert_eq!(o0.full, rf[0]);
                assert_eq!(o1.full, rf[1]);
            }
        }
    }
}

#[test]
fn zero_payload_gives_zero_everywhere() {
    let n = 77;
    let beta = vec![Block::ZERO; 2];
    let run = run_gen(n, 200, 31, &beta, 99);
    let [o0, o1] = run.outs;
    for x in 0..n {
        assert_eq!(xor_blocks(&o0.key.eval_point(x), &o1.key.eval_point(x)), vec![Block::ZERO; 2]);
    }
}

#[test]
fn reference_dealer_gen_matches_cleartext_function() {
    let mut rng = ChaCha20Rng::seed_from_u64(7);
    for &n in SIZES {
        for &out_bits in OUT_BITS {
            let alpha = rng.gen_range(0..n);
            let beta = random_beta(&mut rng, out_bits);
            let (keys, fulls) = gen_reference(n, out_bits, alpha, &beta, [rng.gen(), rng.gen()]);
            check_against_cleartext(&keys, &fulls, n, alpha, &beta);
        }
    }
}

#[test]
fn every_alpha_small_domain() {
    // Exhaustive over α for a non-power-of-two domain.
    let n = 11;
    for alpha in 0..n {
        let beta = vec![Block(0xdead_beef_0000 + alpha as u128)];
        let run = run_gen(n, 64, alpha, &beta, 1000 + alpha);
        let [o0, o1] = run.outs;
        check_against_cleartext(&[o0.key, o1.key], &[o0.full, o1.full], n, alpha, &beta);
    }
}
