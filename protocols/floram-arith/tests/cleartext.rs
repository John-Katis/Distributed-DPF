//! Arithmetic DPF against the cleartext point function over Z_2^ℓ.

use dpf_common::arith::mask;
use floram_arith::{deal, gen_reference, run_gen, ArithKey};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;

const SIZES: &[u64] = &[2, 3, 5, 7, 1000, 1024, (1 << 12) + 3];
const BITS: &[usize] = &[1, 16, 32, 64];

fn check(keys: &[ArithKey; 2], fulls: Option<&[Vec<u64>; 2]>, n: u64, alpha: u64, beta: u64) {
    let m = keys[0].ring_mask();
    let ctx = format!("N={n} alpha={alpha} bits={}", keys[0].bits);
    assert_eq!(keys[0].public_part(), keys[1].public_part(), "{ctx}");
    let ev = [keys[0].eval_full(), keys[1].eval_full()];
    for x in 0..n {
        let want = if x == alpha { beta } else { 0 };
        let p = [keys[0].eval_point(x), keys[1].eval_point(x)];
        assert_eq!(p[0].wrapping_add(p[1]) & m, want, "eval_point at x={x}: {ctx}");
        assert_eq!(ev[0][x as usize], p[0], "eval_full != eval_point at x={x}: {ctx}");
        assert_eq!(ev[1][x as usize], p[1], "eval_full != eval_point at x={x}: {ctx}");
    }
    if let Some(f) = fulls {
        assert_eq!(&ev[0], &f[0], "gen output differs: {ctx}");
        assert_eq!(&ev[1], &f[1], "gen output differs: {ctx}");
    }
}

#[test]
fn two_party_gen_matches_cleartext_function() {
    let mut rng = ChaCha20Rng::seed_from_u64(31);
    let mut seed = 0;
    for &n in SIZES {
        for &bits in BITS {
            for alpha in [0, n - 1, rng.gen_range(0..n)] {
                let beta = rng.gen::<u64>() & mask(bits);
                seed += 1;
                let run = run_gen(n, bits, alpha, beta, seed);
                let [o0, o1] = run.outs;
                let keys = [o0.key, o1.key];
                check(&keys, Some(&[o0.full, o1.full]), n, alpha, beta);
                let d = deal(&keys[0].prg, [keys[0].root, keys[1].root], n, bits, alpha, beta);
                assert_eq!(d[0].public_part(), keys[0].public_part(), "protocol differs from dealer");
            }
        }
    }
}

#[test]
fn every_alpha_with_wrapping_shares() {
    // N = 13 → n = 4, so additive α shares wrap modulo 16.
    let n = 13;
    let mut wrapped = 0;
    for alpha in 0..n {
        for s in 0..4 {
            let run = run_gen(n, 32, alpha, 0xdead_0000 + alpha, 100 * alpha + s);
            wrapped += (run.alpha_shares[0] + run.alpha_shares[1] >= 16) as u32;
            let [o0, o1] = run.outs;
            check(&[o0.key, o1.key], Some(&[o0.full, o1.full]), n, alpha, 0xdead_0000 + alpha);
        }
    }
    assert!(wrapped > 0, "no case exercised a carry out of the top bit");
}

#[test]
fn dealer_matches_cleartext_function() {
    let mut rng = ChaCha20Rng::seed_from_u64(32);
    for &n in SIZES {
        for &bits in BITS {
            let alpha = rng.gen_range(0..n);
            let beta = rng.gen::<u64>() & mask(bits);
            check(&gen_reference(n, bits, alpha, beta, rng.gen()), None, n, alpha, beta);
        }
    }
}
