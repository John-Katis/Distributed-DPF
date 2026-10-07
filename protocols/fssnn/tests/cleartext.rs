//! The FssNN-style DPF against the cleartext point function over Z2.

use dpf_common::block::Block;
use fssnn::key::levels_for;
use fssnn::{deal, gen_reference, run_gen, FssKey};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;

/// Below, at and above the early-termination cut (n = 6), and non-powers of two.
const SIZES: &[u64] = &[2, 3, 5, 33, 64, 65, 127, 1000, 1024, (1 << 12) + 3];

fn check(keys: &[FssKey; 2], n: u64, alpha: u64, beta: bool) {
    let ctx = format!("N={n} alpha={alpha} beta={beta}");
    assert_eq!(keys[0].public_part(), keys[1].public_part(), "{ctx}");
    assert_eq!(keys[0].cws.len(), levels_for(keys[0].depth()), "{ctx}");
    let ev = [keys[0].eval_full(), keys[1].eval_full()];
    for x in 0..n {
        let want = beta && x == alpha;
        let p = [keys[0].eval_point(x), keys[1].eval_point(x)];
        assert_eq!(p[0] ^ p[1], want, "eval_point at x={x}: {ctx}");
        assert_eq!((ev[0][x as usize], ev[1][x as usize]), (p[0], p[1]), "eval_full != eval_point at x={x}: {ctx}");
    }
}

#[test]
fn dealer_keys_match_cleartext_function() {
    let mut rng = ChaCha20Rng::seed_from_u64(1);
    for &n in SIZES {
        for alpha in [0, n - 1, rng.gen_range(0..n)] {
            for beta in [false, true] {
                check(&gen_reference(n, alpha, beta, rng.gen()), n, alpha, beta);
            }
        }
    }
}

#[test]
fn two_party_gen_matches_cleartext_function() {
    let mut rng = ChaCha20Rng::seed_from_u64(2);
    let mut seed = 0;
    for &n in SIZES {
        for alpha in [0, n - 1, rng.gen_range(0..n)] {
            for beta in [false, true] {
                seed += 1;
                let run = run_gen(n, alpha, beta, seed);
                let [o0, o1] = run.outs;
                assert_eq!(o0.prg_calls, 2 * levels_for(o0.key.depth()));
                let keys = [o0.key, o1.key];
                check(&keys, n, alpha, beta);
                // Same keys as the dealer on the same roots.
                let dealt = deal([keys[0].root, keys[1].root], n, alpha, beta);
                assert_eq!(dealt[0].public_part(), keys[0].public_part(), "N={n} alpha={alpha}");
            }
        }
    }
}

#[test]
fn deal_rejects_bad_roots() {
    let r = std::panic::catch_unwind(|| deal([Block(1), Block(1)], 8, 3, true));
    assert!(r.is_err());
}
