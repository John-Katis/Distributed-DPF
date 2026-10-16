//! Semi-honest FssNN-style DPF against the cleartext point function, over
//! `{0,1}^ℓ` (XOR) and Z_2^ℓ.

use dpf_common::arith::mask;
use dpf_common::block::Block;
use fssnn::run_gen;
use fssnn::semi_honest::{deal, gen_reference, FssKey};
use fssnn::Group;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;

/// Powers of two and non-powers of two (padded to 2^n).
const SIZES: &[u64] = &[2, 3, 5, 33, 64, 65, 127, 1000, 1024, (1 << 12) + 3];
const GROUPS: &[(Group, usize)] = &[(Group::Xor, 1), (Group::Xor, 7), (Group::Xor, 64), (Group::Arith, 1), (Group::Arith, 32), (Group::Arith, 64)];

fn combine(group: Group, bits: usize, a: u64, b: u64) -> u64 {
    match group {
        Group::Xor => a ^ b,
        Group::Arith => a.wrapping_add(b) & mask(bits),
    }
}

fn check(keys: &[FssKey; 2], n: u64, alpha: u64, beta: u64) {
    let (group, bits) = (keys[0].group, keys[0].bits);
    let ctx = format!("{group:?} bits={bits} N={n} alpha={alpha} beta={beta}");
    assert_eq!(keys[0].public_part(), keys[1].public_part(), "{ctx}");
    assert_eq!(keys[0].cws.len(), keys[0].depth(), "{ctx}");
    let ev = [keys[0].eval_full(), keys[1].eval_full()];
    for x in 0..n {
        let want = if x == alpha { beta } else { 0 };
        let p = [keys[0].eval_point(x), keys[1].eval_point(x)];
        assert_eq!(combine(group, bits, p[0], p[1]), want, "eval_point at x={x}: {ctx}");
        assert_eq!((ev[0][x as usize], ev[1][x as usize]), (p[0], p[1]), "eval_full != eval_point at x={x}: {ctx}");
    }
    for batch in [4, 64] {
        for (k, e) in keys.iter().zip(&ev) {
            let mut got = Vec::new();
            k.eval_full_stream(batch, |x0, ys| {
                assert_eq!(x0 as usize, got.len());
                got.extend_from_slice(ys);
            });
            assert_eq!(&got, e, "eval_full_stream != eval_full: {ctx} batch={batch}");
        }
    }
}

/// β = 0, the all-ones word and a random one.
fn betas(rng: &mut ChaCha20Rng, bits: usize) -> [u64; 3] {
    [0, mask(bits), rng.gen::<u64>() & mask(bits)]
}

#[test]
fn dealer_keys_match_cleartext_function() {
    let mut rng = ChaCha20Rng::seed_from_u64(1);
    for &(group, bits) in GROUPS {
        for &n in SIZES {
            for alpha in [0, n - 1, rng.gen_range(0..n)] {
                for beta in betas(&mut rng, bits) {
                    check(&gen_reference(n, group, bits, alpha, beta, rng.gen()), n, alpha, beta);
                }
            }
        }
    }
}

#[test]
fn two_party_gen_matches_cleartext_function() {
    let mut rng = ChaCha20Rng::seed_from_u64(2);
    let mut seed = 0;
    for &(group, bits) in GROUPS {
        for &n in SIZES {
            for alpha in [0, n - 1, rng.gen_range(0..n)] {
                for beta in betas(&mut rng, bits) {
                    seed += 1;
                    let run = run_gen(n, group, bits, alpha, beta, seed);
                    let [o0, o1] = run.outs;
                    assert_eq!(o0.prg_calls, 2 * o0.key.depth());
                    let keys = [o0.key, o1.key];
                    check(&keys, n, alpha, beta);
                    // Same keys as the dealer on the same roots.
                    let dealt = deal([keys[0].root, keys[1].root], n, group, bits, alpha, beta);
                    assert_eq!(dealt[0].public_part(), keys[0].public_part(), "{group:?} bits={bits} N={n} alpha={alpha}");
                }
            }
        }
    }
}

#[test]
fn deal_rejects_bad_roots() {
    let r = std::panic::catch_unwind(|| deal([Block(1), Block(1)], 8, Group::Xor, 1, 3, 1));
    assert!(r.is_err());
}
