//! The streaming tree must reproduce the stored tree exactly: same keys, same
//! messages, and the same full-domain output.

use dpf_common::testing::random_beta;
use floram_cprg::{gen_reference, gen_reference_keys, run_gen_mode, TreeMode};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;

const SIZES: &[u64] = &[2, 3, 5, 64, 1000, (1 << 12) + 3];
const OUT_BITS: &[usize] = &[32, 128, 256, 384];
/// A tiny batch forces the walk to split on every level.
const BATCHES: &[usize] = &[4, 64];

#[test]
fn stream_gen_matches_stored_gen() {
    let mut rng = ChaCha20Rng::seed_from_u64(11);
    for &n in SIZES {
        for &ob in OUT_BITS {
            let beta = random_beta(&mut rng, ob);
            let alpha = rng.gen_range(0..n);
            let seed = rng.gen();
            let stored = run_gen_mode(n, ob, alpha, &beta, seed, TreeMode::Stored);
            for &batch in BATCHES {
                let s = run_gen_mode(n, ob, alpha, &beta, seed, TreeMode::Stream { batch });
                for p in 0..2 {
                    let (a, b) = (&stored.outs[p], &s.outs[p]);
                    let ctx = format!("N={n} out={ob} batch={batch} party={p}");
                    assert_eq!(a.key.public_part(), b.key.public_part(), "{ctx}");
                    assert_eq!(a.key.root, b.key.root, "{ctx}");
                    assert_eq!(a.gen_stats, b.gen_stats, "messages differ: {ctx}");
                    assert!(b.full.is_none());
                }
            }
        }
    }
}

#[test]
fn stream_dealer_and_eval_match_stored() {
    let mut rng = ChaCha20Rng::seed_from_u64(12);
    for &n in SIZES {
        for &ob in OUT_BITS {
            let beta = random_beta(&mut rng, ob);
            let alpha = rng.gen_range(0..n);
            let seeds = [rng.gen(), rng.gen()];
            let (keys, _) = gen_reference(n, ob, alpha, &beta, seeds);
            for &batch in BATCHES {
                let sk = gen_reference_keys(n, ob, alpha, &beta, seeds, TreeMode::Stream { batch });
                for p in 0..2 {
                    assert_eq!(keys[p].public_part(), sk[p].public_part(), "N={n} out={ob}");
                    let full = keys[p].eval_full();
                    let mut seen = 0;
                    keys[p].eval_full_stream(batch, |x0, cols| {
                        for (k, col) in cols.iter().enumerate() {
                            assert_eq!(col.as_slice(), &full.column(k)[x0 as usize..x0 as usize + col.len()]);
                        }
                        assert_eq!(x0, seen);
                        seen += cols[0].len() as u64;
                    });
                    assert_eq!(seen, n);
                }
            }
        }
    }
}
