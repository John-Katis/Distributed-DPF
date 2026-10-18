//! The streaming tree must reproduce the stored tree exactly: same keys, same
//! messages, and the same full-domain output.

use dpf_common::arith::Ring;
use floram_arith::{gen_reference, gen_reference_mode, run_gen_mode, TreeMode};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;

const SIZES: &[u64] = &[2, 3, 5, 64, 1000, (1 << 12) + 3];
/// A tiny batch forces the walk to split on every level.
const BATCHES: &[usize] = &[4, 64];

#[test]
fn stream_matches_stored() {
    stream_matches_stored_in::<u64>(&[1, 16, 64]);
    stream_matches_stored_in::<u128>(&[127, 128]);
}

fn stream_matches_stored_in<R: Ring>(widths: &[usize]) {
    let mut rng = ChaCha20Rng::seed_from_u64(31);
    for &n in SIZES {
        for &bits in widths {
            let beta = R::random(&mut rng).and(R::mask(bits));
            let alpha = rng.gen_range(0..n);
            let seed = rng.gen();
            let stored = run_gen_mode(n, bits, alpha, beta, seed, TreeMode::Stored, true);
            let dseed = rng.gen();
            let dkeys = gen_reference(n, bits, alpha, beta, dseed);
            let lean = run_gen_mode(n, bits, alpha, beta, seed, TreeMode::Stored, false);
            for p in 0..2 {
                let (a, b) = (&stored.outs[p], &lean.outs[p]);
                assert_eq!(a.key.public_part(), b.key.public_part(), "N={n} bits={bits}");
                assert_eq!(a.gen_stats, b.gen_stats);
                assert!(a.full.is_some() && b.full.is_none());
            }
            for &batch in BATCHES {
                let mode = TreeMode::Stream { batch };
                let s = run_gen_mode(n, bits, alpha, beta, seed, mode, false);
                for p in 0..2 {
                    let ctx = format!("N={n} bits={bits} batch={batch} party={p}");
                    let (a, b) = (&stored.outs[p], &s.outs[p]);
                    assert_eq!(a.key.public_part(), b.key.public_part(), "{ctx}");
                    assert_eq!(a.gen_stats, b.gen_stats, "messages differ: {ctx}");
                    assert!(b.full.is_none());
                }
                let sk = gen_reference_mode(n, bits, alpha, beta, dseed, mode);
                for p in 0..2 {
                    assert_eq!(dkeys[p].public_part(), sk[p].public_part());
                    let full = dkeys[p].eval_full();
                    let mut got = Vec::new();
                    dkeys[p].eval_full_stream(batch, |x0, ys| {
                        assert_eq!(x0 as usize, got.len());
                        got.extend_from_slice(ys);
                    });
                    assert_eq!(got, full);
                }
            }
        }
    }
}
