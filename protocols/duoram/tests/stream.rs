//! The streaming tree must reproduce the stored tree exactly: same keys, same
//! messages, and the same full-domain output.

use dpf_common::arith::mask;
use duoram::{gen_reference, gen_reference_mode, run_gen_2p_mode, run_gen_3p_mode, TreeMode};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;

const SIZES: &[u64] = &[2, 3, 5, 64, 1000, (1 << 12) + 3];
/// A tiny batch forces the walk to split on every level.
const BATCHES: &[usize] = &[4, 64];

#[test]
fn stream_matches_stored() {
    let mut rng = ChaCha20Rng::seed_from_u64(41);
    for &n in SIZES {
        for bits in [16, 64] {
            let beta = rng.gen::<u64>() & mask(bits);
            let alpha = rng.gen_range(0..n);
            let seed = rng.gen();
            let dseed = rng.gen();
            let dkeys = gen_reference(n, bits, alpha, beta, dseed);
            for three in [false, true] {
                let run = |mode| if three { run_gen_3p_mode(n, bits, alpha, beta, seed, mode) } else { run_gen_2p_mode(n, bits, alpha, beta, seed, mode) };
                let stored = run(TreeMode::Stored);
                for &batch in BATCHES {
                    let s = run(TreeMode::Stream { batch });
                    for p in 0..2 {
                        let ctx = format!("N={n} bits={bits} 3p={three} batch={batch} party={p}");
                        let (a, b) = (&stored.outs[p], &s.outs[p]);
                        assert_eq!(a.key.public_part(), b.key.public_part(), "{ctx}");
                        assert_eq!((a.key.c, a.key.fbar), (b.key.c, b.key.fbar), "{ctx}");
                        assert_eq!((a.pre_stats, a.online_stats), (b.pre_stats, b.online_stats), "messages differ: {ctx}");
                    }
                }
            }
            for &batch in BATCHES {
                let sk = gen_reference_mode(n, bits, alpha, beta, dseed, TreeMode::Stream { batch });
                for p in 0..2 {
                    assert_eq!(dkeys[p].public_part(), sk[p].public_part());
                    assert_eq!((dkeys[p].c, dkeys[p].fbar), (sk[p].c, sk[p].fbar));
                    let full = dkeys[p].eval_full();
                    let mut got = vec![None; n as usize];
                    dkeys[p].eval_full_stream(batch, |x, y| {
                        assert!(got[x as usize].replace(y).is_none(), "x={x} visited twice");
                    });
                    assert_eq!(got.into_iter().map(Option::unwrap).collect::<Vec<_>>(), full);
                }
            }
        }
    }
}
