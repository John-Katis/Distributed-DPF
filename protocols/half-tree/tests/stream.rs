//! The streaming tree must reproduce the stored tree exactly: same keys, same
//! messages, and the same full-domain output; the malicious MAC check must
//! still pass honest runs and catch tampering.

use dpf_common::testing::random_beta;
use half_tree::malicious::{gen_reference_mode, Fault};
use half_tree::semi_honest::{gen_reference, gen_reference_keys};
use half_tree::{run_gen_mode, run_mal_gen_mode, Block, TreeMode};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;

const SIZES: &[u64] = &[2, 3, 5, 64, 1000, (1 << 12) + 3];
/// A tiny batch forces the walk to split on every level.
const BATCHES: &[usize] = &[4, 64];

#[test]
fn semi_honest_stream_matches_stored() {
    let mut rng = ChaCha20Rng::seed_from_u64(21);
    for &n in SIZES {
        for ob in [64, 127, 128, 384] {
            let beta = random_beta(&mut rng, ob);
            let alpha = rng.gen_range(0..n);
            let seed = rng.gen();
            let stored = run_gen_mode(n, ob, alpha, &beta, seed, TreeMode::Stored);
            let dseed = rng.gen();
            let (dkeys, _) = gen_reference(n, ob, alpha, &beta, dseed);
            for &batch in BATCHES {
                let mode = TreeMode::Stream { batch };
                let s = run_gen_mode(n, ob, alpha, &beta, seed, mode);
                for p in 0..2 {
                    let ctx = format!("N={n} out={ob} batch={batch} party={p}");
                    let (a, b) = (&stored.outs[p], &s.outs[p]);
                    assert_eq!((&a.key.cws, a.key.hcw, a.key.lcw, &a.key.cw_out), (&b.key.cws, b.key.hcw, b.key.lcw, &b.key.cw_out), "{ctx}");
                    assert_eq!(a.gen_stats, b.gen_stats, "messages differ: {ctx}");
                    assert!(b.full.is_none());
                }
                let sk = gen_reference_keys(n, ob, alpha, &beta, dseed, mode);
                for p in 0..2 {
                    assert_eq!((&dkeys[p].cws, dkeys[p].hcw, &dkeys[p].cw_out), (&sk[p].cws, sk[p].hcw, &sk[p].cw_out));
                    let full = dkeys[p].eval_full();
                    let mut seen = 0;
                    dkeys[p].eval_full_stream(batch, |x0, cols| {
                        assert_eq!(x0, seen);
                        for (k, col) in cols.iter().enumerate() {
                            assert_eq!(col.as_slice(), &full.column(k)[x0 as usize..x0 as usize + col.len()]);
                        }
                        seen += cols[0].len() as u64;
                    });
                    assert_eq!(seen, n);
                }
            }
        }
    }
}

#[test]
fn malicious_stream_matches_stored_and_catches_tampering() {
    let mut rng = ChaCha20Rng::seed_from_u64(22);
    for &n in SIZES {
        for bm in [1usize, 2] {
            let beta: Vec<Block> = (0..bm).map(|_| Block::random(&mut rng)).collect();
            let alpha = rng.gen_range(0..n);
            let seed = rng.gen();
            let stored = run_mal_gen_mode(n, alpha, &beta, seed, [None, None], None, TreeMode::Stored);
            let dseed = rng.gen();
            let (dkeys, _) = gen_reference_mode(n, alpha, &beta, dseed, TreeMode::Stored);
            for &batch in BATCHES {
                let mode = TreeMode::Stream { batch };
                let s = run_mal_gen_mode(n, alpha, &beta, seed, [None, None], None, mode);
                for p in 0..2 {
                    let ctx = format!("N={n} bm={bm} batch={batch} party={p}");
                    let a = stored.outs[p].as_ref().expect("stored run aborted");
                    let b = s.outs[p].as_ref().expect("stream run aborted");
                    assert_eq!(a.out.key.public_part(), b.out.key.public_part(), "{ctx}");
                    assert_eq!(a.gen_stats, b.gen_stats, "messages differ: {ctx}");
                    assert!(b.out.full.is_none());
                }
                let (sk, _) = gen_reference_mode(n, alpha, &beta, dseed, mode);
                for p in 0..2 {
                    assert_eq!(dkeys[p].public_part(), sk[p].public_part());
                    let full = dkeys[p].eval_full();
                    let mut seen = 0;
                    dkeys[p].eval_full_stream(batch, |x0, part| {
                        assert_eq!(x0, seen);
                        let r = x0 as usize..x0 as usize + part.n;
                        assert_eq!(part.u.as_slice(), &full.u[r.clone()]);
                        for (col, fcol) in part.v.iter().zip(&full.v) {
                            assert_eq!(col.as_slice(), &fcol[r.clone()]);
                        }
                        seen += part.n as u64;
                    });
                    assert_eq!(seen, n);
                }
                let level = rng.gen_range(0..=dkeys[0].depth());
                let fault = Some(Fault { level, err: Block(1 << 9) });
                let bad = run_mal_gen_mode(n, alpha, &beta, seed, [fault, None], None, mode);
                assert!(bad.outs.iter().any(|o| o.is_err()), "tampering at level {level} not caught: N={n} batch={batch}");
            }
        }
    }
}
