//! Benchmarks for the arithmetic dealer-less DPF (NDSS'25 on the Floram tree).
//!
//! ```text
//! cargo run --release -p floram-arith --example bench-floram-arith -- <gen|eval|full|all> [options]
//! ```
//!
//! `--out-bits ℓ` (1..=128, default 64) is the payload ring Z_2^ℓ, computed
//! and sent in 64-bit words for ℓ ≤ 64 and in 128-bit words above. Options and
//! CSV columns are those of `dpf_common::bench`. As in the reference code,
//! Gen makes its triples and COTs when each AND/MUX needs them, so `pre_*` is
//! zero. Gen builds the key only (no
//! full-domain output). `eval` and `full` use dealer keys. With `--stream`, Gen and the dealer use the streaming tree and
//! `full` folds the outputs instead of storing them.

use dpf_common::arith::Ring;
use dpf_common::bench::{bench_eval, bench_full, median, print_gen, whole_gen, GenRow, Opts};
use dpf_common::net::CommStats;
use floram_arith::{gen_reference_mode, run_gen_mode, TreeMode};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use std::hint::black_box;

fn bench_gen<R: Ring>(o: &Opts, rng: &mut ChaCha20Rng) {
    let (mut setup, mut g0, mut g1, mut total) = (vec![], vec![], vec![], vec![]);
    let mut last = None;
    for _ in 0..o.reps {
        // Free the previous run before the next one.
        drop(last.take());
        let beta = R::random(rng).and(R::mask(o.out_bits));
        let run = run_gen_mode(o.size, o.out_bits, rng.gen_range(0..o.size), beta, rng.gen(), o.tree_mode(), false);
        setup.push(run.outs[0].setup_time.max(run.outs[1].setup_time));
        g0.push(run.outs[0].gen_time);
        g1.push(run.outs[1].gen_time);
        total.push(run.times[0].max(run.times[1]));
        last = Some(run);
    }
    let run = last.unwrap();
    let [o0, o1] = &run.outs;
    let (sent, rounds) = whole_gen([o0.setup_stats, o1.setup_stats], [CommStats::default(); 2], [o0.gen_stats, o1.gen_stats]);
    print_gen(
        o,
        &GenRow {
            bm: 1,
            sent,
            rounds,
            total: median(total),
            setup: median(setup),
            pre: std::time::Duration::ZERO,
            gen_p0: median(g0),
            gen_p1: median(g1),
            setup_bytes: o0.setup_stats.total_bytes(),
            pre_bytes: 0,
            pre_rounds: 0,
            gen_bytes: o0.gen_stats.total_bytes(),
            depth: o0.key.depth(),
            gen_rounds: o0.gen_stats.rounds.max(o1.gen_stats.rounds),
            and_gates: o0.and_gates,
            cots: o0.cots,
            key_bytes: o0.key.size_bytes(),
        },
    );
}

fn bench<R: Ring>(o: &Opts, rng: &mut ChaCha20Rng) {
    if o.runs("gen") {
        bench_gen::<R>(o, rng);
    }
    if !(o.runs("eval") || o.runs("full")) {
        return;
    }
    let beta = R::random(rng).and(R::mask(o.out_bits));
    let keys = gen_reference_mode(o.size, o.out_bits, rng.gen_range(0..o.size), beta, rng.gen(), o.tree_mode());
    if o.runs("eval") {
        let xs: Vec<u64> = (0..o.points).map(|_| rng.gen_range(0..o.size)).collect();
        bench_eval(o, 1, &xs, |x| {
            black_box(keys[0].eval_point(x));
        });
    }
    if o.runs("full") {
        bench_full(o, 1, || match o.tree_mode() {
            TreeMode::Stored => {
                black_box(keys[0].eval_full());
            }
            TreeMode::Stream { batch } => {
                let mut acc = R::ZERO;
                keys[0].eval_full_stream(batch, |_, ys| acc = ys.iter().fold(acc, |a, y| a.add(*y)));
                black_box(acc);
            }
        });
    }
}

fn main() {
    let opts = Opts::parse(&["floram-arith"], 64, &[64, 128]);
    assert!((1..=128).contains(&opts.out_bits) && opts.out_list.iter().all(|b| (1..=128).contains(b)), "out-bits must be 1..=128");
    let mut rng = ChaCha20Rng::from_entropy();
    opts.for_each(|o| {
        if o.out_bits <= 64 {
            bench::<u64>(o, &mut rng)
        } else {
            bench::<u128>(o, &mut rng)
        }
    });
}
