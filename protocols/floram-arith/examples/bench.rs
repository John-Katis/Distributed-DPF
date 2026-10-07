//! Benchmarks for the arithmetic dealer-less DPF (NDSS'25 on the Floram tree).
//!
//! ```text
//! cargo run --release -p floram-arith --example bench-floram-arith -- <gen|eval|full|all> [options]
//! ```
//!
//! `--out-bits ℓ` (1..=64, default 64) is the payload ring Z_2^ℓ. Options and
//! CSV columns are those of `dpf_common::bench`. `eval` and `full` use dealer
//! keys.

use dpf_common::arith::mask;
use dpf_common::bench::{bench_eval, bench_full, median, print_gen, GenRow, Opts};
use floram_arith::{gen_reference, run_gen};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use std::hint::black_box;

fn bench_gen(o: &Opts, rng: &mut ChaCha20Rng) {
    let (mut setup, mut g0, mut g1, mut total) = (vec![], vec![], vec![], vec![]);
    let mut last = None;
    for _ in 0..o.reps {
        let beta = rng.gen::<u64>() & mask(o.out_bits);
        let run = run_gen(o.size, o.out_bits, rng.gen_range(0..o.size), beta, rng.gen());
        setup.push(run.outs[0].setup_time.max(run.outs[1].setup_time));
        g0.push(run.outs[0].gen_time);
        g1.push(run.outs[1].gen_time);
        total.push(run.times[0].max(run.times[1]));
        last = Some(run);
    }
    let run = last.unwrap();
    let [o0, o1] = &run.outs;
    print_gen(
        o,
        &GenRow {
            bm: 1,
            setup: median(setup),
            gen_p0: median(g0),
            gen_p1: median(g1),
            total: median(total),
            setup_bytes: o0.setup_stats.total_bytes(),
            gen_bytes: o0.gen_stats.total_bytes(),
            depth: o0.key.depth(),
            flights: o0.gen_stats.flights + o1.gen_stats.flights,
            and_gates: o0.and_gates,
            cots: o0.cots,
            key_bytes: o0.key.size_bytes(),
        },
    );
}

fn main() {
    let opts = Opts::parse(&["floram-arith"], 64, &[16, 32, 64]);
    assert!((1..=64).contains(&opts.out_bits) && opts.out_list.iter().all(|b| (1..=64).contains(b)), "out-bits must be 1..=64");
    let mut rng = ChaCha20Rng::from_entropy();
    opts.for_each(|o| {
        if o.runs("gen") {
            bench_gen(o, &mut rng);
        }
        let beta = rng.gen::<u64>() & mask(o.out_bits);
        let keys = gen_reference(o.size, o.out_bits, rng.gen_range(0..o.size), beta, rng.gen());
        if o.runs("eval") {
            let xs: Vec<u64> = (0..o.points).map(|_| rng.gen_range(0..o.size)).collect();
            bench_eval(o, 1, &xs, |x| {
                black_box(keys[0].eval_point(x));
            });
        }
        if o.runs("full") {
            bench_full(o, 1, || {
                black_box(keys[0].eval_full());
            });
        }
    });
}
