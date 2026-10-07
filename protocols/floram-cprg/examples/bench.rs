//! Benchmarks for the Floram-CPRG distributed DPF.
//!
//! ```text
//! cargo run --release -p floram-cprg --example bench -- <gen|eval|full|all> [options]
//! ```
//!
//! Options and CSV columns are those of `dpf_common::bench`. Setup (PRG keys +
//! base OTs) is reported apart from generation. `eval` and `full` use keys from
//! the trusted-dealer `gen_reference`.

use dpf_common::bench::{bench_eval, bench_full, median, print_gen, GenRow, Opts};
use dpf_common::testing::random_beta;
use floram_cprg::{gen_reference, run_gen, Block};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use std::hint::black_box;

fn bench_gen(o: &Opts, rng: &mut ChaCha20Rng) {
    let (mut setup, mut gen0, mut gen1, mut total) = (vec![], vec![], vec![], vec![]);
    let mut last = None;
    for r in 0..o.reps {
        let beta = random_beta(rng, o.out_bits);
        let run = run_gen(o.size, o.out_bits, rng.gen_range(0..o.size), &beta, rng.gen::<u64>() ^ r as u64);
        setup.push(run.outs[0].setup_time.max(run.outs[1].setup_time));
        gen0.push(run.outs[0].gen_time);
        gen1.push(run.outs[1].gen_time);
        total.push(run.times[0].max(run.times[1]));
        last = Some(run);
    }
    let run = last.unwrap();
    let [o0, o1] = &run.outs;
    print_gen(
        o,
        &GenRow {
            bm: o0.key.bm,
            setup: median(setup),
            gen_p0: median(gen0),
            gen_p1: median(gen1),
            total: median(total),
            setup_bytes: o0.setup_stats.total_bytes(),
            gen_bytes: o0.gen_stats.total_bytes(),
            depth: o0.key.depth(),
            flights: o0.gen_stats.flights + o1.gen_stats.flights,
            and_gates: o0.and_gates,
            cots: 0,
            key_bytes: o0.key.size_bytes(),
        },
    );
}

fn main() {
    let opts = Opts::parse(&["floram"], 128, &[32, 128, 256, 512]);
    let mut rng = ChaCha20Rng::from_entropy();
    opts.for_each(|o| {
        if o.runs("gen") {
            bench_gen(o, &mut rng);
        }
        let beta = random_beta(&mut rng, o.out_bits);
        let (keys, _) = gen_reference(o.size, o.out_bits, rng.gen_range(0..o.size), &beta, [rng.gen(), rng.gen()]);
        if o.runs("eval") {
            let xs: Vec<u64> = (0..o.points).map(|_| rng.gen_range(0..o.size)).collect();
            let mut out = vec![Block::ZERO; keys[0].bm];
            bench_eval(o, keys[0].bm, &xs, |x| {
                keys[0].eval_point_into(x, &mut out);
                black_box(&out);
            });
        }
        if o.runs("full") {
            bench_full(o, keys[0].bm, || {
                black_box(keys[0].eval_full());
            });
        }
    });
}
