//! Benchmarks for Duoram's DPF (preprocessing plus online adjustment).
//!
//! ```text
//! cargo run --release -p duoram --example bench-duoram -- <gen|eval|full|all> --variant <2p|3p> [options]
//! ```
//!
//! `--out-bits w` (1..=64, default 64) is the payload ring Z_2^w. Options and
//! CSV columns are those of `dpf_common::bench`. For `gen`:
//!
//! * `gen_ms_p*` and `total_ms` cover preprocessing and the online phase.
//! * `gen_bytes` is all traffic on all links: P0↔P1 in both directions, plus
//!   P2's dealt correlations in 3P.
//! * `flights` counts P0's and P1's flights on all links.
//! * `cots` is 2P only.
//! * The online phase alone is two words each way in one flight; it is printed
//!   as a `#` comment line.
//!
//! `eval` and `full` use dealer keys.

use dpf_common::arith::mask;
use dpf_common::bench::{bench_eval, bench_full, median, print_gen, GenRow, Opts};
use duoram::{gen_reference, run_gen_2p, run_gen_3p};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use std::hint::black_box;

fn bench_gen(o: &Opts, rng: &mut ChaCha20Rng) {
    let (mut setup, mut g0, mut g1, mut total, mut onl) = (vec![], vec![], vec![], vec![], vec![]);
    let mut last = None;
    for _ in 0..o.reps {
        let beta = rng.gen::<u64>() & mask(o.out_bits);
        let (alpha, seed) = (rng.gen_range(0..o.size), rng.gen());
        let run = if o.variant == "3p" {
            run_gen_3p(o.size, o.out_bits, alpha, beta, seed)
        } else {
            run_gen_2p(o.size, o.out_bits, alpha, beta, seed)
        };
        let [r0, r1] = &run.outs;
        setup.push(r0.setup_time.max(r1.setup_time));
        g0.push(r0.pre_time + r0.online_time);
        g1.push(r1.pre_time + r1.online_time);
        onl.push(r0.online_time.max(r1.online_time));
        total.push(run.times[0].max(run.times[1]));
        last = Some(run);
    }
    let run = last.unwrap();
    let [o0, o1] = &run.outs;
    let link = o0.pre_stats.total_bytes() + o0.online_stats.total_bytes();
    let helper_flights = run.helper.map_or(0, |h| h.flights);
    print_gen(
        o,
        &GenRow {
            bm: 1,
            setup: median(setup),
            gen_p0: median(g0),
            gen_p1: median(g1),
            total: median(total),
            setup_bytes: o0.setup_stats.total_bytes(),
            gen_bytes: link + o0.helper_bytes + o1.helper_bytes,
            depth: o0.key.depth(),
            flights: o0.pre_stats.flights + o0.online_stats.flights + o1.pre_stats.flights + o1.online_stats.flights + helper_flights,
            and_gates: 0,
            cots: o0.cots,
            key_bytes: o0.key.size_bytes(),
        },
    );
    println!(
        "# online,{},{},bytes_both_dirs={},flights={},median_ms={:.3}",
        o.variant,
        o.size,
        o0.online_stats.total_bytes(),
        o0.online_stats.flights + o1.online_stats.flights,
        median(onl).as_secs_f64() * 1e3
    );
}

fn main() {
    let opts = Opts::parse(&["2p", "3p"], 64, &[16, 32, 64]);
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
