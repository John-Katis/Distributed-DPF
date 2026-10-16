//! Benchmarks for Duoram's DPF (preprocessing plus online adjustment).
//!
//! ```text
//! cargo run --release -p duoram --example bench-duoram -- <gen|eval|full|all> --variant <2p|3p> [options]
//! ```
//!
//! * `2p`: 2P-Duoram, P0 and P1 alone; correlations from IKNP OT.
//! * `3p`: 3P-Duoram, correlations dealt by the helper P2.
//!
//! `--out-bits w` (1..=64, default 64) is the payload ring Z_2^w. Options and
//! CSV columns are those of `dpf_common::bench`. For `gen`:
//!
//! * `comp_ms` covers setup, preprocessing and the online phase;
//!   `gen_ms_p*` only preprocessing and the online phase.
//! * `comm_p0`/`comm_p1` are what P0 and P1 send over setup, preprocessing
//!   and online; `comm_p2` is the correlations P2 deals in 3P.
//! * `gen_bytes` is all traffic on all links: P0↔P1 in both directions, plus
//!   P2's dealt correlations in 3P.
//! * `gen_rounds` is the larger of P0's and P1's preprocessing plus online
//!   rounds, and `rounds` adds setup. In 3P the P0–P1 link starts at depth 0,
//!   so P2's dealing round is included.
//! * `cots` is 2P only.
//! * The online phase alone is two words each way in one round; it is printed
//!   as a `#` comment line.
//!
//! `eval` and `full` use dealer keys. With `--stream`, preprocessing and the
//! dealer use the streaming tree and `full` folds the outputs.

use dpf_common::arith::mask;
use dpf_common::bench::{bench_eval, bench_full, median, print_gen, whole_gen, GenRow, Opts};
use duoram::{gen_reference_mode, run_gen_2p_mode, run_gen_3p_mode, TreeMode};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use std::hint::black_box;

fn bench_gen(o: &Opts, rng: &mut ChaCha20Rng) {
    let (mut setup, mut g0, mut g1, mut total, mut onl) = (vec![], vec![], vec![], vec![], vec![]);
    let mut last = None;
    for _ in 0..o.reps {
        // Free the previous run (full-domain outputs) before the next one.
        drop(last.take());
        let beta = rng.gen::<u64>() & mask(o.out_bits);
        let (alpha, seed) = (rng.gen_range(0..o.size), rng.gen());
        let run = if o.variant == "3p" {
            run_gen_3p_mode(o.size, o.out_bits, alpha, beta, seed, o.tree_mode())
        } else {
            run_gen_2p_mode(o.size, o.out_bits, alpha, beta, seed, o.tree_mode())
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
    let (mut sent, rounds) = whole_gen([o0.setup_stats, o1.setup_stats], [o0, o1].map(|r| r.pre_stats + r.online_stats));
    sent[2] = o0.helper_bytes + o1.helper_bytes;
    print_gen(
        o,
        &GenRow {
            bm: 1,
            sent,
            rounds,
            total: median(total),
            setup: median(setup),
            gen_p0: median(g0),
            gen_p1: median(g1),
            setup_bytes: o0.setup_stats.total_bytes(),
            gen_bytes: link + o0.helper_bytes + o1.helper_bytes,
            depth: o0.key.depth(),
            gen_rounds: (o0.pre_stats.rounds + o0.online_stats.rounds).max(o1.pre_stats.rounds + o1.online_stats.rounds),
            and_gates: 0,
            cots: o0.cots,
            key_bytes: o0.key.size_bytes(),
        },
    );
    println!(
        "# online,{},{},bytes_both_dirs={},rounds={},median_ms={:.3}",
        o.label(),
        o.size,
        o0.online_stats.total_bytes(),
        o0.online_stats.rounds.max(o1.online_stats.rounds),
        median(onl).as_secs_f64() * 1e3
    );
}

fn main() {
    let opts = Opts::parse(&["2p", "3p"], 64, &[16, 32, 64]);
    assert!((1..=64).contains(&opts.out_bits) && opts.out_list.iter().all(|b| (1..=64).contains(b)), "out-bits must be 1..=64");
    let mut rng = ChaCha20Rng::from_entropy();
    opts.for_each(|o| {
        match o.variant.as_str() {
            // Both variants produce the same key; they differ only in how the
            // preprocessing gets its correlations.
            "2p" | "3p" => {
                if o.runs("gen") {
                    bench_gen(o, &mut rng);
                }
                if !(o.runs("eval") || o.runs("full")) {
                    return;
                }
                let xs: Vec<u64> = (0..o.points).map(|_| rng.gen_range(0..o.size)).collect();
                let beta = rng.gen::<u64>() & mask(o.out_bits);
                let keys = gen_reference_mode(o.size, o.out_bits, rng.gen_range(0..o.size), beta, rng.gen(), o.tree_mode());
                let k = &keys[0];
                if o.runs("eval") {
                    bench_eval(o, 1, &xs, |x| {
                        black_box(k.eval_point(x));
                    });
                }
                if o.runs("full") {
                    bench_full(o, 1, || match o.tree_mode() {
                        TreeMode::Stored => {
                            black_box(k.eval_full());
                        }
                        TreeMode::Stream { batch } => {
                            let mut acc = 0u64;
                            k.eval_full_stream(batch, |_, y| acc = acc.wrapping_add(y));
                            black_box(acc);
                        }
                    });
                }
            }
            v => unreachable!("unknown variant {v}"),
        }
    });
}
