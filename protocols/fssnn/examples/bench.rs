//! Benchmarks for the FssNN-style distributed DPF.
//!
//! ```text
//! cargo run --release -p fssnn --example bench-fssnn -- <gen|eval|full|all> [--variant bin|arith] [options]
//! ```
//!
//! Both are semi-honest (Alg. 5 with the DGH+21 LPN-PRG in 2PC, correlations
//! from IKNP and KK13 OT) and differ only in the output group:
//!
//! * `bin`: `{0,1}^ℓ` under XOR, FssNN's Z2 for `--out-bits 1`;
//! * `arith`: the ring Z_2^ℓ.
//!
//! `--out-bits ℓ` is 1..=64 (default 64; the sweep uses 16,32,64). Options
//! and CSV columns are those of `dpf_common::bench`. Setup (base OTs of the
//! COT, bit-triple and 1-of-3 OT instances) is reported apart from
//! generation; the PRG correlations are part of generation, and `cots` also
//! counts the random OTs behind them. `eval` and `full` use dealer keys.

use dpf_common::arith::mask;
use dpf_common::bench::{bench_eval, bench_full, median, print_gen, whole_gen, GenRow, Opts};
use dpf_common::stream::TreeMode;
use fssnn::semi_honest;
use fssnn::{run_gen, Group};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use std::hint::black_box;

fn gen_sh(o: &Opts, group: Group, rng: &mut ChaCha20Rng) {
    let (mut setup, mut g0, mut g1, mut total) = (vec![], vec![], vec![], vec![]);
    let mut last = None;
    for _ in 0..o.reps {
        // Free the previous run (full-domain outputs) before the next one.
        drop(last.take());
        let beta = rng.gen::<u64>() & mask(o.out_bits);
        let run = run_gen(o.size, group, o.out_bits, rng.gen_range(0..o.size), beta, rng.gen());
        setup.push(run.outs[0].setup_time.max(run.outs[1].setup_time));
        g0.push(run.outs[0].gen_time);
        g1.push(run.outs[1].gen_time);
        total.push(run.times[0].max(run.times[1]));
        last = Some(run);
    }
    let run = last.unwrap();
    let [o0, o1] = &run.outs;
    let (sent, rounds) = whole_gen([o0.setup_stats, o1.setup_stats], [o0.gen_stats, o1.gen_stats]);
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
            gen_bytes: o0.gen_stats.total_bytes(),
            depth: o0.key.depth(),
            gen_rounds: o0.gen_stats.rounds.max(o1.gen_stats.rounds),
            and_gates: o0.and_gates,
            cots: o0.cots,
            key_bytes: o0.key.size_bytes(),
        },
    );
}

fn main() {
    let opts = Opts::parse(&["bin", "arith"], 64, &[16, 32, 64]);
    assert!((1..=64).contains(&opts.out_bits) && opts.out_list.iter().all(|b| (1..=64).contains(b)), "out-bits must be 1..=64");
    let mut rng = ChaCha20Rng::from_entropy();
    opts.for_each(|o| {
        let group = match o.variant.as_str() {
            "bin" => Group::Xor,
            "arith" => Group::Arith,
            v => unreachable!("unknown variant {v}"),
        };
        if o.runs("gen") {
            gen_sh(o, group, &mut rng);
        }
        if !(o.runs("eval") || o.runs("full")) {
            return;
        }
        let xs: Vec<u64> = (0..o.points).map(|_| rng.gen_range(0..o.size)).collect();
        let beta = rng.gen::<u64>() & mask(o.out_bits);
        let keys = semi_honest::gen_reference(o.size, group, o.out_bits, rng.gen_range(0..o.size), beta, rng.gen());
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
                    k.eval_full_stream(batch, |_, ys| acc = ys.iter().fold(acc, |a, y| a ^ y));
                    black_box(acc);
                }
            });
        }
    });
}
