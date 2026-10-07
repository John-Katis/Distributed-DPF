//! Benchmarks for the Half-Tree distributed DPFs.
//!
//! ```text
//! cargo run --release -p half-tree --example bench-half-tree -- <gen|eval|full|all> --variant <ht|mal> [options]
//! ```
//!
//! * `ht`: semi-honest Half-Tree (GYW+23). `out_bits ≤ 127` uses the PRG-free
//!   Convert, wider payloads hash every leaf.
//! * `mal`: actively secure DPF with one-bit leakage (ZGY+24). The payload is
//!   `ceil(out_bits/128)` GF(2^128) elements, and every output also carries a MAC.
//!   `gen` covers input authentication, generation and the final MAC check.
//!
//! Options and CSV columns are those of `dpf_common::bench`. Setup (base OTs,
//! COT/MAC-key initialisation, coin tosses) is reported apart from generation;
//! COT extension is part of generation. `eval` and `full` use dealer keys.

use dpf_common::bench::{bench_eval, bench_full, median, print_gen, GenRow, Opts};
use dpf_common::block::{blocks_for_bits, depth_for};
use dpf_common::testing::random_beta;
use half_tree::{malicious, run_gen, run_mal_gen, semi_honest, Block};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use std::hint::black_box;

fn gen_ht(o: &Opts, rng: &mut ChaCha20Rng) {
    let (mut setup, mut g0, mut g1, mut total) = (vec![], vec![], vec![], vec![]);
    let mut last = None;
    for _ in 0..o.reps {
        let beta = random_beta(rng, o.out_bits);
        let run = run_gen(o.size, o.out_bits, rng.gen_range(0..o.size), &beta, rng.gen());
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
            bm: o0.key.bm(),
            setup: median(setup),
            gen_p0: median(g0),
            gen_p1: median(g1),
            total: median(total),
            setup_bytes: o0.setup_stats.total_bytes(),
            gen_bytes: o0.gen_stats.total_bytes(),
            depth: o0.key.depth(),
            flights: o0.gen_stats.flights + o1.gen_stats.flights,
            and_gates: 0,
            cots: o0.cots,
            key_bytes: o0.key.size_bytes(),
        },
    );
}

fn gen_mal(o: &Opts, rng: &mut ChaCha20Rng) {
    let bm = blocks_for_bits(o.out_bits);
    let (mut setup, mut g0, mut g1, mut total) = (vec![], vec![], vec![], vec![]);
    let mut last = None;
    for _ in 0..o.reps {
        let beta: Vec<Block> = (0..bm).map(|_| Block::random(rng)).collect();
        let run = run_mal_gen(o.size, rng.gen_range(0..o.size), &beta, rng.gen(), [None, None]);
        let [r0, r1] = run.outs.map(|r| r.expect("honest run aborted"));
        setup.push(r0.setup_time.max(r1.setup_time));
        g0.push(r0.gen_time);
        g1.push(r1.gen_time);
        total.push(run.times[0].max(run.times[1]));
        last = Some((r0, r1));
    }
    let (r0, r1) = last.unwrap();
    print_gen(
        o,
        &GenRow {
            bm,
            setup: median(setup),
            gen_p0: median(g0),
            gen_p1: median(g1),
            total: median(total),
            setup_bytes: r0.setup_stats.total_bytes(),
            gen_bytes: r0.gen_stats.total_bytes(),
            depth: depth_for(o.size),
            flights: r0.gen_stats.flights + r1.gen_stats.flights,
            and_gates: 0,
            cots: r0.cots,
            key_bytes: r0.out.key.size_bytes(),
        },
    );
}

fn main() {
    let opts = Opts::parse(&["ht", "mal"], 128, &[32, 127, 128, 256, 512]);
    let mut rng = ChaCha20Rng::from_entropy();
    opts.for_each(|o| {
        let xs: Vec<u64> = (0..o.points).map(|_| rng.gen_range(0..o.size)).collect();
        match o.variant.as_str() {
            "ht" => {
                if o.runs("gen") {
                    gen_ht(o, &mut rng);
                }
                let beta = random_beta(&mut rng, o.out_bits);
                let (keys, _) = semi_honest::gen_reference(o.size, o.out_bits, rng.gen_range(0..o.size), &beta, rng.gen());
                let k = &keys[0];
                if o.runs("eval") {
                    let mut out = vec![Block::ZERO; k.bm()];
                    bench_eval(o, k.bm(), &xs, |x| {
                        k.eval_point_into(x, &mut out);
                        black_box(&out);
                    });
                }
                if o.runs("full") {
                    bench_full(o, k.bm(), || {
                        black_box(k.eval_full());
                    });
                }
            }
            _ => {
                if o.runs("gen") {
                    gen_mal(o, &mut rng);
                }
                let bm = blocks_for_bits(o.out_bits);
                let beta: Vec<Block> = (0..bm).map(|_| Block::random(&mut rng)).collect();
                let (keys, _) = malicious::gen_reference(o.size, rng.gen_range(0..o.size), &beta, rng.gen());
                let k = &keys[0];
                if o.runs("eval") {
                    bench_eval(o, bm, &xs, |x| {
                        black_box(k.eval_point(x));
                    });
                }
                if o.runs("full") {
                    bench_full(o, bm, || {
                        black_box(k.eval_full());
                    });
                }
            }
        }
    });
}
