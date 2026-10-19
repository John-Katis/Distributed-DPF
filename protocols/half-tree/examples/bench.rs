//! Benchmarks for the Half-Tree distributed DPFs.
//!
//! ```text
//! cargo run --release -p half-tree --example bench-half-tree -- <gen|eval|full|all> --variant <ht|mal-ferret> [options]
//! ```
//!
//! * `ht`: semi-honest Half-Tree (GYW+23). `out_bits ≤ 127` uses the PRG-free
//!   Convert, wider payloads hash every leaf.
//! * `mal-ferret`: actively secure DPF with one-bit leakage (ZGY+24). The
//!   payload is `ceil(out_bits/128)` GF(2^128) elements, and every output also
//!   carries a MAC. `gen` covers input authentication, generation and the final
//!   MAC check. F_COT is Ferret (`FerretConfig::B13`), as in the paper's
//!   implementation: setup bootstraps Ferret and fills one ~10M-COT batch per
//!   direction; preprocessing refills only if that runs out, and generation
//!   then pays one bit per COT.
//!
//! Options and CSV columns are those of `dpf_common::bench`. Setup (base OTs,
//! COT/MAC-key initialisation, coin tosses) and preprocessing (the random
//! COTs, KOS-checked or from Ferret) are reported apart from generation, which
//! derandomises those COTs with one bit each. Gen builds the key only: `ht` skips
//! the full-domain output, and `mal-ferret` computes the outputs for the MAC
//! check but does not keep them. `eval` and `full` use dealer keys.
//! With `--stream`, Gen and the dealer use the streaming tree and `full` folds
//! the outputs instead of storing them.

use dpf_common::bench::{bench_eval, bench_full, median, print_gen, whole_gen, GenRow, Opts};
use dpf_common::block::{blocks_for_bits, depth_for};
use dpf_common::ot::FerretConfig;
use dpf_common::testing::random_beta;
use half_tree::{malicious, run_gen_mode, run_mal_gen_mode, semi_honest, Block, TreeMode};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use std::hint::black_box;

fn gen_ht(o: &Opts, rng: &mut ChaCha20Rng) {
    let (mut setup, mut pre, mut g0, mut g1, mut total) = (vec![], vec![], vec![], vec![], vec![]);
    let mut last = None;
    for _ in 0..o.reps {
        // Free the previous run before the next one.
        drop(last.take());
        let beta = random_beta(rng, o.out_bits);
        let run = run_gen_mode(o.size, o.out_bits, rng.gen_range(0..o.size), &beta, rng.gen(), o.tree_mode(), false);
        setup.push(run.outs[0].setup_time.max(run.outs[1].setup_time));
        pre.push(run.outs[0].pre_time.max(run.outs[1].pre_time));
        g0.push(run.outs[0].gen_time);
        g1.push(run.outs[1].gen_time);
        total.push(run.times[0].max(run.times[1]));
        last = Some(run);
    }
    let run = last.unwrap();
    let [o0, o1] = &run.outs;
    let (sent, rounds) = whole_gen([o0.setup_stats, o1.setup_stats], [o0.pre_stats, o1.pre_stats], [o0.gen_stats, o1.gen_stats]);
    print_gen(
        o,
        &GenRow {
            bm: o0.key.bm(),
            sent,
            rounds,
            total: median(total),
            setup: median(setup),
            pre: median(pre),
            gen_p0: median(g0),
            gen_p1: median(g1),
            setup_bytes: o0.setup_stats.total_bytes(),
            pre_bytes: o0.pre_stats.total_bytes(),
            pre_rounds: o0.pre_stats.rounds.max(o1.pre_stats.rounds),
            gen_bytes: o0.gen_stats.total_bytes(),
            depth: o0.key.depth(),
            gen_rounds: o0.gen_stats.rounds.max(o1.gen_stats.rounds),
            and_gates: 0,
            cots: o0.cots,
            key_bytes: o0.key.size_bytes(),
        },
    );
}

fn gen_mal(o: &Opts, rng: &mut ChaCha20Rng) {
    let bm = blocks_for_bits(o.out_bits);
    let (mut setup, mut pre, mut g0, mut g1, mut total) = (vec![], vec![], vec![], vec![], vec![]);
    let mut last = None;
    for _ in 0..o.reps {
        // Free the previous run before the next one.
        drop(last.take());
        let beta: Vec<Block> = (0..bm).map(|_| Block::random(rng)).collect();
        let run = run_mal_gen_mode(o.size, rng.gen_range(0..o.size), &beta, rng.gen(), [None, None], Some(FerretConfig::B13), o.tree_mode(), false);
        let [r0, r1] = run.outs.map(|r| r.expect("honest run aborted"));
        setup.push(r0.setup_time.max(r1.setup_time));
        pre.push(r0.pre_time.max(r1.pre_time));
        g0.push(r0.gen_time);
        g1.push(r1.gen_time);
        total.push(run.times[0].max(run.times[1]));
        last = Some((r0, r1));
    }
    let (r0, r1) = last.unwrap();
    let (sent, rounds) = whole_gen([r0.setup_stats, r1.setup_stats], [r0.pre_stats, r1.pre_stats], [r0.gen_stats, r1.gen_stats]);
    print_gen(
        o,
        &GenRow {
            bm,
            sent,
            rounds,
            total: median(total),
            setup: median(setup),
            pre: median(pre),
            gen_p0: median(g0),
            gen_p1: median(g1),
            setup_bytes: r0.setup_stats.total_bytes(),
            pre_bytes: r0.pre_stats.total_bytes(),
            pre_rounds: r0.pre_stats.rounds.max(r1.pre_stats.rounds),
            gen_bytes: r0.gen_stats.total_bytes(),
            depth: depth_for(o.size),
            gen_rounds: r0.gen_stats.rounds.max(r1.gen_stats.rounds),
            and_gates: 0,
            cots: r0.cots,
            key_bytes: r0.out.key.size_bytes(),
        },
    );
}

fn main() {
    let opts = Opts::parse(&["ht", "mal-ferret"], 128, &[32, 127, 128, 256, 512]);
    let mut rng = ChaCha20Rng::from_entropy();
    opts.for_each(|o| {
        match o.variant.as_str() {
            "ht" => {
                if o.runs("gen") {
                    gen_ht(o, &mut rng);
                }
                if !(o.runs("eval") || o.runs("full")) {
                    return;
                }
                let xs: Vec<u64> = (0..o.points).map(|_| rng.gen_range(0..o.size)).collect();
                let beta = random_beta(&mut rng, o.out_bits);
                let keys = semi_honest::gen_reference_keys(o.size, o.out_bits, rng.gen_range(0..o.size), &beta, rng.gen(), o.tree_mode());
                let k = &keys[0];
                if o.runs("eval") {
                    let mut out = vec![Block::ZERO; k.bm()];
                    bench_eval(o, k.bm(), &xs, |x| {
                        k.eval_point_into(x, &mut out);
                        black_box(&out);
                    });
                }
                if o.runs("full") {
                    bench_full(o, k.bm(), || match o.tree_mode() {
                        TreeMode::Stored => {
                            black_box(k.eval_full());
                        }
                        TreeMode::Stream { batch } => {
                            let mut acc = Block::ZERO;
                            k.eval_full_stream(batch, |_, cols| acc = cols.iter().flatten().fold(acc, |a, b| a ^ *b));
                            black_box(acc);
                        }
                    });
                }
            }
            _ => {
                if o.runs("gen") {
                    gen_mal(o, &mut rng);
                }
                if !(o.runs("eval") || o.runs("full")) {
                    return;
                }
                let xs: Vec<u64> = (0..o.points).map(|_| rng.gen_range(0..o.size)).collect();
                let bm = blocks_for_bits(o.out_bits);
                let beta: Vec<Block> = (0..bm).map(|_| Block::random(&mut rng)).collect();
                let (keys, _) = malicious::gen_reference_mode(o.size, rng.gen_range(0..o.size), &beta, rng.gen(), o.tree_mode());
                let k = &keys[0];
                if o.runs("eval") {
                    bench_eval(o, bm, &xs, |x| {
                        black_box(k.eval_point(x));
                    });
                }
                if o.runs("full") {
                    bench_full(o, bm, || match o.tree_mode() {
                        TreeMode::Stored => {
                            black_box(k.eval_full());
                        }
                        TreeMode::Stream { batch } => {
                            let mut acc = Block::ZERO;
                            k.eval_full_stream(batch, |_, part| {
                                acc = part.v.iter().flatten().chain(&part.u).fold(acc, |a, s| a ^ s.x ^ s.m);
                            });
                            black_box(acc);
                        }
                    });
                }
            }
        }
    });
}
