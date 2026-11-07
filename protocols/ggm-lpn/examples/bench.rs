//! Benchmarks for our template on a full GGM tree with the DGH+21 LPN-PRG.
//!
//! ```text
//! cargo run --release -p ggm-lpn --example bench-ggm-lpn -- <gen|eval|full|all> [--variant bin] [--nu ν] [options]
//! ```
//!
//! * `bin`: semi-honest, XOR-shared payload in `{0,1}^ℓ`, ℓ ≤ 256; a local
//!   top phase of `0 ≤ ν ≤ n` levels (`--nu`, default `min(1, n)`; the label
//!   gets `+nu<ν>` when it is given), the bottom levels' 2PC LPN-PRG calls
//!   in one batch.
//!
//! Setup is the base OTs and the Ferret bootstrap (`FerretConfig::B13`).
//! Preprocessing is the LPN-PRG correlations, the bit-times-block triples of
//! every level and the glue's two triples, all from Ferret COTs. `and_gates`
//! counts the bit products of Gen (the glue's two, one multiplexer per
//! bottom level). `eval` and `full` use dealer keys.

use dpf_common::bench::{bench_eval, bench_full, mean, print_gen, whole_gen, GenRow, Opts};
use dpf_common::ot::FerretConfig;
use dpf_common::stream::TreeMode;
use ggm_lpn::gen::gen_reference;
use ggm_lpn::{run_gen, Word};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use std::hint::black_box;

fn gen_bin(o: &Opts, rng: &mut ChaCha20Rng) {
    let (mut setup, mut pre, mut g0, mut g1, mut total) = (vec![], vec![], vec![], vec![], vec![]);
    let mut last = None;
    for _ in 0..o.reps {
        drop(last.take());
        let beta = Word::random(rng, o.out_bits);
        let (outs, times) = run_gen(o.size, o.nu, o.out_bits, beta, rng.gen(), FerretConfig::B13);
        setup.push(outs[0].setup_time.max(outs[1].setup_time));
        pre.push(outs[0].pre_time.max(outs[1].pre_time));
        g0.push(outs[0].gen_time);
        g1.push(outs[1].gen_time);
        total.push(times[0].max(times[1]));
        last = Some(outs);
    }
    let [o0, o1] = last.unwrap();
    let (sent, rounds) = whole_gen([o0.setup_stats, o1.setup_stats], [o0.pre_stats, o1.pre_stats], [o0.gen_stats, o1.gen_stats]);
    print_gen(
        o,
        &GenRow {
            bm: 1,
            sent,
            rounds,
            total: mean(total),
            setup: mean(setup),
            pre: mean(pre),
            gen_p0: mean(g0),
            gen_p1: mean(g1),
            setup_bytes: o0.setup_stats.total_bytes(),
            pre_bytes: o0.pre_stats.total_bytes(),
            pre_rounds: o0.pre_stats.rounds.max(o1.pre_stats.rounds),
            gen_bytes: o0.gen_stats.total_bytes(),
            depth: o0.key.depth(),
            gen_rounds: o0.gen_stats.rounds.max(o1.gen_stats.rounds),
            and_gates: o0.products,
            cots: o0.cots,
            key_bytes: o0.key.size_bytes(),
        },
    );
}

fn eval_bin(o: &Opts, rng: &mut ChaCha20Rng) {
    let xs: Vec<u64> = (0..o.points).map(|_| rng.gen_range(0..o.size)).collect();
    let beta = Word::random(rng, o.out_bits);
    let keys = gen_reference(o.size, o.nu, o.out_bits, rng.gen_range(0..o.size), beta, rng.gen());
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
                let mut acc = Word::ZERO;
                k.eval_full_stream(batch, |_, ys| acc = ys.iter().fold(acc, |a, &y| a ^ y));
                black_box(acc);
            }
        });
    }
}

fn main() {
    let opts = Opts::parse(&["bin"], 64, &[64, 128]);
    assert!(opts.out_list.iter().chain([&opts.out_bits]).all(|b| (1..=256).contains(b)), "out-bits must be 1..=256");
    let mut rng = ChaCha20Rng::from_entropy();
    opts.for_each(|o| {
        assert!(!(o.stream && o.runs("gen")), "Gen follows only the path to α: --stream applies to eval and full");
        let n = dpf_common::block::depth_for(o.size);
        assert!(o.nu.is_none_or(|nu| nu <= n), "the glue level is 0 ≤ ν ≤ n");
        if o.runs("gen") {
            gen_bin(o, &mut rng);
        }
        if o.runs("eval") || o.runs("full") {
            eval_bin(o, &mut rng);
        }
    });
}
