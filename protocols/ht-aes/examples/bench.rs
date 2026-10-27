//! Benchmarks for our distributed half-tree DPF with AES–MMO in 2PC.
//!
//! ```text
//! cargo run --release -p ht-aes --example bench-ht-aes -- <gen|eval|full|all> [--variant sh|sh-bin|mal|mal-arith|mal-auth] [options]
//! ```
//!
//! * `sh`: semi-honest, payload in F_p (Goldilocks for `--out-bits` ≤ 64,
//!   `2^127 − 1` above), the paper's leaf (daBits, one Beaver triple), F4
//!   triples from FOLEAGE.
//! * `sh-bin`: semi-honest, payload in F_2^ℓ (no B2A at the leaf).
//! * `mal`: malicious on the same preprocessing, payload in
//!   `{0,1}^ℓ ⊂ GF(2^128)` with a payload MAC and Π_Verify.
//! * `mal-arith`: malicious on the same preprocessing, payload and MAC in F_p:
//!   Goldilocks for `--out-bits` ≤ 64, `2^127 − 1` above.
//! * `mal-auth`: as `mal` with every share authenticated ((A1)–(A5)), F4
//!   triples from leaky authenticated triples on malicious Ferret.
//!
//! Setup is the base OTs, the Ferret bootstrap (`FerretConfig::B13`) and, for
//! `sh` and `mal`, the dealer-free FOLEAGE seed generation for the smallest
//! instance (≥ 3^12 OLEs) that covers one Gen; its traffic is printed as a `#`
//! line. Preprocessing is the FOLEAGE expansion into F4 triples, the string
//! triples and the Ferret COTs (for `mal-auth`: the authenticated triples).
//! `and_gates` counts F4 products. `eval` and `full` use dealer keys; `full`
//! evaluates the whole domain (output and, for `mal` and `mal-auth`, MAC) one
//! level at a time, or with `--stream` in a batched walk that folds the
//! outputs into a checksum. Gen only follows the path to α, so `--stream`
//! applies to `eval` and `full` only.

use dpf_common::bench::{bench_eval, bench_full, median, print_gen, whole_gen, GenRow, Opts};
use dpf_common::block::depth_for;
use dpf_common::net::run_two_party;
use dpf_common::ot::FerretConfig;
use dpf_common::stream::TreeMode;
use ht_aes::field::{Field, Gold, M127};
use dpf_common::foleage::Params;
use dpf_common::net::CommStats;
use ht_aes::semi_honest::{gen, gen_reference, F4Source};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use std::hint::black_box;
use std::time::Instant;

/// `--f4`: `foleage` is the smallest c = 4 instance (≥ 3^12) for one Gen,
/// `foleage-c<c>` the largest instance outside the attack of ePrint 2025/892
/// for that c, `ot` F4 triples from Ferret random COTs.
fn f4_source(o: &Opts, products: usize) -> F4Source {
    match o.f4.as_str() {
        "foleage" => Params::for_oles(2 * products).into(),
        "ot" => F4Source::Ot,
        s => {
            let c: usize = s.strip_prefix("foleage-c").and_then(|c| c.parse().ok()).expect("--f4 foleage|foleage-c<c>|ot");
            let p = Params::with_c(Params::max_log3(c), c);
            assert!(p.oles() >= 2 * products, "3^{} OLEs do not cover one Gen", p.log3);
            p.into()
        }
    }
}

/// The FOLEAGE seed generation, and its share per key when the instance
/// serves `⌊3^N / (2·products)⌋` Gens.
fn print_f4(fp: Option<Params>, seedgen: [CommStats; 2], time: std::time::Duration, products: usize) {
    if let Some(p) = fp {
        let keys = p.oles() / (2 * products);
        let bytes = seedgen[0].total_bytes();
        println!(
            "# foleage: c={} N={} oles={} seedgen_bytes={} seedgen_rounds={} seedgen_ms={:.1} keys_per_instance={} seedgen_bytes_per_key={}",
            p.c,
            p.log3,
            p.oles(),
            bytes,
            seedgen[0].rounds.max(seedgen[1].rounds),
            time.as_secs_f64() * 1e3,
            keys,
            bytes / keys
        );
    }
}

fn gen_sh<F: Field>(o: &Opts, rng: &mut ChaCha20Rng) {
    let (mut setup, mut pre, mut g0, mut g1, mut total) = (vec![], vec![], vec![], vec![], vec![]);
    let mut last = None;
    let fp = f4_source(o, ht_aes::sh_products(depth_for(o.size)));
    for _ in 0..o.reps {
        drop(last.take());
        let alpha = rng.gen_range(0..o.size);
        let beta = F::random(rng);
        let a0: u64 = rng.gen::<u64>() & dpf_common::arith::mask(depth_for(o.size));
        let b0 = F::random(rng);
        let b1 = beta.sub(b0);
        let seeds: [[u8; 32]; 2] = [rng.gen(), rng.gen()];
        let n = o.size;
        let timed = |party: usize, a: u64, b: F| {
            move |c: &mut dpf_common::net::Channel| {
                let t = Instant::now();
                let out = gen(c, n, a, b, seeds[party], Some(FerretConfig::B13), fp);
                (out, t.elapsed())
            }
        };
        let ((r0, t0), (r1, t1)) = run_two_party(timed(0, a0, b0), timed(1, alpha ^ a0, b1));
        setup.push(r0.setup_time.max(r1.setup_time));
        pre.push(r0.pre_time.max(r1.pre_time));
        g0.push(r0.gen_time);
        g1.push(r1.gen_time);
        total.push(t0.max(t1));
        last = Some((r0, r1));
    }
    let (o0, o1) = last.unwrap();
    let (sent, rounds) = whole_gen([o0.setup_stats, o1.setup_stats], [o0.pre_stats, o1.pre_stats], [o0.gen_stats, o1.gen_stats]);
    print_f4(o0.foleage, [o0.seedgen_stats, o1.seedgen_stats], o0.seedgen_time.max(o1.seedgen_time), o0.products);
    print_gen(
        o,
        &GenRow {
            bm: 1,
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
            and_gates: o0.products,
            cots: o0.cots,
            key_bytes: o0.key.size_bytes(),
        },
    );
}

fn eval_sh<F: Field>(o: &Opts, rng: &mut ChaCha20Rng) {
    let xs: Vec<u64> = (0..o.points).map(|_| rng.gen_range(0..o.size)).collect();
    let beta = F::random(rng);
    let keys = gen_reference::<F>(o.size, rng.gen_range(0..o.size), beta, rng.gen());
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
                let mut acc = F::ZERO;
                k.eval_full_stream(batch, |_, ys| acc = ys.iter().fold(acc, |a, y| a.add(*y)));
                black_box(acc);
            }
        });
    }
}

fn gen_mal(o: &Opts, rng: &mut ChaCha20Rng) {
    use ht_aes::malicious::{low, run_mal};
    let (mut setup, mut pre, mut g0, mut g1, mut total) = (vec![], vec![], vec![], vec![], vec![]);
    let mut last = None;
    let bits = o.out_bits;
    let fp = f4_source(o, ht_aes::malicious::mal_products(depth_for(o.size)));
    for _ in 0..o.reps {
        drop(last.take());
        let alpha = rng.gen_range(0..o.size);
        let a0: u64 = rng.gen::<u64>() & dpf_common::arith::mask(depth_for(o.size));
        let b0 = low(dpf_common::block::Block::random(rng), bits);
        let b1 = low(dpf_common::block::Block::random(rng), bits) ^ b0;
        let seeds: [[u8; 32]; 2] = [rng.gen(), rng.gen()];
        let n = o.size;
        let timed = |party: usize, a: u64, b: dpf_common::block::Block| {
            move |c: &mut dpf_common::net::Channel| {
                let t = Instant::now();
                let out = run_mal(c, n, bits, a, b, seeds[party], Some(FerretConfig::B13), fp, None);
                (out, t.elapsed())
            }
        };
        let ((r0, t0), (r1, t1)) = run_two_party(timed(0, a0, b0), timed(1, alpha ^ a0, b1));
        setup.push(r0.setup_time.max(r1.setup_time));
        pre.push(r0.pre_time.max(r1.pre_time));
        g0.push(r0.gen_time);
        g1.push(r1.gen_time);
        total.push(t0.max(t1));
        last = Some((r0, r1));
    }
    let (o0, o1) = last.unwrap();
    let (sent, rounds) = whole_gen([o0.setup_stats, o1.setup_stats], [o0.pre_stats, o1.pre_stats], [o0.gen_stats, o1.gen_stats]);
    print_f4(o0.foleage, [o0.seedgen_stats, o1.seedgen_stats], o0.seedgen_time.max(o1.seedgen_time), o0.products);
    print_gen(
        o,
        &GenRow {
            bm: 1,
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
            and_gates: o0.products,
            cots: o0.cots,
            key_bytes: o0.key.size_bytes(),
        },
    );
}

fn gen_mal_auth(o: &Opts, rng: &mut ChaCha20Rng) {
    use ht_aes::malicious_auth::{low, run_mal};
    let (mut setup, mut pre, mut g0, mut g1, mut total) = (vec![], vec![], vec![], vec![], vec![]);
    let mut last = None;
    let bits = o.out_bits;
    for _ in 0..o.reps {
        drop(last.take());
        let alpha = rng.gen_range(0..o.size);
        let a0: u64 = rng.gen::<u64>() & dpf_common::arith::mask(depth_for(o.size));
        let b0 = low(dpf_common::block::Block::random(rng), bits);
        let b1 = low(dpf_common::block::Block::random(rng), bits) ^ b0;
        let seeds: [[u8; 32]; 2] = [rng.gen(), rng.gen()];
        let n = o.size;
        let timed = |party: usize, a: u64, b: dpf_common::block::Block| {
            move |c: &mut dpf_common::net::Channel| {
                let t = Instant::now();
                let out = run_mal(c, n, bits, a, b, seeds[party], Some(FerretConfig::B13), None).expect("honest run aborted");
                (out, t.elapsed())
            }
        };
        let ((r0, t0), (r1, t1)) = run_two_party(timed(0, a0, b0), timed(1, alpha ^ a0, b1));
        setup.push(r0.setup_time.max(r1.setup_time));
        pre.push(r0.pre_time.max(r1.pre_time));
        g0.push(r0.gen_time);
        g1.push(r1.gen_time);
        total.push(t0.max(t1));
        last = Some((r0, r1));
    }
    let (o0, o1) = last.unwrap();
    let (sent, rounds) = whole_gen([o0.setup_stats, o1.setup_stats], [o0.pre_stats, o1.pre_stats], [o0.gen_stats, o1.gen_stats]);
    print_gen(
        o,
        &GenRow {
            bm: 1,
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
            and_gates: o0.products,
            cots: o0.cots,
            key_bytes: o0.key.size_bytes(),
        },
    );
}

fn eval_mal(o: &Opts, rng: &mut ChaCha20Rng) {
    use ht_aes::malicious::{gen_reference, low};
    let xs: Vec<u64> = (0..o.points).map(|_| rng.gen_range(0..o.size)).collect();
    let beta = low(dpf_common::block::Block::random(rng), o.out_bits);
    let (keys, _) = gen_reference(o.size, o.out_bits, rng.gen_range(0..o.size), beta, rng.gen());
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
                let mut acc = dpf_common::block::Block::ZERO;
                k.eval_full_stream(batch, |_, outs| acc = outs.iter().fold(acc, |a, y| a ^ y.0 ^ y.1));
                black_box(acc);
            }
        });
    }
}

fn gen_sh_bin(o: &Opts, rng: &mut ChaCha20Rng) {
    use ht_aes::malicious::low;
    use ht_aes::semi_honest::bin::gen;
    let (mut setup, mut pre, mut g0, mut g1, mut total) = (vec![], vec![], vec![], vec![], vec![]);
    let mut last = None;
    let bits = o.out_bits;
    let fp = f4_source(o, ht_aes::sh_products(depth_for(o.size)));
    for _ in 0..o.reps {
        drop(last.take());
        let alpha = rng.gen_range(0..o.size);
        let a0: u64 = rng.gen::<u64>() & dpf_common::arith::mask(depth_for(o.size));
        let b0 = low(dpf_common::block::Block::random(rng), bits);
        let b1 = low(dpf_common::block::Block::random(rng), bits) ^ b0;
        let seeds: [[u8; 32]; 2] = [rng.gen(), rng.gen()];
        let n = o.size;
        let timed = |party: usize, a: u64, b: dpf_common::block::Block| {
            move |c: &mut dpf_common::net::Channel| {
                let t = Instant::now();
                let out = gen(c, n, bits, a, b, seeds[party], Some(FerretConfig::B13), fp);
                (out, t.elapsed())
            }
        };
        let ((r0, t0), (r1, t1)) = run_two_party(timed(0, a0, b0), timed(1, alpha ^ a0, b1));
        setup.push(r0.setup_time.max(r1.setup_time));
        pre.push(r0.pre_time.max(r1.pre_time));
        g0.push(r0.gen_time);
        g1.push(r1.gen_time);
        total.push(t0.max(t1));
        last = Some((r0, r1));
    }
    let (o0, o1) = last.unwrap();
    let (sent, rounds) = whole_gen([o0.setup_stats, o1.setup_stats], [o0.pre_stats, o1.pre_stats], [o0.gen_stats, o1.gen_stats]);
    print_f4(o0.foleage, [o0.seedgen_stats, o1.seedgen_stats], o0.seedgen_time.max(o1.seedgen_time), o0.products);
    print_gen(
        o,
        &GenRow {
            bm: 1,
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
            and_gates: o0.products,
            cots: o0.cots,
            key_bytes: o0.key.size_bytes(),
        },
    );
}

fn eval_sh_bin(o: &Opts, rng: &mut ChaCha20Rng) {
    use ht_aes::malicious::low;
    use ht_aes::semi_honest::bin::gen_reference;
    let xs: Vec<u64> = (0..o.points).map(|_| rng.gen_range(0..o.size)).collect();
    let beta = low(dpf_common::block::Block::random(rng), o.out_bits);
    let keys = gen_reference(o.size, o.out_bits, rng.gen_range(0..o.size), beta, rng.gen());
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
                let mut acc = dpf_common::block::Block::ZERO;
                k.eval_full_stream(batch, |_, ys| acc = ys.iter().fold(acc, |a, y| a ^ *y));
                black_box(acc);
            }
        });
    }
}

fn gen_mal_arith<F: Field>(o: &Opts, rng: &mut ChaCha20Rng) {
    use ht_aes::malicious_arith::run_mal_arith;
    let (mut setup, mut pre, mut g0, mut g1, mut total) = (vec![], vec![], vec![], vec![], vec![]);
    let mut last = None;
    let fp = f4_source(o, ht_aes::malicious::mal_products(depth_for(o.size)));
    for _ in 0..o.reps {
        drop(last.take());
        let alpha = rng.gen_range(0..o.size);
        let a0: u64 = rng.gen::<u64>() & dpf_common::arith::mask(depth_for(o.size));
        let (b0, beta) = (F::random(rng), F::random(rng));
        let seeds: [[u8; 32]; 2] = [rng.gen(), rng.gen()];
        let n = o.size;
        let timed = |party: usize, a: u64, b: F| {
            move |c: &mut dpf_common::net::Channel| {
                let t = Instant::now();
                let out = run_mal_arith(c, n, a, b, seeds[party], Some(FerretConfig::B13), fp, None);
                (out, t.elapsed())
            }
        };
        let ((r0, t0), (r1, t1)) = run_two_party(timed(0, a0, b0), timed(1, alpha ^ a0, beta.sub(b0)));
        setup.push(r0.setup_time.max(r1.setup_time));
        pre.push(r0.pre_time.max(r1.pre_time));
        g0.push(r0.gen_time);
        g1.push(r1.gen_time);
        total.push(t0.max(t1));
        last = Some((r0, r1));
    }
    let (o0, o1) = last.unwrap();
    let (sent, rounds) = whole_gen([o0.setup_stats, o1.setup_stats], [o0.pre_stats, o1.pre_stats], [o0.gen_stats, o1.gen_stats]);
    print_f4(o0.foleage, [o0.seedgen_stats, o1.seedgen_stats], o0.seedgen_time.max(o1.seedgen_time), o0.products);
    print_gen(
        o,
        &GenRow {
            bm: 1,
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
            and_gates: o0.products,
            cots: o0.cots,
            key_bytes: o0.key.size_bytes(),
        },
    );
}

fn eval_mal_arith<F: Field>(o: &Opts, rng: &mut ChaCha20Rng) {
    use ht_aes::malicious_arith::gen_reference;
    let xs: Vec<u64> = (0..o.points).map(|_| rng.gen_range(0..o.size)).collect();
    let (keys, _) = gen_reference(o.size, rng.gen_range(0..o.size), F::random(rng), rng.gen());
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
                let mut acc = F::ZERO;
                k.eval_full_stream(batch, |_, outs| acc = outs.iter().fold(acc, |a, y| a.add(y.0).add(y.1)));
                black_box(acc);
            }
        });
    }
}

fn main() {
    let opts = Opts::parse(&["sh", "sh-bin", "mal", "mal-arith", "mal-auth"], 64, &[64, 128]);
    assert!(opts.out_list.iter().chain([&opts.out_bits]).all(|b| (1..=128).contains(b)), "out-bits must be 1..=128");
    let mut rng = ChaCha20Rng::from_entropy();
    opts.for_each(|o| {
        assert!(!(o.stream && o.runs("gen")), "ht-aes Gen has no streaming tree: it follows only the path to α");
        let wide = o.out_bits > 64;
        match o.variant.as_str() {
            "sh" => {
                if o.runs("gen") {
                    if wide { gen_sh::<M127>(o, &mut rng) } else { gen_sh::<Gold>(o, &mut rng) }
                }
                if o.runs("eval") || o.runs("full") {
                    if wide { eval_sh::<M127>(o, &mut rng) } else { eval_sh::<Gold>(o, &mut rng) }
                }
            }
            "sh-bin" => {
                if o.runs("gen") {
                    gen_sh_bin(o, &mut rng);
                }
                if o.runs("eval") || o.runs("full") {
                    eval_sh_bin(o, &mut rng);
                }
            }
            "mal-arith" => {
                if o.runs("gen") {
                    if wide { gen_mal_arith::<M127>(o, &mut rng) } else { gen_mal_arith::<Gold>(o, &mut rng) }
                }
                if o.runs("eval") || o.runs("full") {
                    if wide { eval_mal_arith::<M127>(o, &mut rng) } else { eval_mal_arith::<Gold>(o, &mut rng) }
                }
            }
            "mal" | "mal-auth" => {
                if o.runs("gen") {
                    if o.variant == "mal" { gen_mal(o, &mut rng) } else { gen_mal_auth(o, &mut rng) }
                }
                if o.runs("eval") || o.runs("full") {
                    eval_mal(o, &mut rng);
                }
            }
            v => unreachable!("unknown variant {v}"),
        }
    });
}
