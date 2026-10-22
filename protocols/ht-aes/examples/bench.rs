//! Benchmarks for our distributed half-tree DPF with AES–MMO in 2PC.
//!
//! ```text
//! cargo run --release -p ht-aes --example bench-ht-aes -- <gen|eval|full|all> [--variant sh|mal|mal-auth] [options]
//! ```
//!
//! * `sh`: semi-honest, payload in Z_2^ℓ (`--out-bits` ≤ 128; 64-bit words up
//!   to ℓ = 64, 128-bit words above), F4 triples from FOLEAGE.
//! * `mal`: malicious on the same preprocessing, payload in
//!   `{0,1}^ℓ ⊂ GF(2^128)` with a payload MAC and Π_Verify.
//! * `mal-auth`: as `mal` with every share authenticated ((A1)–(A5)), F4
//!   triples from leaky authenticated triples on malicious Ferret.
//!
//! Setup is the base OTs, the Ferret bootstrap (`FerretConfig::B13`) and, for
//! `sh` and `mal`, the dealer-free FOLEAGE seed generation for the smallest
//! instance (≥ 3^12 OLEs) that covers one Gen; its traffic is printed as a `#`
//! line. Preprocessing is the FOLEAGE expansion into F4 triples, the string
//! triples and the Ferret COTs (for `mal-auth`: the authenticated triples).
//! `and_gates` counts F4 products. `eval` and `full` use dealer keys; `full`
//! holds the whole domain for `sh` and evaluates point by point (output and
//! MAC) for `mal` and `mal-auth`.

use dpf_common::arith::Ring;
use dpf_common::bench::{bench_eval, bench_full, median, print_gen, whole_gen, GenRow, Opts};
use dpf_common::block::depth_for;
use dpf_common::net::run_two_party;
use dpf_common::ot::FerretConfig;
use ht_aes::semi_honest::{foleage_for, gen, gen_reference};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use std::hint::black_box;
use std::time::Instant;

fn gen_sh<T: Ring>(o: &Opts, rng: &mut ChaCha20Rng) {
    let (mut setup, mut pre, mut g0, mut g1, mut total) = (vec![], vec![], vec![], vec![], vec![]);
    let mut last = None;
    let bits = o.out_bits;
    let fp = foleage_for(depth_for(o.size));
    for _ in 0..o.reps {
        drop(last.take());
        let alpha = rng.gen_range(0..o.size);
        let beta = T::random(rng).and(T::mask(bits));
        let a0: u64 = rng.gen::<u64>() & dpf_common::arith::mask(depth_for(o.size));
        let b0 = T::random(rng).and(T::mask(bits));
        let b1 = beta.sub(b0).and(T::mask(bits));
        let seeds: [[u8; 32]; 2] = [rng.gen(), rng.gen()];
        let n = o.size;
        let timed = |party: usize, a: u64, b: T| {
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
    println!(
        "# foleage: N={} oles={} seedgen_bytes={} seedgen_rounds={} seedgen_ms={:.1}",
        o0.foleage.log3,
        o0.foleage.oles(),
        o0.seedgen_stats.total_bytes(),
        o0.seedgen_stats.rounds.max(o1.seedgen_stats.rounds),
        o0.seedgen_time.max(o1.seedgen_time).as_secs_f64() * 1e3
    );
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

fn eval_sh<T: Ring>(o: &Opts, rng: &mut ChaCha20Rng) {
    let xs: Vec<u64> = (0..o.points).map(|_| rng.gen_range(0..o.size)).collect();
    let beta = T::random(rng).and(T::mask(o.out_bits));
    let keys = gen_reference::<T>(o.size, o.out_bits, rng.gen_range(0..o.size), beta, rng.gen());
    let k = &keys[0];
    if o.runs("eval") {
        bench_eval(o, 1, &xs, |x| {
            black_box(k.eval_point(x));
        });
    }
    if o.runs("full") {
        bench_full(o, 1, || {
            black_box(k.eval_full());
        });
    }
}

fn gen_mal(o: &Opts, rng: &mut ChaCha20Rng) {
    use ht_aes::malicious::{low, mal_foleage_for, run_mal};
    let (mut setup, mut pre, mut g0, mut g1, mut total) = (vec![], vec![], vec![], vec![], vec![]);
    let mut last = None;
    let bits = o.out_bits;
    let fp = mal_foleage_for(depth_for(o.size));
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
    println!(
        "# foleage: N={} oles={} seedgen_bytes={} seedgen_rounds={} seedgen_ms={:.1}",
        o0.foleage.log3,
        o0.foleage.oles(),
        o0.seedgen_stats.total_bytes(),
        o0.seedgen_stats.rounds.max(o1.seedgen_stats.rounds),
        o0.seedgen_time.max(o1.seedgen_time).as_secs_f64() * 1e3
    );
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
        bench_full(o, 1, || {
            black_box((0..o.size).map(|x| k.eval_point(x)).fold(dpf_common::block::Block::ZERO, |a, y| a ^ y.0 ^ y.1));
        });
    }
}

fn main() {
    let opts = Opts::parse(&["sh", "mal", "mal-auth"], 64, &[64, 128]);
    assert!(opts.out_list.iter().chain([&opts.out_bits]).all(|b| (1..=128).contains(b)), "out-bits must be 1..=128");
    assert!(!opts.stream, "ht-aes has no streaming tree: Gen follows only the path to α");
    let mut rng = ChaCha20Rng::from_entropy();
    opts.for_each(|o| {
        let wide = o.out_bits > 64;
        match o.variant.as_str() {
            "sh" => {
                if o.runs("gen") {
                    if wide { gen_sh::<u128>(o, &mut rng) } else { gen_sh::<u64>(o, &mut rng) }
                }
                if o.runs("eval") || o.runs("full") {
                    if wide { eval_sh::<u128>(o, &mut rng) } else { eval_sh::<u64>(o, &mut rng) }
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
