//! Benchmarks for the Floram-CPRG distributed DPF.
//!
//! ```text
//! cargo run --release -p floram-cprg --example bench -- <gen|eval|full|all> [options]
//!
//!   --in-bits n        domain 2^n (default 16)
//!   --size N           any domain size N >= 2 (overrides --in-bits)
//!   --out-bits m       payload bits (default 128); bm = ceil(m/128) blocks
//!   --reps R           repetitions; the median is reported (default 5)
//!   --points P         points per repetition in `eval` (default 100000)
//!   --sweep            sweep in-bits over 8..=max-in-bits and out-bits over --out-list
//!   --max-in-bits n    upper end of the sweep (default 20)
//!   --out-list a,b,..  out-bits used by the sweep (default 32,128,256,512)
//! ```
//!
//! Output is CSV on stdout. Communication is counted by the in-process
//! network: setup (PRG keys + base OTs) is reported apart from generation, and
//! bytes are summed over both directions. `flights` is the number of one-way
//! message flights in generation; a round trip is two.

use dpf_common::testing::random_beta;
use floram_cprg::{gen_reference, run_gen, Block};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use std::hint::black_box;
use std::time::{Duration, Instant};

#[derive(Clone)]
struct Opts {
    mode: String,
    size: u64,
    out_bits: usize,
    reps: usize,
    points: usize,
    sweep: bool,
    max_in_bits: u32,
    out_list: Vec<usize>,
}

fn parse() -> Opts {
    let mut o = Opts {
        mode: "all".into(),
        size: 1 << 16,
        out_bits: 128,
        reps: 5,
        points: 100_000,
        sweep: false,
        max_in_bits: 20,
        out_list: vec![32, 128, 256, 512],
    };
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    let val = |i: usize| -> &str { args.get(i + 1).map(String::as_str).expect("missing flag value") };
    while i < args.len() {
        match args[i].as_str() {
            "gen" | "eval" | "full" | "all" => o.mode = args[i].clone(),
            "--in-bits" => { o.size = 1u64 << val(i).parse::<u32>().unwrap(); i += 1; }
            "--size" => { o.size = val(i).parse().unwrap(); i += 1; }
            "--out-bits" => { o.out_bits = val(i).parse().unwrap(); i += 1; }
            "--reps" => { o.reps = val(i).parse().unwrap(); i += 1; }
            "--points" => { o.points = val(i).parse().unwrap(); i += 1; }
            "--max-in-bits" => { o.max_in_bits = val(i).parse().unwrap(); i += 1; }
            "--out-list" => { o.out_list = val(i).split(',').map(|x| x.parse().unwrap()).collect(); i += 1; }
            "--sweep" => o.sweep = true,
            "-h" | "--help" => {
                eprintln!("usage: bench <gen|eval|full|all> [--in-bits n | --size N] [--out-bits m] [--reps R] [--points P] [--sweep [--max-in-bits n] [--out-list a,b]]");
                std::process::exit(0);
            }
            other => panic!("unknown argument {other}"),
        }
        i += 1;
    }
    assert!(o.size >= 2 && o.reps >= 1);
    o
}

fn median(mut v: Vec<Duration>) -> Duration {
    v.sort();
    v[v.len() / 2]
}

fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1e3
}

fn in_bits(n: u64) -> f64 {
    (n as f64).log2()
}

fn random_instance(rng: &mut ChaCha20Rng, n: u64, out_bits: usize) -> (u64, Vec<Block>) {
    let beta = random_beta(rng, out_bits);
    (rng.gen_range(0..n), beta)
}

fn bench_gen(o: &Opts, rng: &mut ChaCha20Rng) {
    let (mut setup, mut gen0, mut gen1, mut total) = (vec![], vec![], vec![], vec![]);
    let mut last = None;
    for r in 0..o.reps {
        let (alpha, beta) = random_instance(rng, o.size, o.out_bits);
        let run = run_gen(o.size, o.out_bits, alpha, &beta, rng.gen::<u64>() ^ r as u64);
        setup.push(run.outs[0].setup_time.max(run.outs[1].setup_time));
        gen0.push(run.outs[0].gen_time);
        gen1.push(run.outs[1].gen_time);
        total.push(run.times[0].max(run.times[1]));
        last = Some(run);
    }
    let run = last.unwrap();
    let [o0, o1] = &run.outs;
    let depth = o0.key.depth();
    let gen_bytes = o0.gen_stats.total_bytes();
    println!(
        "gen,{},{:.2},{},{},{},{:.3},{:.3},{:.3},{:.3},{},{},{:.0},{},{},{}",
        o.size,
        in_bits(o.size),
        o.out_bits,
        o0.key.bm,
        o.reps,
        ms(median(setup)),
        ms(median(gen0)),
        ms(median(gen1)),
        ms(median(total)),
        o0.setup_stats.total_bytes(),
        gen_bytes,
        gen_bytes as f64 / depth as f64,
        o0.gen_stats.flights + o1.gen_stats.flights,
        o0.and_gates,
        o0.key.size_bytes(),
    );
}

fn bench_eval(o: &Opts, rng: &mut ChaCha20Rng) {
    let (alpha, beta) = random_instance(rng, o.size, o.out_bits);
    let (keys, _) = gen_reference(o.size, o.out_bits, alpha, &beta, [rng.gen(), rng.gen()]);
    let key = &keys[0];
    let xs: Vec<u64> = (0..o.points).map(|_| rng.gen_range(0..o.size)).collect();
    let mut out = vec![Block::ZERO; key.bm];
    let mut times = vec![];
    for _ in 0..o.reps {
        let t = Instant::now();
        for &x in &xs {
            key.eval_point_into(black_box(x), &mut out);
            black_box(&out);
        }
        times.push(t.elapsed());
    }
    let per = median(times).as_secs_f64() * 1e9 / o.points as f64;
    println!("eval,{},{:.2},{},{},{},{},{:.1}", o.size, in_bits(o.size), o.out_bits, key.bm, o.reps, o.points, per);
}

fn bench_full(o: &Opts, rng: &mut ChaCha20Rng) {
    let (alpha, beta) = random_instance(rng, o.size, o.out_bits);
    let (keys, _) = gen_reference(o.size, o.out_bits, alpha, &beta, [rng.gen(), rng.gen()]);
    let mut times = vec![];
    for _ in 0..o.reps {
        let t = Instant::now();
        black_box(keys[0].eval_full());
        times.push(t.elapsed());
    }
    let m = median(times);
    println!(
        "full,{},{:.2},{},{},{},{:.3},{:.2}",
        o.size,
        in_bits(o.size),
        o.out_bits,
        keys[0].bm,
        o.reps,
        ms(m),
        m.as_secs_f64() * 1e9 / o.size as f64
    );
}

fn run_one(o: &Opts, rng: &mut ChaCha20Rng) {
    match o.mode.as_str() {
        "gen" => bench_gen(o, rng),
        "eval" => bench_eval(o, rng),
        "full" => bench_full(o, rng),
        _ => {
            bench_gen(o, rng);
            bench_eval(o, rng);
            bench_full(o, rng);
        }
    }
}

fn main() {
    let o = parse();
    let mut rng = ChaCha20Rng::from_entropy();
    println!("# gen: mode,N,in_bits,out_bits,bm,reps,setup_ms,gen_ms_p0,gen_ms_p1,total_ms,setup_bytes,gen_bytes,gen_bytes_per_level,flights,and_gates,key_bytes");
    println!("# eval: mode,N,in_bits,out_bits,bm,reps,points,ns_per_eval");
    println!("# full: mode,N,in_bits,out_bits,bm,reps,ms_per_full_eval,ns_per_point");
    if o.sweep {
        for n in 8..=o.max_in_bits {
            for &m in &o.out_list {
                let mut p = o.clone();
                p.size = 1u64 << n;
                p.out_bits = m;
                run_one(&p, &mut rng);
            }
        }
    } else {
        run_one(&o, &mut rng);
    }
}
