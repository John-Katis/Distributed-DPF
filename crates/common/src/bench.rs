//! Shared command line, statistics and CSV schema for the protocols'
//! `examples/bench.rs`, so all benchmarks print comparable rows.
//!
//! ```text
//! bench <gen|eval|full|all> [options]
//!
//!   --variant v        protocol variant, for crates that have several
//!   --in-bits n        domain 2^n (default 16)
//!   --size N           any domain size N >= 2 (overrides --in-bits)
//!   --out-bits m       payload bits (default 128)
//!   --reps R           repetitions; the median is reported (default 5)
//!   --points P         points per repetition in `eval` (default 100000)
//!   --sweep            sweep in-bits over 8..=max-in-bits and out-bits over --out-list
//!   --max-in-bits n    upper end of the sweep (default 20)
//!   --out-list a,b,..  out-bits used by the sweep (default 32,128,256,512)
//! ```
//!
//! Each row starts with `mode,variant`. Bytes are summed over both directions,
//! `flights` adds both parties' one-way message flights (a round trip is two).

use std::time::Duration;

/// Column names, printed once as `#` comments.
pub const HEADER: &str = "\
# gen: mode,variant,N,in_bits,out_bits,bm,reps,setup_ms,gen_ms_p0,gen_ms_p1,total_ms,setup_bytes,gen_bytes,gen_bytes_per_level,flights,and_gates,cots,key_bytes
# eval: mode,variant,N,in_bits,out_bits,bm,reps,points,ns_per_eval
# full: mode,variant,N,in_bits,out_bits,bm,reps,ms_per_full_eval,ns_per_point";

#[derive(Clone, Debug)]
pub struct Opts {
    pub mode: String,
    pub variant: String,
    pub size: u64,
    pub out_bits: usize,
    pub reps: usize,
    pub points: usize,
    pub sweep: bool,
    pub max_in_bits: u32,
    pub out_list: Vec<usize>,
}

impl Opts {
    /// Parses `std::env::args`. `variants` lists the accepted `--variant`
    /// values; the first is the default.
    pub fn parse(variants: &[&str], default_out_bits: usize, default_out_list: &[usize]) -> Opts {
        let mut o = Opts {
            mode: "all".into(),
            variant: variants[0].into(),
            size: 1 << 16,
            out_bits: default_out_bits,
            reps: 5,
            points: 100_000,
            sweep: false,
            max_in_bits: 20,
            out_list: default_out_list.to_vec(),
        };
        let args: Vec<String> = std::env::args().skip(1).collect();
        let mut i = 0;
        let val = |i: usize| -> &str { args.get(i + 1).map(String::as_str).expect("missing flag value") };
        while i < args.len() {
            match args[i].as_str() {
                "gen" | "eval" | "full" | "all" => o.mode = args[i].clone(),
                "--variant" => {
                    o.variant = val(i).into();
                    assert!(variants.contains(&o.variant.as_str()), "variant must be one of {variants:?}");
                    i += 1;
                }
                "--in-bits" => { o.size = 1u64 << val(i).parse::<u32>().unwrap(); i += 1; }
                "--size" => { o.size = val(i).parse().unwrap(); i += 1; }
                "--out-bits" => { o.out_bits = val(i).parse().unwrap(); i += 1; }
                "--reps" => { o.reps = val(i).parse().unwrap(); i += 1; }
                "--points" => { o.points = val(i).parse().unwrap(); i += 1; }
                "--max-in-bits" => { o.max_in_bits = val(i).parse().unwrap(); i += 1; }
                "--out-list" => { o.out_list = val(i).split(',').map(|x| x.parse().unwrap()).collect(); i += 1; }
                "--sweep" => o.sweep = true,
                "-h" | "--help" => {
                    eprintln!("usage: bench <gen|eval|full|all> [--variant {}] [--in-bits n | --size N] [--out-bits m] [--reps R] [--points P] [--sweep [--max-in-bits n] [--out-list a,b]]", variants.join("|"));
                    std::process::exit(0);
                }
                other => panic!("unknown argument {other}"),
            }
            i += 1;
        }
        assert!(o.size >= 2 && o.reps >= 1);
        o
    }

    /// Calls `f` once, or for every (in-bits, out-bits) pair of the sweep.
    pub fn for_each(&self, mut f: impl FnMut(&Opts)) {
        println!("{HEADER}");
        if self.sweep {
            for n in 8..=self.max_in_bits {
                for &m in &self.out_list {
                    let mut p = self.clone();
                    p.size = 1u64 << n;
                    p.out_bits = m;
                    f(&p);
                }
            }
        } else {
            f(self);
        }
    }

    pub fn runs(&self, mode: &str) -> bool {
        self.mode == "all" || self.mode == mode
    }

    pub fn in_bits(&self) -> f64 {
        (self.size as f64).log2()
    }
}

pub fn median(mut v: Vec<Duration>) -> Duration {
    v.sort();
    v[v.len() / 2]
}

pub fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1e3
}

/// One `gen` row.
pub struct GenRow {
    pub bm: usize,
    pub setup: Duration,
    pub gen_p0: Duration,
    pub gen_p1: Duration,
    pub total: Duration,
    pub setup_bytes: usize,
    pub gen_bytes: usize,
    pub depth: usize,
    pub flights: usize,
    pub and_gates: usize,
    pub cots: usize,
    pub key_bytes: usize,
}

pub fn print_gen(o: &Opts, r: &GenRow) {
    println!(
        "gen,{},{},{:.2},{},{},{},{:.3},{:.3},{:.3},{:.3},{},{},{:.0},{},{},{},{}",
        o.variant,
        o.size,
        o.in_bits(),
        o.out_bits,
        r.bm,
        o.reps,
        ms(r.setup),
        ms(r.gen_p0),
        ms(r.gen_p1),
        ms(r.total),
        r.setup_bytes,
        r.gen_bytes,
        r.gen_bytes as f64 / r.depth as f64,
        r.flights,
        r.and_gates,
        r.cots,
        r.key_bytes,
    );
}

/// Times `eval(x)` over `points` random inputs, `reps` times, and prints the
/// median nanoseconds per evaluation.
pub fn bench_eval(o: &Opts, bm: usize, xs: &[u64], mut eval: impl FnMut(u64)) {
    let mut times = vec![];
    for _ in 0..o.reps {
        let t = std::time::Instant::now();
        for &x in xs {
            eval(std::hint::black_box(x));
        }
        times.push(t.elapsed());
    }
    let per = median(times).as_secs_f64() * 1e9 / xs.len() as f64;
    println!("eval,{},{},{:.2},{},{},{},{},{:.1}", o.variant, o.size, o.in_bits(), o.out_bits, bm, o.reps, xs.len(), per);
}

/// Times a full-domain evaluation `reps` times and prints the median.
pub fn bench_full(o: &Opts, bm: usize, mut full: impl FnMut()) {
    let mut times = vec![];
    for _ in 0..o.reps {
        let t = std::time::Instant::now();
        full();
        times.push(t.elapsed());
    }
    let m = median(times);
    println!(
        "full,{},{},{:.2},{},{},{},{:.3},{:.2}",
        o.variant,
        o.size,
        o.in_bits(),
        o.out_bits,
        bm,
        o.reps,
        ms(m),
        m.as_secs_f64() * 1e9 / o.size as f64
    );
}
