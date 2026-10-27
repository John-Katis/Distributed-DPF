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
//!   --lan l,b          LAN profile: latency per round l ms, bandwidth b Mbit/s (default 10,1000)
//!   --wan l,b          WAN profile (default 100,100)
//!   --stream           streaming tree ([`crate::stream`]): O(batch·n) memory,
//!                      ~2× Gen compute, same messages; variant gets `+stream`
//!   --batch-log b      nodes per streaming batch, 2^b (default 16)
//!   --stream-from n    stored tree below 2^n, streaming tree from 2^n on
//!                      (for sweeps whose large domains do not fit in memory)
//! ```
//!
//! Every row has the same metric columns after the parameters:
//!
//! * `comm_p0,comm_p1,comm_p2`: bytes each party sends (`comm_p2` is the 3P
//!   helper, otherwise 0); `comm_total` is their sum, i.e. all traffic.
//! * `rounds`: one-way latencies, so a simultaneous exchange is one round
//!   (see [`crate::net`]); the maximum over the parties, which is also the
//!   protocol's total.
//! * `comp_ms`: computation, the wall time from the start to the end of the
//!   operation (median over `reps`; for Gen the slower party, setup included).
//! * `lan_net_ms`, `wan_net_ms`: analytical network time on each profile,
//!   `rounds·latency + 8·comm_total/bandwidth` ([`crate::net::net_time`]).
//! * `lan_total_ms`, `wan_total_ms`: `comp_ms` plus that profile's network time.
//!
//! DPF evaluation is local, so `eval` (one point) and `full` (the whole
//! domain) rows have no communication and no rounds. The columns after the
//! metrics break Gen down into three phases:
//!
//! * setup (`setup_*`): base OTs and keys, once per session;
//! * preprocessing (`pre_*`): the input-independent correlations Gen
//!   consumes (random COTs and OTs, bit triples, PRG correlations, a 3P
//!   helper's dealing);
//! * generation proper (`gen_*`), given those correlations.

use crate::net::CommStats;
use crate::stream::TreeMode;
use std::time::Duration;

/// Column names, printed once as `#` comments.
pub const HEADER: &str = "\
# gen: mode,variant,N,in_bits,out_bits,bm,reps,comm_p0,comm_p1,comm_p2,comm_total,rounds,comp_ms,lan_net_ms,lan_total_ms,wan_net_ms,wan_total_ms,setup_ms,pre_ms,gen_ms_p0,gen_ms_p1,setup_bytes,pre_bytes,pre_rounds,gen_bytes,gen_bytes_per_level,gen_rounds,and_gates,cots,key_bytes
# eval: mode,variant,N,in_bits,out_bits,bm,reps,comm_p0,comm_p1,comm_p2,comm_total,rounds,comp_ms,lan_net_ms,lan_total_ms,wan_net_ms,wan_total_ms,points,ns_per_eval
# full: mode,variant,N,in_bits,out_bits,bm,reps,comm_p0,comm_p1,comm_p2,comm_total,rounds,comp_ms,lan_net_ms,lan_total_ms,wan_net_ms,wan_total_ms,ns_per_point";

/// A simulated network: the latency of one round and the bandwidth.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Link {
    pub latency_ms: f64,
    pub mbps: f64,
}

/// 1 Gbit/s, 10 ms per round.
pub const LAN: Link = Link { latency_ms: 10.0, mbps: 1000.0 };
/// 100 Mbit/s, 100 ms per round.
pub const WAN: Link = Link { latency_ms: 100.0, mbps: 100.0 };

impl Link {
    /// Network time of `rounds` rounds carrying `bytes` in total.
    pub fn net_time(&self, rounds: usize, bytes: usize) -> Duration {
        crate::net::net_time(rounds, bytes, Duration::from_secs_f64(self.latency_ms / 1e3), self.mbps * 1e6)
    }

    fn parse(v: &str) -> Link {
        let (l, b) = v.split_once(',').expect("link must be latency_ms,mbps");
        let link = Link { latency_ms: l.parse().unwrap(), mbps: b.parse().unwrap() };
        assert!(link.latency_ms >= 0.0 && link.mbps > 0.0);
        link
    }
}

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
    pub lan: Link,
    pub wan: Link,
    pub stream: bool,
    pub batch_log: u32,
    /// In-bits from which the streaming tree is used even without `--stream`.
    pub stream_from: u32,
    /// ht-aes: source of the F4 triples (`foleage`, `foleage-c<c>`, `ot`).
    pub f4: String,
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
            lan: LAN,
            wan: WAN,
            stream: false,
            batch_log: 16,
            stream_from: u32::MAX,
            f4: "foleage".into(),
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
                "--in-bits" => { o.size = 1u64 << in_bits(val(i)); i += 1; }
                "--size" => { o.size = val(i).parse().unwrap(); i += 1; }
                "--out-bits" => { o.out_bits = val(i).parse().unwrap(); i += 1; }
                "--reps" => { o.reps = val(i).parse().unwrap(); i += 1; }
                "--points" => { o.points = val(i).parse().unwrap(); i += 1; }
                "--max-in-bits" => { o.max_in_bits = in_bits(val(i)); i += 1; }
                "--out-list" => { o.out_list = val(i).split(',').map(|x| x.parse().unwrap()).collect(); i += 1; }
                "--lan" => { o.lan = Link::parse(val(i)); i += 1; }
                "--wan" => { o.wan = Link::parse(val(i)); i += 1; }
                "--sweep" => o.sweep = true,
                "--stream" => o.stream = true,
                "--batch-log" => { o.batch_log = val(i).parse().unwrap(); i += 1; }
                "--stream-from" => { o.stream_from = in_bits(val(i)); i += 1; }
                "--f4" => { o.f4 = val(i).into(); i += 1; }
                "-h" | "--help" => {
                    eprintln!("usage: bench <gen|eval|full|all> [--variant {}] [--in-bits n | --size N] [--out-bits m] [--reps R] [--points P] [--sweep [--max-in-bits n] [--out-list a,b]] [--lan ms,mbps] [--wan ms,mbps] [--stream] [--stream-from n] [--batch-log b] [--f4 foleage|foleage-c<c>|ot]", variants.join("|"));
                    std::process::exit(0);
                }
                other => panic!("unknown argument {other}"),
            }
            i += 1;
        }
        assert!(o.size >= 2 && o.reps >= 1);
        assert!((1..=30).contains(&o.batch_log), "--batch-log must be in 1..=30");
        o
    }

    /// The tree mode selected by `--stream` / `--batch-log`.
    pub fn tree_mode(&self) -> TreeMode {
        if self.stream {
            TreeMode::Stream { batch: 1 << self.batch_log }
        } else {
            TreeMode::Stored
        }
    }

    /// The variant as printed in the CSV: `+stream` marks the streaming tree.
    /// A non-default `--f4` is appended as `+<f4>`.
    pub fn label(&self) -> String {
        let mut l = self.variant.clone();
        if self.f4 != "foleage" {
            l += &format!("+{}", self.f4);
        }
        if self.stream {
            l += "+stream";
        }
        l
    }

    /// Calls `f` once, or for every (in-bits, out-bits) pair of the sweep.
    pub fn for_each(&self, mut f: impl FnMut(&Opts)) {
        println!("{HEADER}");
        println!(
            "# net: lan latency_ms={},mbps={}; wan latency_ms={},mbps={}",
            self.lan.latency_ms, self.lan.mbps, self.wan.latency_ms, self.wan.mbps
        );
        if self.sweep {
            for n in 8..=self.max_in_bits {
                for &m in &self.out_list {
                    let mut p = self.clone();
                    p.size = 1u64 << n;
                    p.out_bits = m;
                    p.stream |= n >= p.stream_from;
                    f(&p);
                }
            }
        } else {
            let mut p = self.clone();
            p.stream |= p.in_bits() >= p.stream_from as f64;
            f(&p);
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
    /// Bytes each party sends from the start to the end of Gen, setup
    /// included: P0, P1 and the 3P helper P2 (0 in two-party protocols).
    pub sent: [usize; 3],
    /// Rounds from the start to the end of Gen, setup included (max over the
    /// parties).
    pub rounds: usize,
    /// Wall time of the slower party from the start to the end of Gen, setup
    /// included.
    pub total: Duration,
    pub setup: Duration,
    /// Preprocessing wall time of the slower party.
    pub pre: Duration,
    pub gen_p0: Duration,
    pub gen_p1: Duration,
    pub setup_bytes: usize,
    /// Preprocessing traffic, all links and directions.
    pub pre_bytes: usize,
    /// Preprocessing rounds (max over the parties).
    pub pre_rounds: usize,
    pub gen_bytes: usize,
    pub depth: usize,
    /// Rounds of generation proper (max over the parties).
    pub gen_rounds: usize,
    pub and_gates: usize,
    pub cots: usize,
    pub key_bytes: usize,
}

/// `sent` and `rounds` of a two-party Gen whose setup, preprocessing and
/// generation traffic were counted apart.
pub fn whole_gen(setup: [CommStats; 2], pre: [CommStats; 2], gen: [CommStats; 2]) -> ([usize; 3], usize) {
    let sent = |p: usize| setup[p].bytes_sent + pre[p].bytes_sent + gen[p].bytes_sent;
    let rounds = |p: usize| setup[p].rounds + pre[p].rounds + gen[p].rounds;
    ([sent(0), sent(1), 0], rounds(0).max(rounds(1)))
}

/// The shared metric columns, from `comm_p0` to `wan_total_ms`.
fn metrics(o: &Opts, sent: [usize; 3], rounds: usize, comp: Duration) -> String {
    let bytes: usize = sent.iter().sum();
    let mut s = format!("{},{},{},{},{},{:.6}", sent[0], sent[1], sent[2], bytes, rounds, ms(comp));
    for link in [o.lan, o.wan] {
        let net = link.net_time(rounds, bytes);
        s += &format!(",{:.6},{:.6}", ms(net), ms(comp + net));
    }
    s
}

pub fn print_gen(o: &Opts, r: &GenRow) {
    println!(
        "gen,{},{},{:.2},{},{},{},{},{:.3},{:.3},{:.3},{:.3},{},{},{},{},{:.0},{},{},{},{}",
        o.label(),
        o.size,
        o.in_bits(),
        o.out_bits,
        r.bm,
        o.reps,
        metrics(o, r.sent, r.rounds, r.total),
        ms(r.setup),
        ms(r.pre),
        ms(r.gen_p0),
        ms(r.gen_p1),
        r.setup_bytes,
        r.pre_bytes,
        r.pre_rounds,
        r.gen_bytes,
        r.gen_bytes as f64 / r.depth as f64,
        r.gen_rounds,
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
    let per = Duration::from_secs_f64(median(times).as_secs_f64() / xs.len() as f64);
    println!(
        "eval,{},{},{:.2},{},{},{},{},{},{:.1}",
        o.label(),
        o.size,
        o.in_bits(),
        o.out_bits,
        bm,
        o.reps,
        metrics(o, [0; 3], 0, per),
        xs.len(),
        per.as_secs_f64() * 1e9
    );
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
        "full,{},{},{:.2},{},{},{},{},{:.2}",
        o.label(),
        o.size,
        o.in_bits(),
        o.out_bits,
        bm,
        o.reps,
        metrics(o, [0; 3], 0, m),
        m.as_secs_f64() * 1e9 / o.size as f64
    );
}

/// Parses an input length; the domain size `2^n` must fit in a `u64`.
fn in_bits(v: &str) -> u32 {
    let n: u32 = v.parse().expect("input bits must be an integer");
    assert!((1..=63).contains(&n), "input bits must be in 1..=63 (the domain size 2^n is a u64)");
    n
}
