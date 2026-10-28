//! One Ferret direction (party 0 holds Δ), ours against mpz-ot-core's, both
//! on base COTs from our `CotPair` and over our `Channel`.
//!
//! Two phases, after `CotPair::setup` and a `sync`:
//! 1. first N: base COTs (KOS or IKNP), bootstrap, refills until N are held,
//!    take N;
//! 2. next N: refills until N more are held, take N (steady state).
//!
//! Every output is checked against `M = K ⊕ r·Δ`.
//!
//! ```text
//! cargo run --release --example bench-mpz-ferret -- [--n 20000000] [--modes ours-mal,ours-sh,mpz-b13,mpz-default]
//! ```

use dpf_common::block::Block;
use dpf_common::net::{run_two_party, Channel, CommStats};
use dpf_common::ot::cot::RandomCots;
use dpf_common::ot::ferret::{FerretReceiver, FerretSender};
use dpf_common::ot::{CotPair, FerretConfig};
use exp_mpz_ferret::{b13, bootstrap_cost, BaseReceiver, BaseSender, MpzReceiver, MpzSender, Params};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::time::{Duration, Instant};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Mode {
    OursMal,
    OursSh,
    MpzB13,
    MpzDefault,
}

impl Mode {
    fn parse(s: &str) -> Mode {
        match s {
            "ours-mal" => Mode::OursMal,
            "ours-sh" => Mode::OursSh,
            "mpz-b13" => Mode::MpzB13,
            "mpz-default" => Mode::MpzDefault,
            _ => panic!("unknown mode {s}"),
        }
    }

    fn name(self) -> &'static str {
        match self {
            Mode::OursMal => "ours-mal",
            Mode::OursSh => "ours-sh",
            Mode::MpzB13 => "mpz-b13",
            Mode::MpzDefault => "mpz-default",
        }
    }

    fn malicious(self) -> bool {
        self != Mode::OursSh
    }

    fn base_cots(self) -> usize {
        match self {
            Mode::OursMal | Mode::OursSh => FerretConfig::B13.base_cots(self.malicious()),
            Mode::MpzB13 | Mode::MpzDefault => bootstrap_cost(),
        }
    }
}

/// One party's measurements of one phase.
#[derive(Clone, Copy, Default)]
struct Phase {
    stats: CommStats,
    time: Duration,
    iterations: usize,
}

enum Side {
    OursS(FerretSender),
    OursR(FerretReceiver),
    MpzS(MpzSender),
    MpzR(MpzReceiver),
}

enum Out {
    Keys(Vec<Block>),
    Cots(Vec<bool>, Vec<Block>),
}

impl Side {
    fn iterations(&self) -> usize {
        match self {
            Side::OursS(s) => s.iterations,
            Side::OursR(r) => r.iterations,
            Side::MpzS(s) => s.iterations,
            Side::MpzR(r) => r.iterations,
        }
    }

    fn produce(&mut self, ch: &mut Channel, n: usize, rng: &mut ChaCha20Rng) -> Out {
        match self {
            Side::OursS(s) => {
                s.ensure(ch, n, rng).unwrap();
                Out::Keys(s.take(n))
            }
            Side::OursR(r) => {
                r.ensure(ch, n, rng).unwrap();
                let (b, m) = r.take(n);
                Out::Cots(b, m)
            }
            Side::MpzS(s) => {
                s.ensure(ch, n).unwrap();
                Out::Keys(s.take(n).unwrap())
            }
            Side::MpzR(r) => {
                r.ensure(ch, n).unwrap();
                let (b, m) = r.take(n).unwrap();
                Out::Cots(b, m)
            }
        }
    }
}

fn party(ch: &mut Channel, mode: Mode, n: usize) -> (Block, [Phase; 2], [Out; 2]) {
    let me = ch.party();
    let mut rng = ChaCha20Rng::seed_from_u64(10 + me as u64);
    // lsb 1, so our Ferret receiver knows lsb(Δ) without an exchange.
    let delta = Block::random(&mut rng).with_lsb(true);
    let mut cot = CotPair::setup(ch, &mut rng, delta, mode.malicious()).unwrap();
    ch.sync();

    let s0 = ch.stats();
    let t0 = Instant::now();
    let base = cot.random_cots(ch, 0, mode.base_cots(), &mut rng).unwrap();
    let seed = Block::random(&mut rng);
    let mut side = match (mode, base) {
        (Mode::OursMal | Mode::OursSh, RandomCots::Sender(k)) => {
            Side::OursS(FerretSender::bootstrap(ch, FerretConfig::B13, delta, &k, mode.malicious(), &mut rng).unwrap())
        }
        (Mode::OursMal | Mode::OursSh, RandomCots::Receiver(b, m)) => {
            Side::OursR(FerretReceiver::bootstrap(ch, FerretConfig::B13, &b, &m, true, mode.malicious(), &mut rng).unwrap())
        }
        (_, base) => {
            let p = if mode == Mode::MpzB13 { Params::Ours(b13()) } else { Params::Default };
            match base {
                RandomCots::Sender(k) => Side::MpzS(MpzSender::setup(ch, seed, p, BaseSender::new(delta, &k)).unwrap()),
                RandomCots::Receiver(b, m) => Side::MpzR(MpzReceiver::setup(ch, seed, p, BaseReceiver::new(&b, &m)).unwrap()),
            }
        }
    };
    let out0 = side.produce(ch, n, &mut rng);
    let p0 = Phase { stats: ch.stats().since(&s0), time: t0.elapsed(), iterations: side.iterations() };

    ch.sync();
    let s1 = ch.stats();
    let t1 = Instant::now();
    let it1 = side.iterations();
    let out1 = side.produce(ch, n, &mut rng);
    let p1 = Phase { stats: ch.stats().since(&s1), time: t1.elapsed(), iterations: side.iterations() - it1 };
    (delta, [p0, p1], [out0, out1])
}

fn check(delta: Block, keys: &Out, cots: &Out) {
    let (Out::Keys(k), Out::Cots(r, m)) = (keys, cots) else { unreachable!() };
    assert_eq!(k.len(), m.len());
    for j in 0..k.len() {
        assert_eq!(m[j], k[j] ^ delta.and_bit(r[j]), "COT {j} wrong");
    }
}

fn mb(b: usize) -> f64 {
    b as f64 / 1e6
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut n = 20_000_000usize;
    let mut modes = vec![Mode::OursMal, Mode::OursSh, Mode::MpzB13, Mode::MpzDefault];
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--n" => n = args[i + 1].parse().unwrap(),
            "--modes" => modes = args[i + 1].split(',').map(Mode::parse).collect(),
            a => panic!("unknown argument {a}"),
        }
        i += 2;
    }

    println!("N = {n} COTs per phase, one direction, both parties in one process (single-threaded each)");
    println!("bytes: both directions; time: max over the parties; rounds: party 0's count\n");
    println!("| mode | base COTs | phase | iterations | bytes (MB) | bits/COT | rounds | time (s) | ns/COT |");
    println!("|---|---|---|---|---|---|---|---|---|");
    for mode in modes {
        let ((delta, p0, o0), (_, p1, o1)) = run_two_party(move |ch| party(ch, mode, n), move |ch| party(ch, mode, n));
        for i in 0..2 {
            check(delta, &o0[i], &o1[i]);
            let bytes = p0[i].stats.total_bytes();
            let time = p0[i].time.max(p1[i].time);
            println!(
                "| {} | {} | {} | {} | {:.2} | {:.4} | {} | {:.3} | {:.1} |",
                mode.name(),
                mode.base_cots(),
                ["first N", "next N"][i],
                p0[i].iterations,
                mb(bytes),
                8.0 * bytes as f64 / n as f64,
                p0[i].stats.rounds,
                time.as_secs_f64(),
                time.as_nanos() as f64 / n as f64,
            );
        }
    }
}
