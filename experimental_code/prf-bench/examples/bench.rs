//! PRF microbenchmarks on one host.
//!
//! ```text
//! cargo run --release -p exp-prf-bench --example bench-prf -- <local|2pc|ferret|all>
//! ```
//!
//! * `local`: latency of one plaintext call, each call on the previous
//!   output (a descent), median of 7 runs; and throughput on independent
//!   inputs (full-domain style).
//! * `2pc`: one call of F_prf on XOR-shared input, batches of 1 and of the
//!   calls of one n = 32 key pair (32 joint AES–MMO calls at ν = 17, 64
//!   LPN-PRG calls), median of 5 runs, outputs checked against the clear.
//!   Correlations come from Ferret (B13), bootstrapped once and not counted.
//!   Also the two other S-box realizations of Tab. prf-2pc: the MAESTRO-style
//!   F_16 tower (`maestro`) and the Boyar–Peralta circuit with AND triples
//!   (`triples`), both on the same Ferret COTs and the same `mmo_shared`.
//! * `ferret`: cost of one Ferret COT (time and bytes, refills included).

use dpf_common::aes_tower::{bits_of, block_of, mmo_shared, Mmo, OtTower, Shared128, SharedKey, COTS_PER_CALL};
use dpf_common::block::Block;
use dpf_common::net::{run_two_party, Channel, CommStats};
use dpf_common::ot::{CotPair, FerretConfig};
use exp_prf_bench::maestro::{self, Maestro};
use exp_prf_bench::triples::{self, TripleCircuit};
use exp_prf_bench::{ColLpn, RowLpn};
use fssnn::lpn_prg::lpn_prg;
use fssnn::semi_honest::sec_prg;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use std::hint::black_box;
use std::time::{Duration, Instant};

const COT_BITS: f64 = 0.443;

fn median(mut v: Vec<f64>) -> f64 {
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    v[v.len() / 2]
}

/// Median ns per call of `f` over `reps` runs of `calls` calls.
fn ns_per_call(reps: usize, calls: usize, mut f: impl FnMut(usize)) -> f64 {
    f(calls / 10); // warm-up
    median(
        (0..reps)
            .map(|_| {
                let t = Instant::now();
                f(calls);
                t.elapsed().as_nanos() as f64 / calls as f64
            })
            .collect(),
    )
}

fn local() {
    let m = Mmo::new(*b"prf-bench/key-01");
    let m2 = Mmo::new(*b"prf-bench/key-02");
    let (row, col, fss) = (RowLpn::new(), ColLpn::new(), lpn_prg());
    let (reps, n_aes, n_lpn) = (7, 3_000_000, 300_000);
    let x0 = Block(0x0123_4567_89ab_cdef_fedc_ba98_7654_3210);

    println!("# local latency (chained), ns/call, median of {reps}");
    let pi = ns_per_call(reps, n_aes, |k| {
        let mut x = x0;
        for _ in 0..k {
            x = m.pi(x);
        }
        black_box(x);
    });
    let h = ns_per_call(reps, n_aes, |k| {
        let mut x = x0;
        for _ in 0..k {
            x = m.h(x);
        }
        black_box(x);
    });
    let ggm = ns_per_call(reps, n_aes, |k| {
        let mut x = x0;
        for _ in 0..k {
            // Both children of a GGM node; the next node takes the left one,
            // the right one stays live so neither call is dropped.
            let (l, r) = (m.h(x), m2.h(x));
            x = l ^ Block(r.0 & 1);
        }
        black_box(x);
    });
    let lrow = ns_per_call(reps, n_lpn, |k| {
        let mut x = x0.0;
        for _ in 0..k {
            let y = row.eval(x);
            x = y[0] ^ (y[1] & 1);
        }
        black_box(x);
    });
    let lside = ns_per_call(reps, n_lpn, |k| {
        // Point Eval (tree::child): one side of G, 128 of the 256 B rows.
        let mut x = x0.0;
        for i in 0..k {
            x = row.eval_side(x, i & 1);
        }
        black_box(x);
    });
    let lfss = ns_per_call(reps, n_lpn, |k| {
        let mut x = x0.0;
        for _ in 0..k {
            let y = fss.eval(x);
            x = y[0] ^ (y[1] & 1);
        }
        black_box(x);
    });
    let lfss_side = ns_per_call(reps, n_lpn, |k| {
        let mut x = x0.0;
        for i in 0..k {
            x = fss.eval_side(x, i & 1);
        }
        black_box(x);
    });
    let lcol = ns_per_call(reps, n_lpn, |k| {
        let mut x = x0.0;
        for _ in 0..k {
            let y = col.eval(x);
            x = y[0] ^ (y[1] & 1);
        }
        black_box(x);
    });
    println!("aes_block_pi,{pi:.2}");
    println!("aes_mmo_h,{h:.2}");
    println!("aes_mmo_ggm_node_2calls,{ggm:.2}");
    println!("lpn_prg_rowwise_B,{lrow:.1}");
    println!("lpn_prg_rowwise_B_one_side,{lside:.1}");
    println!("lpn_prg_fssnn_current,{lfss:.1}");
    println!("lpn_prg_fssnn_current_one_side(point_eval),{lfss_side:.1}");
    println!("lpn_prg_colxor_B,{lcol:.1}");

    println!("# local throughput (independent inputs), ns/call, median of {reps}");
    const BUF: usize = 1024;
    let xs: Vec<Block> = (0..BUF).map(|i| Block(i as u128 * 0x9e37_79b9_7f4a_7c15)).collect();
    let mut out = vec![Block::ZERO; BUF];
    let ht = ns_per_call(reps, n_aes, |k| {
        for _ in 0..k / BUF {
            m.h_many(&xs, &mut out);
            black_box(&out);
        }
    });
    let lt = ns_per_call(reps, n_lpn, |k| {
        for i in 0..k {
            black_box(col.eval(xs[i % BUF].0));
        }
    });
    let lrt = ns_per_call(reps, n_lpn, |k| {
        for i in 0..k {
            black_box(row.eval(xs[i % BUF].0));
        }
    });
    println!("aes_mmo_h_many,{ht:.2}");
    println!("lpn_prg_rowwise_B_indep,{lrt:.1}");
    println!("lpn_prg_colxor_B_indep,{lt:.1}");
}

/// Per run: corr time, online time, corr stats, online stats, COTs used.
type Run = (Duration, Duration, CommStats, CommStats, usize);

fn setup(ch: &mut Channel, seed: u64) -> (CotPair, ChaCha20Rng) {
    let mut r = ChaCha20Rng::seed_from_u64(seed);
    let delta = Block::random(&mut r).with_lsb(ch.party() == 1);
    let mut cot = CotPair::setup(ch, &mut r, delta, false).unwrap();
    cot.enable_ferret(ch, FerretConfig::B13, &mut r).unwrap();
    (cot, r)
}

fn mmo_party(b: usize, batch: usize, reps: usize, xs: Vec<Vec<Block>>, s0: Vec<Vec<Block>>) -> impl FnOnce(&mut Channel) -> (Vec<Run>, Vec<Vec<Block>>) {
    move |ch: &mut Channel| {
        let (mut cot, mut r) = setup(ch, 100 + b as u64);
        let m = Mmo::new(*b"prf-bench/key-01");
        let (mut runs, mut outs) = (vec![], vec![]);
        for rep in 0..reps {
            let (t, s, p) = (Instant::now(), ch.stats(), cot.produced);
            let pool = cot.random_cots(ch, 0, batch * COTS_PER_CALL, &mut r).unwrap();
            let mut be = OtTower::new(b, pool, cot.delta());
            let (tc, sc, used) = (t.elapsed(), ch.stats().since(&s), cot.produced - p);
            let mut sk = vec![SharedKey::public(&be, &m)];
            let jobs: Vec<(usize, Shared128<bool>)> =
                (0..batch).map(|i| (0, bits_of(if b == 0 { s0[rep][i] } else { xs[rep][i] ^ s0[rep][i] }))).collect();
            let (t, s) = (Instant::now(), ch.stats());
            let y = mmo_shared(&mut be, ch, &mut sk, &jobs);
            runs.push((tc, t.elapsed(), sc, ch.stats().since(&s), used));
            outs.push(y.iter().map(block_of).collect());
        }
        (runs, outs)
    }
}

/// AES–MMO with S-boxes from `make(ch, cot, rng, sboxes)` (built in the
/// correlation phase: COTs and any preprocessing count as `corr`).
fn mmo_with<B, F>(b: usize, batch: usize, reps: usize, xs: Vec<Vec<Block>>, s0: Vec<Vec<Block>>, make: F) -> impl FnOnce(&mut Channel) -> (Vec<Run>, Vec<Vec<Block>>)
where
    B: dpf_common::aes_tower::TowerBackend<Bit = bool>,
    F: Fn(&mut Channel, &mut CotPair, &mut ChaCha20Rng, usize) -> B + Send + 'static,
{
    move |ch: &mut Channel| {
        let (mut cot, mut r) = setup(ch, 400 + b as u64);
        let m = Mmo::new(*b"prf-bench/key-01");
        let (mut runs, mut outs) = (vec![], vec![]);
        for rep in 0..reps {
            let (t, s, p) = (Instant::now(), ch.stats(), cot.produced);
            let mut be = make(ch, &mut cot, &mut r, 160 * batch);
            let (tc, sc, used) = (t.elapsed(), ch.stats().since(&s), cot.produced - p);
            let mut sk = vec![SharedKey::public(&be, &m)];
            let jobs: Vec<(usize, Shared128<bool>)> =
                (0..batch).map(|i| (0, bits_of(if b == 0 { s0[rep][i] } else { xs[rep][i] ^ s0[rep][i] }))).collect();
            let (t, s) = (Instant::now(), ch.stats());
            let y = mmo_shared(&mut be, ch, &mut sk, &jobs);
            runs.push((tc, t.elapsed(), sc, ch.stats().since(&s), used));
            outs.push(y.iter().map(block_of).collect());
        }
        // Party 1 counts the COTs of both directions in `produced`, as party 0 does.
        (runs, outs)
    }
}

fn make_maestro(ch: &mut Channel, cot: &mut CotPair, r: &mut ChaCha20Rng, sboxes: usize) -> Maestro {
    let cots = cot.random_cots(ch, 0, sboxes * maestro::COTS_PER_SBOX, r).unwrap();
    let mut m = Maestro::new(ch.party(), cots, cot.delta());
    m.preprocess(ch, sboxes, r);
    m
}

fn make_triples(ch: &mut Channel, cot: &mut CotPair, r: &mut ChaCha20Rng, sboxes: usize) -> TripleCircuit {
    let k = sboxes * triples::ANDS_PER_SBOX;
    let me = ch.party();
    let (a, b) = (cot.random_cots(ch, 0, k, r).unwrap(), cot.random_cots(ch, 1, k, r).unwrap());
    let (sent, recv) = if me == 0 { (a, b) } else { (b, a) };
    TripleCircuit::new(me, exp_bp_sbox::boyar_peralta(), sent, recv, cot.delta())
}

fn lpn_party(b: usize, batch: usize, reps: usize, xs: Vec<Vec<u128>>, s0: Vec<Vec<u128>>) -> impl FnOnce(&mut Channel) -> (Vec<Run>, Vec<Vec<[u128; 2]>>) {
    move |ch: &mut Channel| {
        let (mut cot, mut r) = setup(ch, 200 + b as u64);
        let (mut runs, mut outs, mut tw) = (vec![], vec![], 0u64);
        for rep in 0..reps {
            let (t, s, p) = (Instant::now(), ch.stats(), cot.produced);
            let corr = sec_prg::preprocess(ch, &mut cot, batch, &mut tw, &mut r);
            let (tc, sc, used) = (t.elapsed(), ch.stats().since(&s), cot.produced - p);
            let mine: Vec<u128> = (0..batch).map(|i| if b == 0 { s0[rep][i] } else { xs[rep][i] ^ s0[rep][i] }).collect();
            let (t, s) = (Instant::now(), ch.stats());
            let y = sec_prg::eval_shared(ch, &corr, &mine);
            runs.push((tc, t.elapsed(), sc, ch.stats().since(&s), used));
            outs.push(y);
        }
        (runs, outs)
    }
}

fn report(name: &str, batch: usize, out_bits: usize, r0: &[Run], r1: &[Run]) {
    let per = |f: &dyn Fn(&Run, &Run) -> f64| median(r0.iter().zip(r1).map(|(a, b)| f(a, b)).collect()) / batch as f64;
    let kbit = |s0: &CommStats, s1: &CommStats| 8.0 * (s0.bytes_sent + s1.bytes_sent) as f64 / 1000.0;
    let online = per(&|a, b| kbit(&a.3, &b.3));
    let corr = per(&|a, b| kbit(&a.2, &b.2));
    // Both parties count the same COTs.
    let cots = per(&|a, _b| a.4 as f64);
    let cot_kbit = cots * COT_BITS / 1000.0;
    let total = online + corr + cot_kbit;
    let rounds = median(r0.iter().map(|a| a.3.rounds as f64).collect());
    let t_on = per(&|a, b| a.1.max(b.1).as_secs_f64() * 1e6);
    let t_corr = per(&|a, b| a.0.max(b.0).as_secs_f64() * 1e6);
    println!(
        "{name},{batch},{out_bits},{online:.2},{corr:.2},{cots:.0},{cot_kbit:.2},{total:.2},{:.1},{rounds},{t_on:.1},{t_corr:.1}",
        1000.0 * total / out_bits as f64
    );
}

fn twopc() {
    println!("# 2PC, per call: name,batch,out_bits,online_kbit,corr_kbit(measured),cots,cot_kbit(@{COT_BITS}),total_kbit,bit_per_out,rounds(per batch),online_us,corr_us");
    let reps = 5;
    let mut rng = ChaCha20Rng::seed_from_u64(9);
    for batch in [1usize, 32] {
        let xs: Vec<Vec<Block>> = (0..reps).map(|_| (0..batch).map(|_| Block::random(&mut rng)).collect()).collect();
        let s0: Vec<Vec<Block>> = (0..reps).map(|_| (0..batch).map(|_| Block::random(&mut rng)).collect()).collect();
        let ((r0, y0), (r1, y1)) = run_two_party(mmo_party(0, batch, reps, xs.clone(), s0.clone()), mmo_party(1, batch, reps, xs.clone(), s0));
        let m = Mmo::new(*b"prf-bench/key-01");
        for rep in 0..reps {
            for i in 0..batch {
                assert_eq!(y0[rep][i] ^ y1[rep][i], m.h(xs[rep][i]), "AES–MMO output");
            }
        }
        report("aes_mmo_ot_tower", batch, 128, &r0, &r1);
        let check = |y0: &[Vec<Block>], y1: &[Vec<Block>], what: &str| {
            for rep in 0..reps {
                for i in 0..batch {
                    assert_eq!(y0[rep][i] ^ y1[rep][i], m.h(xs[rep][i]), "{what}");
                }
            }
        };
        let s0: Vec<Vec<Block>> = (0..reps).map(|_| (0..batch).map(|_| Block::random(&mut rng)).collect()).collect();
        let ((r0, y0), (r1, y1)) = run_two_party(
            mmo_with(0, batch, reps, xs.clone(), s0.clone(), make_maestro),
            mmo_with(1, batch, reps, xs.clone(), s0.clone(), make_maestro),
        );
        check(&y0, &y1, "MAESTRO-style AES–MMO output");
        report("aes_mmo_maestro_style", batch, 128, &r0, &r1);
        let ((r0, y0), (r1, y1)) = run_two_party(
            mmo_with(0, batch, reps, xs.clone(), s0.clone(), make_triples),
            mmo_with(1, batch, reps, xs.clone(), s0, make_triples),
        );
        check(&y0, &y1, "AND-triple AES–MMO output");
        report("aes_mmo_and_triples", batch, 128, &r0, &r1);
    }
    for batch in [1usize, 64] {
        let xs: Vec<Vec<u128>> = (0..reps).map(|_| (0..batch).map(|_| rng.gen()).collect()).collect();
        let s0: Vec<Vec<u128>> = (0..reps).map(|_| (0..batch).map(|_| rng.gen()).collect()).collect();
        let ((r0, y0), (r1, y1)) = run_two_party(lpn_party(0, batch, reps, xs.clone(), s0.clone()), lpn_party(1, batch, reps, xs.clone(), s0));
        for rep in 0..reps {
            for i in 0..batch {
                let y = lpn_prg().eval(xs[rep][i]);
                assert_eq!([y0[rep][i][0] ^ y1[rep][i][0], y0[rep][i][1] ^ y1[rep][i][1]], y, "LPN-PRG output");
            }
        }
        report("lpn_prg_dgh21", batch, 256, &r0, &r1);
    }
}

fn ferret() {
    // Enough COTs to force refill iterations in both directions.
    let n = 25_000_000usize;
    let party = |b: usize| {
        move |ch: &mut Channel| {
            let (mut cot, mut r) = setup(ch, 300 + b as u64);
            let (t, s) = (Instant::now(), ch.stats());
            let mut left = n;
            while left > 0 {
                let k = left.min(1 << 20);
                black_box(cot.random_cots(ch, 0, k, &mut r).unwrap());
                left -= k;
            }
            (t.elapsed(), ch.stats().since(&s))
        }
    };
    let ((t0, s0), (t1, s1)) = run_two_party(party(0), party(1));
    let ns = t0.max(t1).as_nanos() as f64 / n as f64;
    let bits = 8.0 * (s0.bytes_sent + s1.bytes_sent) as f64 / n as f64;
    println!("# Ferret B13, one direction, {n} COTs incl. refills");
    println!("ferret_cot,ns_per_cot,{ns:.2},bits_per_cot,{bits:.3}");
}

fn main() {
    let mode = std::env::args().nth(1).unwrap_or_else(|| "all".into());
    match mode.as_str() {
        "local" => local(),
        "2pc" => twopc(),
        "ferret" => ferret(),
        "all" => {
            local();
            twopc();
            ferret();
        }
        m => panic!("unknown mode {m}: local|2pc|ferret|all"),
    }
}
