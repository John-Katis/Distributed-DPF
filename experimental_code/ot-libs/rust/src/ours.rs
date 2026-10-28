//! Our OTs (`dpf_common::ot`) in the shared row format. Party 0 is the OT
//! sender / holds Δ. `first` in `start_ch` is the party that speaks first in
//! the phase (see `Meas::start_ch`).

use crate::count::{emit, Meas};
use dpf_common::block::Block;
use dpf_common::net::run_two_party;
use dpf_common::ot::cot::{BaseOt, RandomCots};
use dpf_common::ot::ferret::{FerretReceiver, FerretSender};
use dpf_common::ot::kkot::{KkotReceiver, KkotSender};
use dpf_common::ot::{endemic, np, CotPair, CotReceiver, CotSender, FerretConfig, IknpReceiver, IknpSender};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;

const LIB: &str = "ours";

/// 128 random base OTs: Naor–Pinkas (sender speaks first) or endemic
/// Masny–Rindal (receiver speaks first).
pub fn base(mr: bool) {
    let n = 128;
    let choices: Vec<bool> = (0..n).map(|i| i % 3 == 0).collect();
    let c2 = choices.clone();
    let first = if mr { 1 } else { 0 };
    let ((m0, k), (m1, r)) = run_two_party(
        move |ch| {
            let mut rng = ChaCha20Rng::seed_from_u64(1);
            let mut m = Meas::default();
            m.start_ch(ch, first);
            let k = if mr { endemic::send_random(ch, n, &mut rng) } else { np::send_random(ch, n, &mut rng) }.unwrap();
            m.stop_ch(ch);
            (m, k)
        },
        move |ch| {
            let mut rng = ChaCha20Rng::seed_from_u64(2);
            let mut m = Meas::default();
            m.start_ch(ch, first);
            let r = if mr { endemic::recv_random(ch, &c2, &mut rng) } else { np::recv_random(ch, &c2, &mut rng) }.unwrap();
            m.stop_ch(ch);
            (m, r)
        },
    );
    let ok = (0..n).all(|i| r[i] == if choices[i] { k[i].1 } else { k[i].0 } && k[i].0 != k[i].1);
    emit(LIB, if mr { "base-mr" } else { "base-np" }, "-", n, &["all"], &m0, &m1, ok);
}

/// COT with Δ, one direction. Semi-honest: `CotSender`/`CotReceiver` on
/// Naor–Pinkas, then one IKNP extension. Malicious: `CotPair` (its setup runs
/// the endemic base OTs of both directions; its extend runs KOS in both
/// directions, the empty one padded with `KOS_EXTRA` COTs).
pub fn cot(mal: bool, n: usize) {
    let choices: Vec<bool> = {
        let mut rng = ChaCha20Rng::seed_from_u64(3);
        (0..n).map(|_| rng.r#gen()).collect()
    };
    let c2 = choices.clone();
    let ((m0, delta, k), (m1, mm)) = run_two_party(
        move |ch| {
            let mut rng = ChaCha20Rng::seed_from_u64(4);
            let delta = Block::random(&mut rng);
            let mut m = Meas::default();
            let k = if mal {
                m.start_ch(ch, 0);
                let mut p = CotPair::setup(ch, &mut rng, delta, true).unwrap();
                m.stop_ch(ch);
                m.start_ch(ch, 1);
                let (k, _) = p.extend(ch, &[], n, &mut rng).unwrap();
                m.stop_ch(ch);
                k
            } else {
                m.start_ch(ch, 1);
                let mut s = CotSender::setup(ch, &mut rng, delta, BaseOt::NaorPinkas).unwrap();
                m.stop_ch(ch);
                m.start_ch(ch, 1);
                let k = s.recv_extend(ch, n).unwrap();
                m.stop_ch(ch);
                k
            };
            (m, delta, k)
        },
        move |ch| {
            let mut rng = ChaCha20Rng::seed_from_u64(5);
            let mut m = Meas::default();
            let mm = if mal {
                m.start_ch(ch, 0);
                let mut p = { let d = Block::random(&mut rng); CotPair::setup(ch, &mut rng, d, true) }.unwrap();
                m.stop_ch(ch);
                m.start_ch(ch, 1);
                let (_, mm) = p.extend(ch, &c2, 0, &mut rng).unwrap();
                m.stop_ch(ch);
                mm
            } else {
                m.start_ch(ch, 1);
                let mut r = CotReceiver::setup(ch, &mut rng, BaseOt::NaorPinkas).unwrap();
                m.stop_ch(ch);
                m.start_ch(ch, 1);
                let mm = r.send_extend(ch, &c2).unwrap();
                m.stop_ch(ch);
                mm
            };
            (m, mm)
        },
    );
    let ok = (0..n).all(|j| mm[j] == k[j] ^ delta.and_bit(choices[j]));
    emit(LIB, "cot", if mal { "mal" } else { "sh" }, n, &["setup", "extend"], &m0, &m1, ok);
}

/// Chosen-message 1-out-of-2 OT, semi-honest IKNP (`iknp.rs`, as Obliv-C).
pub fn ot(n: usize) {
    let mut rng = ChaCha20Rng::seed_from_u64(6);
    let msgs: Vec<(Block, Block)> = (0..n).map(|_| (Block::random(&mut rng), Block::random(&mut rng))).collect();
    let choices: Vec<bool> = (0..n).map(|_| rng.r#gen()).collect();
    let (ms, c2) = (msgs.clone(), choices.clone());
    let ((m0, ()), (m1, got)) = run_two_party(
        move |ch| {
            let mut rng = ChaCha20Rng::seed_from_u64(7);
            let mut m = Meas::default();
            m.start_ch(ch, 1);
            let mut s = IknpSender::setup(ch, &mut rng);
            m.stop_ch(ch);
            m.start_ch(ch, 1);
            s.send(ch, &ms);
            m.stop_ch(ch);
            (m, ())
        },
        move |ch| {
            let mut rng = ChaCha20Rng::seed_from_u64(8);
            let mut m = Meas::default();
            m.start_ch(ch, 1);
            let mut r = IknpReceiver::setup(ch, &mut rng);
            m.stop_ch(ch);
            m.start_ch(ch, 1);
            let got = r.recv(ch, &c2);
            m.stop_ch(ch);
            (m, got)
        },
    );
    let ok = (0..n).all(|j| got[j] == if choices[j] { msgs[j].1 } else { msgs[j].0 });
    emit(LIB, "ot", "sh", n, &["setup", "extend"], &m0, &m1, ok);
}

/// Ferret (B13), one direction: setup = `CotPair::setup`, the base COTs and
/// the `pre` iteration; then two phases of n random COTs.
pub fn ferret(mal: bool, n: usize) {
    let cfg = FerretConfig::B13;
    let first_setup = if mal { 0 } else { 1 };
    let ((m0, delta, k), (m1, rm)) = run_two_party(
        move |ch| {
            let mut rng = ChaCha20Rng::seed_from_u64(9);
            // lsb 1, so the Ferret receiver knows lsb(Δ) without an exchange.
            let delta = Block::random(&mut rng).with_lsb(true);
            let mut m = Meas::default();
            m.start_ch(ch, first_setup);
            let mut cot = CotPair::setup(ch, &mut rng, delta, mal).unwrap();
            let RandomCots::Sender(base) = cot.random_cots(ch, 0, cfg.base_cots(mal), &mut rng).unwrap() else { unreachable!() };
            let mut s = FerretSender::bootstrap(ch, cfg, delta, &base, mal, &mut rng).unwrap();
            m.stop_ch(ch);
            let mut k = vec![];
            for _ in 0..2 {
                m.start_ch(ch, 1);
                s.ensure(ch, n, &mut rng).unwrap();
                k.push(s.take(n));
                m.stop_ch(ch);
            }
            (m, delta, k)
        },
        move |ch| {
            let mut rng = ChaCha20Rng::seed_from_u64(10);
            let mut m = Meas::default();
            m.start_ch(ch, first_setup);
            let mut cot = { let d = Block::random(&mut rng); CotPair::setup(ch, &mut rng, d, mal) }.unwrap();
            let RandomCots::Receiver(b, mm) = cot.random_cots(ch, 0, cfg.base_cots(mal), &mut rng).unwrap() else { unreachable!() };
            let mut r = FerretReceiver::bootstrap(ch, cfg, &b, &mm, true, mal, &mut rng).unwrap();
            m.stop_ch(ch);
            let mut out = vec![];
            for _ in 0..2 {
                m.start_ch(ch, 1);
                r.ensure(ch, n, &mut rng).unwrap();
                out.push(r.take(n));
                m.stop_ch(ch);
            }
            (m, out)
        },
    );
    let mut ok = true;
    for p in 0..2 {
        let (r, mm) = &rm[p];
        let ones = r.iter().filter(|&&b| b).count();
        ok &= ones > n / 3 && ones < 2 * n / 3;
        ok &= (0..n).all(|j| mm[j] == k[p][j] ^ delta.and_bit(r[j]));
    }
    emit(LIB, "ferret", if mal { "mal" } else { "sh" }, n, &["setup", "first N", "next N"], &m0, &m1, ok);
}

/// KK13 1-out-of-N chosen-message OT with `l`-bit messages.
pub fn kk13(n: usize, nn: usize, l: usize) {
    let mut rng = ChaCha20Rng::seed_from_u64(11);
    let mask = ((1u16 << l) - 1) as u8;
    let msgs: Vec<Vec<u8>> = (0..n).map(|_| (0..nn).map(|_| rng.r#gen::<u8>() & mask).collect()).collect();
    let choices: Vec<u8> = (0..n).map(|_| rng.gen_range(0..nn) as u8).collect();
    let (ms, c2) = (msgs.clone(), choices.clone());
    let ((m0, ()), (m1, got)) = run_two_party(
        move |ch| {
            let mut rng = ChaCha20Rng::seed_from_u64(12);
            let mut m = Meas::default();
            m.start_ch(ch, 1);
            let mut s = KkotSender::setup(ch, &mut rng);
            m.stop_ch(ch);
            m.start_ch(ch, 1);
            s.send(ch, &ms, nn, l);
            m.stop_ch(ch);
            (m, ())
        },
        move |ch| {
            let mut rng = ChaCha20Rng::seed_from_u64(13);
            let mut m = Meas::default();
            m.start_ch(ch, 1);
            let mut r = KkotReceiver::setup(ch, &mut rng);
            m.stop_ch(ch);
            m.start_ch(ch, 1);
            let got = r.recv(ch, &c2, nn, l);
            m.stop_ch(ch);
            (m, got)
        },
    );
    let ok = (0..n).all(|j| got[j] == msgs[j][choices[j] as usize]);
    emit(LIB, &format!("1ofN-kk13-N{nn}-l{l}"), "sh", n, &["setup", "extend"], &m0, &m1, ok);
}
