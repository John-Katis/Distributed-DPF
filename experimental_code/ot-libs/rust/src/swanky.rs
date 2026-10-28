//! swanky (Galois, legacy `AbstractChannel` OT crates) over `count::End`.
//! Base OT: Naor–Pinkas and Chou–Orlandi (128 chosen-message OTs). OT
//! extension: ALSZ (semi-honest) and KOS (malicious), as random OT and as
//! correlated OT with a chosen Δ (one extra block per OT).

use crate::count::{emit, link, End, Meas};
use rand010::{RngExt, SeedableRng};
use rand010::rngs::StdRng;
use swanky_block::Block;
use swanky_field_binary::F2;
use swanky_ot_traits::{CorrelatedReceiver, CorrelatedSender, RandomReceiver, RandomSender, Receiver, Sender};

const LIB: &str = "swanky";

fn rng(seed: u64) -> StdRng {
    StdRng::seed_from_u64(seed)
}

fn block(r: &mut StdRng) -> Block {
    Block::from(r.random::<[u8; 16]>())
}

fn two<A: Send, B: Send>(f0: impl FnOnce(&mut End) -> A + Send, f1: impl FnOnce(&mut End) -> B + Send) -> (A, B) {
    let (mut e0, mut e1) = link();
    std::thread::scope(|s| {
        let h = s.spawn(move || f1(&mut e1));
        let a = f0(&mut e0);
        (a, h.join().unwrap())
    })
}

fn base<S: Sender<Msg = Block>, R: Receiver<Msg = Block>>(name: &str) {
    let n = 128;
    let mut r = rng(1);
    let data: Vec<(Block, Block)> = (0..n).map(|_| (block(&mut r), block(&mut r))).collect();
    let choices: Vec<bool> = (0..n).map(|_| r.random()).collect();
    let (d2, c2) = (data.clone(), choices.clone());
    let ((m0, ()), (m1, got)) = two(
        move |e| {
            let mut m = Meas::default();
            let mut r = rng(2);
            m.start(e);
            let mut s = S::init(e, &mut r).unwrap();
            s.send(e, &d2, &mut r).unwrap();
            m.stop(e);
            (m, ())
        },
        move |e| {
            let mut m = Meas::default();
            let mut r = rng(3);
            m.start(e);
            let mut rv = R::init(e, &mut r).unwrap();
            let cs: Vec<F2> = c2.iter().map(|&b| F2::from(b)).collect();
            let got = rv.receive(e, &cs, &mut r).unwrap();
            m.stop(e);
            (m, got)
        },
    );
    let ok = (0..n).all(|i| got[i] == if choices[i] { data[i].1 } else { data[i].0 });
    emit(LIB, name, "-", n, &["all"], &m0, &m1, ok);
}

pub fn base_all() {
    base::<swanky_ot_noar_pinkas::Sender, swanky_ot_noar_pinkas::Receiver>("base-np");
    base::<swanky_ot_chou_orlandi::Sender, swanky_ot_chou_orlandi::Receiver>("base-co");
}

/// Random OT extension: setup (`init`, the base OTs), then n random OTs.
fn rot<S: RandomSender<Msg = Block>, R: RandomReceiver<Msg = Block>>(comp: &str, sec: &str, n: usize) {
    let choices: Vec<bool> = {
        let mut r = rng(4);
        (0..n).map(|_| r.random()).collect()
    };
    let c2 = choices.clone();
    let ((m0, ms), (m1, got)) = two(
        move |e| {
            let mut m = Meas::default();
            let mut r = rng(5);
            m.start(e);
            let mut s = S::init(e, &mut r).unwrap();
            m.stop(e);
            m.start(e);
            let ms = s.send_random(e, n, &mut r).unwrap();
            m.stop(e);
            (m, ms)
        },
        move |e| {
            let mut m = Meas::default();
            let mut r = rng(6);
            m.start(e);
            let mut rv = R::init(e, &mut r).unwrap();
            m.stop(e);
            m.start(e);
            let cs: Vec<F2> = c2.iter().map(|&b| F2::from(b)).collect();
            let got = rv.receive_random(e, &cs, &mut r).unwrap();
            m.stop(e);
            (m, got)
        },
    );
    let ok = (0..n).all(|i| got[i] == if choices[i] { ms[i].1 } else { ms[i].0 });
    emit(LIB, comp, sec, n, &["setup", "extend"], &m0, &m1, ok);
}

/// Correlated OT with a chosen Δ: n OTs with m1 = m0 ⊕ Δ.
fn cot<S: CorrelatedSender<Msg = Block>, R: CorrelatedReceiver<Msg = Block>>(comp: &str, sec: &str, n: usize) {
    let mut r0 = rng(7);
    let delta = block(&mut r0);
    let choices: Vec<bool> = (0..n).map(|_| r0.random()).collect();
    let c2 = choices.clone();
    let ((m0, ms), (m1, got)) = two(
        move |e| {
            let mut m = Meas::default();
            let mut r = rng(8);
            m.start(e);
            let mut s = S::init(e, &mut r).unwrap();
            m.stop(e);
            m.start(e);
            let ms = s.send_correlated(e, n, delta, &mut r).unwrap();
            m.stop(e);
            (m, ms)
        },
        move |e| {
            let mut m = Meas::default();
            let mut r = rng(9);
            m.start(e);
            let mut rv = R::init(e, &mut r).unwrap();
            m.stop(e);
            m.start(e);
            let cs: Vec<F2> = c2.iter().map(|&b| F2::from(b)).collect();
            let got = rv.receive_correlated(e, &cs, &mut r).unwrap();
            m.stop(e);
            (m, got)
        },
    );
    let ok = (0..n).all(|i| got[i] == if choices[i] { ms[i] ^ delta } else { ms[i] });
    emit(LIB, comp, sec, n, &["setup", "extend"], &m0, &m1, ok);
}

pub fn ext_all(n: usize) {
    use swanky_ot_alsz_kos::{alsz, kos};
    rot::<alsz::Sender, alsz::Receiver>("rot", "sh", n);
    rot::<kos::Sender, kos::Receiver>("rot", "mal", n);
    cot::<alsz::Sender, alsz::Receiver>("cot-chosen-delta", "sh", n);
    cot::<kos::Sender, kos::Receiver>("cot-chosen-delta", "mal", n);
}
