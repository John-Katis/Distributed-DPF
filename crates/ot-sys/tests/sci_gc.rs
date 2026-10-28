//! SCI (triples, multiplexer) and the half-gates bindings, two threads.

use dpf_ot_sys::*;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::Mutex;

struct Shared(Mutex<Sender<(usize, Vec<u8>)>>, Mutex<Receiver<(usize, Vec<u8>)>>, std::sync::atomic::AtomicUsize);

impl SharedTransport for Shared {
    fn clock(&self) -> usize {
        self.2.load(std::sync::atomic::Ordering::Relaxed)
    }
    fn advance_clock(&self, s: usize) {
        self.2.fetch_max(s, std::sync::atomic::Ordering::Relaxed);
    }
    fn send_at(&self, m: Vec<u8>, s: usize) -> bool {
        self.0.lock().unwrap().send((s, m)).is_ok()
    }
    fn recv_at(&self) -> Option<(usize, Vec<u8>)> {
        self.1.lock().unwrap().recv().ok()
    }
}

fn two<A: Send, B: Send>(f0: impl FnOnce(&Shared) -> A + Send, f1: impl FnOnce(&Shared) -> B + Send) -> (A, B) {
    let (t0, r1) = channel();
    let (t1, r0) = channel();
    let (p0, p1) = (Shared(Mutex::new(t0), Mutex::new(r0), Default::default()), Shared(Mutex::new(t1), Mutex::new(r1), Default::default()));
    std::thread::scope(|s| {
        let h = s.spawn(move || f1(&p1));
        let a = f0(&p0);
        (a, h.join().unwrap())
    })
}

fn rnd(i: u64) -> u64 {
    let x = (i + 1).wrapping_mul(0x9e37_79b9_7f4a_7c15);
    x ^ (x >> 29) ^ (x << 11)
}

#[test]
fn sci_triples_and_mux() {
    let n = 1000;
    let bw = 37;
    let mask = (1u64 << bw) - 1;
    let sel: [Vec<bool>; 2] = [(0..n).map(|i| rnd(i) & 1 == 1).collect(), (0..n).map(|i| rnd(i + 99) & 2 == 2).collect()];
    let x: [Vec<u64>; 2] = [(0..n).map(|i| rnd(i + 7) & mask).collect(), (0..n).map(|i| rnd(i + 8) & mask).collect()];
    let (s0, s1, x0, x1) = (sel[0].clone(), sel[1].clone(), x[0].clone(), x[1].clone());
    let ((t0, y0), (t1, y1)) = two(
        move |t| {
            let mut s = Sci::new(t, true).unwrap();
            let tr = s.triples(t, 2 * n as usize).unwrap();
            (tr, s.mux(t, &s0, &x0, bw).unwrap())
        },
        move |t| {
            let mut s = Sci::new(t, false).unwrap();
            let tr = s.triples(t, 2 * n as usize).unwrap();
            (tr, s.mux(t, &s1, &x1, bw).unwrap())
        },
    );
    for i in 0..2 * n as usize {
        let (a, b, c) = (t0[i].0 ^ t1[i].0, t0[i].1 ^ t1[i].1, t0[i].2 ^ t1[i].2);
        assert_eq!(a & b, c, "triple {i}");
    }
    for i in 0..n as usize {
        let s = sel[0][i] ^ sel[1][i];
        let xv = x[0][i].wrapping_add(x[1][i]) & mask;
        assert_eq!(y0[i].wrapping_add(y1[i]) & mask, if s { xv } else { 0 }, "mux {i}");
    }
}

#[test]
fn half_gates_agree() {
    let delta = 0x1234_5678_9abc_def0_0fed_cba9_8765_4321u128 | 1;
    let s = 0x55u128 << 64 | 0xaa;
    let n = 300;
    let a0: Vec<u128> = (0..n).map(|i| (rnd(i) as u128) << 64 | rnd(i + 1) as u128).collect();
    let b0: Vec<u128> = (0..n).map(|i| (rnd(i + 2) as u128) << 64 | rnd(i + 3) as u128).collect();
    for (x, y) in [(false, false), (false, true), (true, false), (true, true)] {
        // Fresh instances: the hash state advances once per gate, in order.
        let (mut g, mut e) = (HalfGates::new(s), HalfGates::new(s));
        for round in 0..3 {
            let (out0, tables) = g.garble(delta, &a0, &b0);
            let a: Vec<u128> = a0.iter().map(|&v| v ^ if x { delta } else { 0 }).collect();
            let b: Vec<u128> = b0.iter().map(|&v| v ^ if y { delta } else { 0 }).collect();
            let w = e.eval(&a, &b, &tables);
            for i in 0..n as usize {
                assert_eq!(w[i], out0[i] ^ if x & y { delta } else { 0 }, "round {round} gate {i} ({x},{y})");
            }
        }
    }
}
