//! The raw bindings over an in-memory transport, two threads.

use dpf_ot_sys::*;
use std::sync::mpsc::{channel, Receiver, Sender};

struct Pipe(Sender<Vec<u8>>, Receiver<Vec<u8>>);

impl Transport for Pipe {
    fn send_msg(&mut self, m: Vec<u8>) -> bool {
        self.0.send(m).is_ok()
    }
    fn recv_msg(&mut self) -> Option<Vec<u8>> {
        self.1.recv().ok()
    }
}

fn two<A: Send, B: Send>(f0: impl FnOnce(&mut Pipe) -> A + Send, f1: impl FnOnce(&mut Pipe) -> B + Send) -> (A, B) {
    let (t0, r1) = channel();
    let (t1, r0) = channel();
    let (mut p0, mut p1) = (Pipe(t0, r0), Pipe(t1, r1));
    std::thread::scope(|s| {
        let h = s.spawn(move || f1(&mut p1));
        let a = f0(&mut p0);
        (a, h.join().unwrap())
    })
}

fn rnd(i: u64) -> u128 {
    let x = (i as u128 + 1).wrapping_mul(0x9e37_79b9_7f4a_7c15_f39c_c060_5ced_c835);
    x ^ (x >> 61) ^ (x << 17)
}

fn choices(n: usize, s: u64) -> Vec<bool> {
    (0..n).map(|i| rnd(i as u64 + s) & 4 != 0).collect()
}

#[test]
fn naor_pinkas() {
    let m0: Vec<u128> = (0..128).map(|i| rnd(i)).collect();
    let m1: Vec<u128> = (0..128).map(|i| rnd(i + 500)).collect();
    let b = choices(128, 9);
    let (a0, a1, bb) = (m0.clone(), m1.clone(), b.clone());
    let ((), got) = two(move |t| np_send(t, &a0, &a1).unwrap(), move |t| np_recv(t, &bb).unwrap());
    for i in 0..128 {
        assert_eq!(got[i], if b[i] { m1[i] } else { m0[i] });
    }
}

#[test]
fn masny_rindal() {
    let b = choices(128, 3);
    let bb = b.clone();
    let (m, got) = two(move |t| mr_send(t, [1; 16], 128, None).unwrap(), move |t| mr_recv(t, [2; 16], &bb, None).unwrap());
    for i in 0..128 {
        assert_ne!(m[i].0, m[i].1);
        assert_eq!(got[i], if b[i] { m[i].1 } else { m[i].0 });
    }
}

#[test]
fn masny_rindal_tampered_aborts_or_mismatches() {
    let b = choices(128, 4);
    let bb = b.clone();
    let (m, got) = two(move |t| mr_send(t, [1; 16], 128, Some(40)), move |t| mr_recv(t, [2; 16], &bb, None));
    match (m, got) {
        (Ok(m), Ok(got)) => assert!((0..128).any(|i| got[i] != if b[i] { m[i].1 } else { m[i].0 })),
        _ => {}
    }
}

/// Base OTs for an IKNP instance: sender's Δ bits and keys, receiver's pairs.
fn iknp_pair(mal: bool, delta: u128) -> ((Iknp, u128), Iknp) {
    let s: [bool; 128] = std::array::from_fn(|i| (delta >> i) & 1 == 1);
    let k0: Vec<u128> = (0..128).map(|i| rnd(i + 1000)).collect();
    let k1: Vec<u128> = (0..128).map(|i| rnd(i + 2000)).collect();
    let kb: [u128; 128] = std::array::from_fn(|i| if s[i] { k1[i] } else { k0[i] });
    let (k0a, k1a): ([u128; 128], [u128; 128]) = (k0.try_into().unwrap(), k1.try_into().unwrap());
    two(
        move |t| {
            let mut x = Iknp::new(mal);
            x.setup_send(t, &s, &kb).unwrap();
            let d = x.delta();
            (x, d)
        },
        move |t| {
            let mut x = Iknp::new(mal);
            x.setup_recv(t, &k0a, &k1a).unwrap();
            x
        },
    )
}

#[test]
fn iknp_cot_delta_and_ot() {
    for mal in [false, true] {
        let delta = rnd(77);
        let ((mut s, d), mut r) = iknp_pair(mal, delta);
        assert_eq!(d, delta, "emp's Δ is the base-OT choice vector in our bit order");
        let b = choices(1000, 5);
        let bb = b.clone();
        let (k, m) = two(|t| s.send_cot(t, 1000).unwrap(), |t| r.recv_cot(t, &bb).unwrap());
        for i in 0..1000 {
            assert_eq!(m[i], k[i] ^ if b[i] { delta } else { 0 });
        }
        let m0: Vec<u128> = (0..300).map(|i| rnd(i + 7)).collect();
        let m1: Vec<u128> = (0..300).map(|i| rnd(i + 8)).collect();
        let c = choices(300, 6);
        let (a0, a1, cc) = (m0.clone(), m1.clone(), c.clone());
        let ((), got) = two(|t| s.send(t, &a0, &a1).unwrap(), |t| r.recv(t, &cc).unwrap());
        for i in 0..300 {
            assert_eq!(got[i], if c[i] { m1[i] } else { m0[i] });
        }
    }
}

#[test]
fn iknp_malicious_tamper_aborts() {
    let ((mut s, _), mut r) = iknp_pair(true, rnd(1));
    let b = choices(2000, 7);
    r.fault_next = Some(100);
    let (k, m) = two(|t| s.send_cot(t, 2000), |t| r.recv_cot(t, &b));
    assert!(k.is_err(), "the sender's check must fail");
    let _ = m;
}

const TOY: FerretParams = [1024, 16, 200, 6, 512, 8, 100, 6];

#[test]
fn ferret_both_modes() {
    for mal in [false, true] {
        let nb = ferret_base_cots(&TOY);
        let delta = rnd(5) | 1;
        let k: Vec<u128> = (0..nb).map(|i| rnd(i as u64 + 9000)).collect();
        let bits = choices(nb, 11);
        let m: Vec<u128> = (0..nb).map(|i| k[i] ^ if bits[i] { delta } else { 0 }).collect();
        let (ks, ms) = two(
            move |t| {
                let mut f = Ferret::new(true, mal, &TOY).unwrap();
                f.setup(t, Some(delta), &k, &[]).unwrap();
                (f.rcot(t, 700).unwrap(), f.rcot(t, 3000).unwrap())
            },
            move |t| {
                let mut f = Ferret::new(false, mal, &TOY).unwrap();
                f.setup(t, None, &m, &bits).unwrap();
                (f.rcot(t, 700).unwrap(), f.rcot(t, 3000).unwrap())
            },
        );
        for (k, m) in [(&ks.0, &ms.0), (&ks.1, &ms.1)] {
            let ones = m.iter().filter(|&&x| x & 1 == 1).count();
            assert!(ones > m.len() / 3 && ones < 2 * m.len() / 3);
            for i in 0..k.len() {
                assert_eq!(k[i] & 1, 0);
                assert_eq!(m[i], k[i] ^ if m[i] & 1 == 1 { delta } else { 0 });
            }
        }
    }
}


/// emp's check covers exactly the rows handed out (and its 256 extra ones):
/// a flipped bit in a used row aborts, one in a padding row is harmless.
#[test]
fn iknp_malicious_small_batch() {
    for (off, caught) in [(16usize, true), (3, false)] {
        let ((mut s, _), mut r) = iknp_pair(true, u128::MAX);
        let b = choices(10, 7);
        r.fault_next = Some(off);
        let (k, _) = two(|t| s.send_cot(t, 10), |t| r.recv_cot(t, &b));
        assert_eq!(k.is_err(), caught, "offset {off}");
    }
}

/// A corrupted secret sum (the first tree's, after its `log_bin` levels of
/// 32 bytes) makes the malicious receiver abort. Needs build.sh's patch of
/// emp's `consistency_check_f2k`, which otherwise only prints a warning.
#[test]
fn ferret_malicious_tamper_aborts() {
    let nb = ferret_base_cots(&TOY);
    let delta = rnd(5) | 1;
    let k: Vec<u128> = (0..nb).map(|i| rnd(i as u64 + 9000)).collect();
    let bits = choices(nb, 11);
    let m: Vec<u128> = (0..nb).map(|i| k[i] ^ if bits[i] { delta } else { 0 }).collect();
    let (_, r) = two(
        move |t| {
            let mut f = Ferret::new(true, true, &TOY).unwrap();
            f.setup(t, Some(delta), &k, &[]).unwrap();
            f.fault_next = Some(32 * TOY[3] as usize);
            f.rcot(t, 700).map(|_| ())
        },
        move |t| {
            let mut f = Ferret::new(false, true, &TOY).unwrap();
            f.setup(t, None, &m, &bits).unwrap();
            f.rcot(t, 700).map(|_| ())
        },
    );
    assert_eq!(r, Err(OtError("SPCOT consistency check fails".into())));
}
