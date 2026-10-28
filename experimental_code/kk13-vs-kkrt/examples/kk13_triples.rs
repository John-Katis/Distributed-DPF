//! CrypTFlow2 bit triples on our KK13 (`dpf_common::ot::kkot`), exactly as
//! `dpf_common::bool2pc` makes them: one 1-out-of-8 OT of 2-bit messages per
//! correlated pair, the first triple used. Phases as in kkrt_triples.cpp:
//! setup (KK13's 256 Naor–Pinkas base OTs), `seq` single-triple calls (as
//! floram-arith's F_AND), one batch. Every triple is checked.
//!
//! ```text
//! cargo run --release -p exp-kk13-vs-kkrt --example kk13-triples -- [seq = 200] [batch = 2^20]
//! ```

use dpf_common::net::{run_two_party, Channel, CommStats};
use dpf_common::ot::kkot::{KkotReceiver, KkotSender};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use std::time::Instant;

type Triple = (bool, bool, bool);

fn sender_batch(ch: &mut Channel, s: &mut KkotSender, m: usize, rng: &mut ChaCha20Rng) -> Vec<Triple> {
    let mut out = Vec::with_capacity(m);
    let msgs: Vec<Vec<u8>> = (0..m)
        .map(|_| {
            let (a, b0, b1, c0, c1): (bool, bool, bool, bool, bool) = (rng.gen(), rng.gen(), rng.gen(), rng.gen(), rng.gen());
            out.push((a, b0, c0));
            (0..8u8)
                .map(|j| {
                    let (ja, jb0, jb1) = (j & 1 == 1, j & 2 == 2, j & 4 == 4);
                    let t0 = ((a ^ ja) & (b0 ^ jb0)) ^ c0;
                    let t1 = ((a ^ ja) & (b1 ^ jb1)) ^ c1;
                    (t1 as u8) << 1 | t0 as u8
                })
                .collect()
        })
        .collect();
    s.send(ch, &msgs, 8, 2);
    out
}

fn recver_batch(ch: &mut Channel, r: &mut KkotReceiver, m: usize, rng: &mut ChaCha20Rng) -> Vec<Triple> {
    let ab: Vec<(bool, bool, bool)> = (0..m).map(|_| (rng.gen(), rng.gen(), rng.gen())).collect();
    let sel: Vec<u8> = ab.iter().map(|&(a, b0, b1)| (b1 as u8) << 2 | (b0 as u8) << 1 | a as u8).collect();
    let res = r.recv(ch, &sel, 8, 2);
    ab.iter().zip(res).map(|(&(a, b0, _), c)| (a, b0, c & 1 == 1)).collect()
}

struct Meas {
    st: Vec<CommStats>,
    t: Vec<f64>,
}

fn party(ch: &mut Channel, seq: usize, batch: usize) -> (Meas, Vec<Triple>) {
    let mut rng = ChaCha20Rng::seed_from_u64(1 + ch.party() as u64);
    let mut m = Meas { st: vec![], t: vec![] };
    let mut out = vec![];
    let phase = |ch: &mut Channel, m: &mut Meas, f: &mut dyn FnMut(&mut Channel)| {
        ch.sync();
        // Party 1 speaks first in every phase (KK13's base-OT sender, and
        // the receiver's columns), so the sync's last round is not shared.
        let s0 = ch.stats();
        let t0 = Instant::now();
        f(ch);
        m.st.push(ch.stats().since(&s0));
        m.t.push(t0.elapsed().as_secs_f64());
    };
    if ch.party() == 0 {
        let mut s = None;
        phase(ch, &mut m, &mut |ch| s = Some(KkotSender::setup(ch, &mut rng)));
        let mut s = s.unwrap();
        let mut r2 = ChaCha20Rng::seed_from_u64(7);
        phase(ch, &mut m, &mut |ch| (0..seq).for_each(|_| out.extend(sender_batch(ch, &mut s, 1, &mut r2))));
        phase(ch, &mut m, &mut |ch| out.extend(sender_batch(ch, &mut s, batch, &mut r2)));
    } else {
        let mut r = None;
        phase(ch, &mut m, &mut |ch| r = Some(KkotReceiver::setup(ch, &mut rng)));
        let mut r = r.unwrap();
        let mut r2 = ChaCha20Rng::seed_from_u64(8);
        phase(ch, &mut m, &mut |ch| (0..seq).for_each(|_| out.extend(recver_batch(ch, &mut r, 1, &mut r2))));
        phase(ch, &mut m, &mut |ch| out.extend(recver_batch(ch, &mut r, batch, &mut r2)));
    }
    (m, out)
}

fn main() {
    let a: Vec<usize> = std::env::args().skip(1).map(|s| s.parse().unwrap()).collect();
    let seq = a.first().copied().unwrap_or(200);
    let batch = a.get(1).copied().unwrap_or(1 << 20);
    let ((m0, t0), (m1, t1)) = run_two_party(move |ch| party(ch, seq, batch), move |ch| party(ch, seq, batch));
    let ok = t0.len() == t1.len() && t0.iter().zip(&t1).all(|(x, y)| ((x.0 ^ y.0) & (x.1 ^ y.1)) == (x.2 ^ y.2));
    for (i, (ph, n)) in [("setup", seq + batch), ("seq", seq), ("batch", batch)].iter().enumerate() {
        let (a, b) = (m0.st[i], m1.st[i]);
        println!(
            "KK13 (ours),and-triples,sh,{n},{ph},{},{},{},{:.6},{}",
            a.bytes_sent + b.bytes_sent,
            a.rounds.max(b.rounds),
            a.messages_sent + b.messages_sent,
            m0.t[i].max(m1.t[i]),
            if ok { "ok" } else { "FAIL" }
        );
    }
}
