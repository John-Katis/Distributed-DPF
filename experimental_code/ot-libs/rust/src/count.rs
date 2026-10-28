//! The Rust twin of `../cpp/count_io.h`: an in-memory duplex link that counts
//! bytes, messages and rounds with the rule of `dpf_common::net::Channel`
//! (a message is stamped clock + 1, a party's clock is the largest stamp it
//! received), for libraries that bring their own channel trait (swanky).
//! Writes are buffered and leave as one message on `flush` or on the next
//! read. Also the CSV row shared by every harness.

use dpf_common::net::{Channel, CommStats};
use std::io;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::time::Instant;

#[derive(Clone, Copy, Debug, Default)]
pub struct Stats {
    pub bytes_sent: u64,
    pub msgs: u64,
    pub rounds: u64,
}

impl std::ops::Sub for Stats {
    type Output = Stats;
    fn sub(self, o: Stats) -> Stats {
        Stats { bytes_sent: self.bytes_sent - o.bytes_sent, msgs: self.msgs - o.msgs, rounds: self.rounds - o.rounds }
    }
}

impl From<CommStats> for Stats {
    fn from(s: CommStats) -> Stats {
        Stats { bytes_sent: s.bytes_sent as u64, msgs: s.messages_sent as u64, rounds: s.rounds as u64 }
    }
}

type Msg = (u64, Vec<u8>);

pub struct End {
    pub party: usize,
    tx: Sender<Msg>,
    rx: Receiver<Msg>,
    buf: Vec<u8>,
    cur: Vec<u8>,
    pos: usize,
    clock: u64,
    st: Stats,
}

pub fn link() -> (End, End) {
    let (t0, r1) = channel();
    let (t1, r0) = channel();
    let mk = |party, tx, rx| End { party, tx, rx, buf: vec![], cur: vec![], pos: 0, clock: 0, st: Stats::default() };
    (mk(0, t0, r0), mk(1, t1, r1))
}

impl End {
    pub fn write(&mut self, b: &[u8]) {
        self.buf.extend_from_slice(b);
    }

    pub fn flush(&mut self) {
        if self.buf.is_empty() {
            return;
        }
        let stamp = self.clock + 1;
        self.st.rounds = self.st.rounds.max(stamp);
        self.st.bytes_sent += self.buf.len() as u64;
        self.st.msgs += 1;
        self.tx.send((stamp, std::mem::take(&mut self.buf))).expect("peer hung up");
    }

    pub fn read(&mut self, out: &mut [u8]) {
        self.flush();
        let mut off = 0;
        while off < out.len() {
            if self.pos == self.cur.len() {
                let (stamp, m) = self.rx.recv().expect("peer hung up");
                self.clock = self.clock.max(stamp);
                self.st.rounds = self.st.rounds.max(stamp);
                self.cur = m;
                self.pos = 0;
            }
            let k = (out.len() - off).min(self.cur.len() - self.pos);
            out[off..off + k].copy_from_slice(&self.cur[self.pos..self.pos + k]);
            self.pos += k;
            off += k;
        }
    }

    pub fn stats(&self) -> Stats {
        self.st
    }

    /// Round trip as `Channel::sync`, then a fresh round for whoever speaks next.
    pub fn sync(&mut self) {
        let mut x = [0u8];
        if self.party == 1 {
            self.write(&x);
            self.read(&mut x);
        } else {
            self.read(&mut x);
            self.write(&x);
            self.flush();
        }
        self.clock = self.st.rounds;
    }
}

impl swanky_channel_legacy::AbstractChannel for End {
    fn read_bytes(&mut self, bytes: &mut [u8]) -> io::Result<()> {
        self.read(bytes);
        Ok(())
    }
    fn write_bytes(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.write(bytes);
        Ok(())
    }
    fn flush(&mut self) -> io::Result<()> {
        End::flush(self);
        Ok(())
    }
}

/// Consecutive measured phases of one party.
#[derive(Default)]
pub struct Meas {
    pub st: Vec<Stats>,
    pub t: Vec<f64>,
    s0: Stats,
    t0: Option<Instant>,
}

impl Meas {
    pub fn start(&mut self, e: &mut End) {
        e.flush();
        e.sync();
        self.s0 = e.stats();
        self.t0 = Some(Instant::now());
    }

    pub fn stop(&mut self, e: &mut End) {
        e.flush();
        self.st.push(e.stats() - self.s0);
        self.t.push(self.t0.unwrap().elapsed().as_secs_f64());
    }

    /// As `start` over our `Channel`. `Channel::sync` ends with party 0
    /// sending, so if party 0 also speaks first in the phase its message
    /// would share that round: `first = 0` adds one message 1 → 0 so party
    /// 0's clock is current. Not counted.
    pub fn start_ch(&mut self, ch: &mut Channel, first: usize) {
        ch.sync();
        if first == 0 {
            if ch.party() == 1 {
                ch.send(vec![0]);
            } else {
                ch.recv();
            }
        }
        self.s0 = ch.stats().into();
        self.t0 = Some(Instant::now());
    }

    pub fn stop_ch(&mut self, ch: &mut Channel) {
        self.st.push(Stats::from(ch.stats()) - self.s0);
        self.t.push(self.t0.unwrap().elapsed().as_secs_f64());
    }
}

/// lib,component,security,n,phase,bytes,rounds,msgs,secs,check, as `cio::row`.
pub fn emit(lib: &str, comp: &str, sec: &str, n: usize, phases: &[&str], m0: &Meas, m1: &Meas, ok: bool) {
    for (i, ph) in phases.iter().enumerate() {
        let (a, b) = (m0.st[i], m1.st[i]);
        println!(
            "{lib},{comp},{sec},{n},{ph},{},{},{},{:.6},{}",
            a.bytes_sent + b.bytes_sent,
            a.rounds.max(b.rounds),
            a.msgs + b.msgs,
            m0.t[i].max(m1.t[i]),
            if ok { "ok" } else { "FAIL" }
        );
    }
}
