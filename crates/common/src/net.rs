//! In-process two- and three-party networks with byte and round counting.
//!
//! Each party runs on its own thread and talks over a pair of `mpsc` channels.
//! Nothing touches a socket, and nothing is delayed: network cost is added
//! analytically from the counters ([`net_time`]).
//!
//! # Rounds
//!
//! A round is one one-way network latency (Duoram's "sequential messages").
//! Messages that can be in transit at the same time share a round, so a
//! simultaneous exchange (both parties send their CW share, then both
//! receive) is one round, while a request and its reply are two.
//!
//! Every message carries a depth stamp. A party's clock is the largest stamp
//! it has received, a message it sends is stamped clock + 1, and a party's
//! round count is the largest stamp it has sent or received. The protocol's
//! round count is the maximum over the parties. In a three-party protocol a
//! party's links share one clock, so a message relayed through a party
//! counts as two rounds.

use crate::block::{blocks_from_bytes, blocks_to_bytes, pack_bits, unpack_bits, Block};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Communication counters for one party.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CommStats {
    pub bytes_sent: usize,
    pub bytes_recv: usize,
    pub messages_sent: usize,
    /// Largest round stamp this party has sent or received (see the module
    /// docs). After [`since`](Self::since), the rounds within that span.
    pub rounds: usize,
}

impl CommStats {
    /// Bytes on the wire in both directions, as seen by this party.
    pub fn total_bytes(&self) -> usize {
        self.bytes_sent + self.bytes_recv
    }

    /// Counters accumulated since `earlier`.
    pub fn since(&self, earlier: &CommStats) -> CommStats {
        CommStats {
            bytes_sent: self.bytes_sent - earlier.bytes_sent,
            bytes_recv: self.bytes_recv - earlier.bytes_recv,
            messages_sent: self.messages_sent - earlier.messages_sent,
            rounds: self.rounds - earlier.rounds,
        }
    }
}

/// Counters of two consecutive spans of one party.
impl std::ops::Add for CommStats {
    type Output = CommStats;

    fn add(self, later: CommStats) -> CommStats {
        CommStats {
            bytes_sent: self.bytes_sent + later.bytes_sent,
            bytes_recv: self.bytes_recv + later.bytes_recv,
            messages_sent: self.messages_sent + later.messages_sent,
            rounds: self.rounds + later.rounds,
        }
    }
}

/// Network time over a real link: `rounds·latency + 8·bytes/bandwidth`, with
/// `latency` one-way and `bytes` the traffic in both directions.
pub fn net_time(rounds: usize, bytes: usize, latency: Duration, bits_per_sec: f64) -> Duration {
    latency * rounds as u32 + Duration::from_secs_f64(8.0 * bytes as f64 / bits_per_sec)
}

/// A message and its round stamp.
type Msg = (usize, Vec<u8>);

/// One party's end of the two-party link.
///
/// The receiver and the counters sit behind (uncontended) locks so that a
/// library running two threads on one channel (SCI's two COT directions,
/// [`dpf_ot_sys::SharedTransport`]) can send and receive through `&self`.
pub struct Channel {
    party: usize,
    tx: Sender<Msg>,
    rx: Mutex<Receiver<Msg>>,
    stats: Mutex<CommStats>,
    /// Largest stamp received by this party, shared by all of its links.
    clock: Arc<AtomicUsize>,
}

impl Channel {
    /// Party index: 0 is Floram's party 1 (garbler, OT sender) and 1 is party 2
    /// (evaluator, OT receiver).
    pub fn party(&self) -> usize {
        self.party
    }

    pub fn stats(&self) -> CommStats {
        *self.stats.lock().unwrap()
    }

    pub fn send(&mut self, msg: Vec<u8>) {
        assert!(self.try_send(msg), "peer hung up");
    }

    pub fn recv(&mut self) -> Vec<u8> {
        self.try_recv().expect("peer hung up")
    }

    /// As [`send`](Self::send), but `false` instead of a panic if the peer
    /// has closed its end.
    pub fn try_send(&mut self, msg: Vec<u8>) -> bool {
        self.send_shared(msg)
    }

    /// As [`recv`](Self::recv), but `None` instead of a panic if the peer
    /// has closed its end.
    pub fn try_recv(&mut self) -> Option<Vec<u8>> {
        self.recv_shared()
    }

    fn send_shared(&self, msg: Vec<u8>) -> bool {
        let stamp = self.clock.load(Ordering::Relaxed) + 1;
        let len = msg.len();
        if self.tx.send((stamp, msg)).is_err() {
            return false;
        }
        let mut st = self.stats.lock().unwrap();
        st.rounds = st.rounds.max(stamp);
        st.bytes_sent += len;
        st.messages_sent += 1;
        true
    }

    fn recv_shared(&self) -> Option<Vec<u8>> {
        let (stamp, msg) = self.rx.lock().unwrap().recv().ok()?;
        self.clock.fetch_max(stamp, Ordering::Relaxed);
        let mut st = self.stats.lock().unwrap();
        st.rounds = st.rounds.max(stamp);
        st.bytes_recv += msg.len();
        Some(msg)
    }

    /// A round trip (party 1 → party 0 → party 1) after which both parties
    /// know the other has finished everything before the call. Used to start
    /// generation timers on a common footing after setup.
    pub fn sync(&mut self) {
        if self.party == 1 {
            self.send(vec![0]);
            self.recv();
        } else {
            self.recv();
            self.send(vec![0]);
        }
    }

    pub fn send_blocks(&mut self, v: &[Block]) {
        self.send(blocks_to_bytes(v));
    }

    pub fn recv_blocks(&mut self, n: usize) -> Vec<Block> {
        let v = blocks_from_bytes(&self.recv());
        assert_eq!(v.len(), n, "unexpected message length");
        v
    }

    /// Sends an `out_bits`-bit payload (`ceil(out_bits/128)` blocks whose bits
    /// from `out_bits` on are zero) in `ceil(out_bits/8)` bytes.
    pub fn send_payload(&mut self, v: &[Block], out_bits: usize) {
        self.send(crate::block::payload_to_bytes(v, out_bits));
    }

    /// Receives what [`send_payload`](Self::send_payload) sent.
    pub fn recv_payload(&mut self, out_bits: usize) -> Vec<Block> {
        crate::block::payload_from_bytes(&self.recv(), out_bits)
    }

    pub fn send_bits(&mut self, bits: &[bool]) {
        self.send(pack_bits(bits));
    }

    pub fn recv_bits(&mut self, n: usize) -> Vec<bool> {
        let m = self.recv();
        assert_eq!(m.len(), n.div_ceil(8), "unexpected message length");
        unpack_bits(&m, n)
    }
}

/// The OT libraries of [`dpf_ot_sys`] send their messages over a `Channel`,
/// so they are counted like every other message.
impl dpf_ot_sys::Transport for Channel {
    fn send_msg(&mut self, msg: Vec<u8>) -> bool {
        self.try_send(msg)
    }

    fn recv_msg(&mut self) -> Option<Vec<u8>> {
        self.try_recv()
    }
}

/// SCI ([`dpf_ot_sys::Sci`]) uses one channel from two threads. Its bridge
/// keeps a clock per thread (a thread's message depends only on what that
/// thread received), so two parallel COT directions share their rounds as in
/// the network model, whatever the thread timing.
impl dpf_ot_sys::SharedTransport for Channel {
    fn clock(&self) -> usize {
        self.clock.load(Ordering::Relaxed)
    }

    fn advance_clock(&self, stamp: usize) {
        self.clock.fetch_max(stamp, Ordering::Relaxed);
    }

    fn send_at(&self, msg: Vec<u8>, stamp: usize) -> bool {
        let len = msg.len();
        if self.tx.send((stamp, msg)).is_err() {
            return false;
        }
        let mut st = self.stats.lock().unwrap();
        st.rounds = st.rounds.max(stamp);
        st.bytes_sent += len;
        st.messages_sent += 1;
        true
    }

    fn recv_at(&self) -> Option<(usize, Vec<u8>)> {
        let (stamp, msg) = self.rx.lock().unwrap().recv().ok()?;
        let mut st = self.stats.lock().unwrap();
        st.rounds = st.rounds.max(stamp);
        st.bytes_recv += msg.len();
        Some((stamp, msg))
    }
}

/// A connected pair of channels, for party 0 and party 1.
pub fn channel_pair() -> (Channel, Channel) {
    let (tx0, rx1) = channel();
    let (tx1, rx0) = channel();
    let mk = |party, tx, rx| Channel { party, tx, rx: Mutex::new(rx), stats: Mutex::default(), clock: Arc::default() };
    (mk(0, tx0, rx0), mk(1, tx1, rx1))
}

/// Runs `f0` as party 0 and `f1` as party 1 on two scoped threads and returns
/// both results.
pub fn run_two_party<R0, R1, F0, F1>(f0: F0, f1: F1) -> (R0, R1)
where
    R0: Send,
    R1: Send,
    F0: FnOnce(&mut Channel) -> R0 + Send,
    F1: FnOnce(&mut Channel) -> R1 + Send,
{
    let (mut c0, mut c1) = channel_pair();
    std::thread::scope(|s| {
        let h0 = s.spawn(move || f0(&mut c0));
        let h1 = s.spawn(move || f1(&mut c1));
        let r0 = h0.join().expect("party 0 panicked");
        let r1 = h1.join().expect("party 1 panicked");
        (r0, r1)
    })
}

/// One party's links to the other two in a three-party protocol. Each link is
/// an ordinary [`Channel`] pair, so every link keeps its own [`CommStats`];
/// on the link between parties `i < j`, `i` is the channel's party 0.
pub struct Peers {
    party: usize,
    links: [Option<Channel>; 3],
}

impl Peers {
    /// Party index in 0..3.
    pub fn party(&self) -> usize {
        self.party
    }

    /// The link to party `j`.
    pub fn to(&mut self, j: usize) -> &mut Channel {
        self.links[j].as_mut().expect("no link to self")
    }

    /// Counters of the link to party `j`.
    pub fn stats_with(&self, j: usize) -> CommStats {
        self.links[j].as_ref().expect("no link to self").stats()
    }

    /// Counters summed over both links (rounds: the larger of the two).
    pub fn stats(&self) -> CommStats {
        let mut s = CommStats::default();
        for l in self.links.iter().flatten() {
            let t = l.stats();
            s.bytes_sent += t.bytes_sent;
            s.bytes_recv += t.bytes_recv;
            s.messages_sent += t.messages_sent;
            s.rounds = s.rounds.max(t.rounds);
        }
        s
    }
}

/// Runs `f0`, `f1`, `f2` as parties 0, 1 and 2 on three scoped threads, fully
/// connected, and returns their results.
pub fn run_three_party<R0, R1, R2, F0, F1, F2>(f0: F0, f1: F1, f2: F2) -> (R0, R1, R2)
where
    R0: Send,
    R1: Send,
    R2: Send,
    F0: FnOnce(&mut Peers) -> R0 + Send,
    F1: FnOnce(&mut Peers) -> R1 + Send,
    F2: FnOnce(&mut Peers) -> R2 + Send,
{
    let (c01, c10) = channel_pair();
    let (mut c02, c20) = channel_pair();
    let (mut c12, mut c21) = channel_pair();
    // One clock per party, shared by its two links.
    c02.clock = c01.clock.clone();
    c12.clock = c10.clock.clone();
    c21.clock = c20.clock.clone();
    let mut p0 = Peers { party: 0, links: [None, Some(c01), Some(c02)] };
    let mut p1 = Peers { party: 1, links: [Some(c10), None, Some(c12)] };
    let mut p2 = Peers { party: 2, links: [Some(c20), Some(c21), None] };
    std::thread::scope(|s| {
        let h0 = s.spawn(move || f0(&mut p0));
        let h1 = s.spawn(move || f1(&mut p1));
        let h2 = s.spawn(move || f2(&mut p2));
        let r0 = h0.join().expect("party 0 panicked");
        let r1 = h1.join().expect("party 1 panicked");
        let r2 = h2.join().expect("party 2 panicked");
        (r0, r1, r2)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn three_party_links() {
        let (a, b, c) = run_three_party(
            |p| {
                p.to(1).send(vec![1]);
                p.to(2).send(vec![2, 2]);
                p.to(2).recv()
            },
            |p| {
                let m = p.to(0).recv();
                p.to(2).send(m);
                p.stats()
            },
            |p| {
                assert_eq!(p.to(0).recv(), vec![2, 2]);
                assert_eq!(p.to(1).recv(), vec![1]);
                p.to(0).send(vec![7]);
                p.stats_with(0)
            },
        );
        // 0 → 1 and 0 → 2 (round 1), 1 → 2 relays (round 2), 2 → 0 (round 3).
        assert_eq!(a, vec![7]);
        assert_eq!(b, CommStats { bytes_sent: 1, bytes_recv: 1, messages_sent: 1, rounds: 2 });
        assert_eq!(c, CommStats { bytes_sent: 1, bytes_recv: 2, messages_sent: 1, rounds: 3 });
    }

    #[test]
    fn ping_pong_counts() {
        let (s0, s1) = run_two_party(
            |c| {
                c.send(vec![1, 2, 3]);
                c.send(vec![4]);
                let r = c.recv();
                assert_eq!(r, vec![9; 10]);
                c.stats()
            },
            |c| {
                assert_eq!(c.recv(), vec![1, 2, 3]);
                assert_eq!(c.recv(), vec![4]);
                c.send(vec![9; 10]);
                c.stats()
            },
        );
        // A request and its reply: two rounds.
        assert_eq!(s0, CommStats { bytes_sent: 4, bytes_recv: 10, messages_sent: 2, rounds: 2 });
        assert_eq!(s1, CommStats { bytes_sent: 10, bytes_recv: 4, messages_sent: 1, rounds: 2 });
    }

    #[test]
    fn simultaneous_exchange_is_one_round() {
        let exchange = |c: &mut Channel| {
            for i in 0..3u8 {
                c.send(vec![i]);
                assert_eq!(c.recv(), vec![i]);
            }
            c.stats().rounds
        };
        assert_eq!(run_two_party(exchange, exchange), (3, 3));
    }
}
