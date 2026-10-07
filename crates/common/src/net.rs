//! In-process two- and three-party networks with byte and round counting.
//!
//! Each party runs on its own thread and talks over a pair of `mpsc` channels.
//! Nothing touches a socket. `CommStats` has the shape of the one in the
//! verifiable-dOPRF `network` crate, specialised to two parties.

use crate::block::{blocks_from_bytes, blocks_to_bytes, pack_bits, unpack_bits, Block};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::time::Duration;

/// Communication counters for one party.
///
/// A *flight* is a run of consecutive sends with no receive in between. Adding
/// both parties' flights gives the number of one-way message flights in the
/// protocol, and a round trip is two flights.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CommStats {
    pub bytes_sent: usize,
    pub bytes_recv: usize,
    pub messages_sent: usize,
    pub flights: usize,
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
            flights: self.flights - earlier.flights,
        }
    }

    /// Wall-clock estimate over a real link: `T_comp + rounds·RTT + 8·bytes/BW`,
    /// with rounds = flights/2 (the model used in the dOPRF repo).
    pub fn link_time(&self, comp: Duration, total_flights: usize, rtt: Duration, bits_per_sec: f64) -> Duration {
        let rounds = total_flights.div_ceil(2) as u32;
        comp + rtt * rounds + Duration::from_secs_f64(8.0 * self.total_bytes() as f64 / bits_per_sec)
    }
}

/// One party's end of the two-party link.
pub struct Channel {
    party: usize,
    tx: Sender<Vec<u8>>,
    rx: Receiver<Vec<u8>>,
    stats: CommStats,
    last_was_send: bool,
}

impl Channel {
    /// Party index: 0 is Floram's party 1 (garbler, OT sender) and 1 is party 2
    /// (evaluator, OT receiver).
    pub fn party(&self) -> usize {
        self.party
    }

    pub fn stats(&self) -> CommStats {
        self.stats
    }

    pub fn send(&mut self, msg: Vec<u8>) {
        if !self.last_was_send {
            self.stats.flights += 1;
            self.last_was_send = true;
        }
        self.stats.bytes_sent += msg.len();
        self.stats.messages_sent += 1;
        self.tx.send(msg).expect("peer hung up");
    }

    pub fn recv(&mut self) -> Vec<u8> {
        let msg = self.rx.recv().expect("peer hung up");
        self.stats.bytes_recv += msg.len();
        self.last_was_send = false;
        msg
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

    pub fn send_bits(&mut self, bits: &[bool]) {
        self.send(pack_bits(bits));
    }

    pub fn recv_bits(&mut self, n: usize) -> Vec<bool> {
        let m = self.recv();
        assert_eq!(m.len(), n.div_ceil(8), "unexpected message length");
        unpack_bits(&m, n)
    }
}

/// A connected pair of channels, for party 0 and party 1.
pub fn channel_pair() -> (Channel, Channel) {
    let (tx0, rx1) = channel();
    let (tx1, rx0) = channel();
    let mk = |party, tx, rx| Channel { party, tx, rx, stats: CommStats::default(), last_was_send: false };
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

    /// Counters summed over both links.
    pub fn stats(&self) -> CommStats {
        let mut s = CommStats::default();
        for l in self.links.iter().flatten() {
            let t = l.stats();
            s.bytes_sent += t.bytes_sent;
            s.bytes_recv += t.bytes_recv;
            s.messages_sent += t.messages_sent;
            s.flights += t.flights;
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
    let (c02, c20) = channel_pair();
    let (c12, c21) = channel_pair();
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
        assert_eq!(a, vec![7]);
        assert_eq!(b, CommStats { bytes_sent: 1, bytes_recv: 1, messages_sent: 1, flights: 1 });
        assert_eq!(c, CommStats { bytes_sent: 1, bytes_recv: 2, messages_sent: 1, flights: 1 });
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
        assert_eq!(s0, CommStats { bytes_sent: 4, bytes_recv: 10, messages_sent: 2, flights: 1 });
        assert_eq!(s1, CommStats { bytes_sent: 10, bytes_recv: 4, messages_sent: 1, flights: 1 });
    }
}
