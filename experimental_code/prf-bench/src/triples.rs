//! The Boyar–Peralta S-box (`exp_bp_sbox::boyar_peralta`, 34 ANDs at AND-depth
//! 4) in 2PC with one Beaver triple per AND, the textbook baseline.
//!
//! A triple `(a, b, c = ab)` comes from two random COTs, one per direction,
//! without communication: a random COT `(q, q ⊕ Γ)` / `(c, q ⊕ cΓ)` hashed to
//! bits is a random OT, i.e. shares of `x·c` for the sender's `x = H(q) ⊕
//! H(q ⊕ Γ)` and the receiver's choice c. With party 0 the sender of one and
//! party 1 of the other, the two cross terms `a₀b₁` and `a₁b₀` are shared.
//! Online, an AND opens `x ⊕ a` and `y ⊕ b`, 2 bits per party, so an S-box
//! costs 136 bits and 68 COTs, and a call 40 rounds.

use dpf_common::aes_tower::TowerBackend;
use dpf_common::block::Block;
use dpf_common::hash::FixedKeyHash;
use dpf_common::net::Channel;
use dpf_common::ot::RandomCots;
use exp_bp_sbox::{Circuit, Op};
use std::sync::OnceLock;

pub const ANDS_PER_SBOX: usize = 34;
pub const COTS_PER_SBOX: usize = 2 * ANDS_PER_SBOX;
pub const ONLINE_BITS_PER_SBOX: usize = 4 * ANDS_PER_SBOX;

fn hash() -> &'static FixedKeyHash {
    static H: OnceLock<FixedKeyHash> = OnceLock::new();
    H.get_or_init(|| FixedKeyHash::new(b"prf-bench/triple"))
}

pub struct TripleCircuit {
    party: usize,
    circuit: Circuit,
    /// AND depth of every wire.
    depth: Vec<usize>,
    /// This party's share of each triple `(a, b, c)`, consumed front to back.
    triples: Vec<(bool, bool, bool)>,
    next: usize,
}

impl TripleCircuit {
    /// `sent`: the random COTs in which this party is the sender (keys,
    /// with its key `gamma`), `recv` those in which it is the receiver, as
    /// many of each as triples are wanted.
    pub fn new(party: usize, circuit: Circuit, sent: RandomCots, recv: RandomCots, gamma: Block) -> Self {
        let (RandomCots::Sender(k), RandomCots::Receiver(c, m)) = (sent, recv) else {
            panic!("one sender and one receiver batch");
        };
        assert_eq!(k.len(), c.len());
        let h = hash();
        // Tweaks: the sender's COT j and the receiver's COT j of the other
        // direction get the same index within their direction.
        let dir = |sender: usize| (sender as u64) << 40;
        let triples = (0..k.len())
            .map(|j| {
                let tq = dir(party) + j as u64;
                let tr = dir(1 - party) + j as u64;
                let (m0, m1) = (h.h(k[j], tq).lsb(), h.h(k[j] ^ gamma, tq).lsb());
                let a = m0 ^ m1; // sender's random bit
                let b = c[j]; // receiver's random choice
                let mc = h.h(m[j], tr).lsb();
                // a·b_peer ⊕ a_peer·b shared as m0 (as sender) ⊕ mc (as receiver).
                (a, b, (a & b) ^ m0 ^ mc)
            })
            .collect();
        let mut depth = vec![0usize; circuit.wires];
        for g in &circuit.gates {
            depth[g.out] = depth[g.a].max(depth[g.b]) + (g.op == Op::And) as usize;
        }
        TripleCircuit { party, circuit, depth, triples, next: 0 }
    }
}

impl TowerBackend for TripleCircuit {
    type Bit = bool;

    fn constant(&self, c: bool) -> bool {
        c && self.party == 0
    }

    fn sbox(&mut self, ch: &mut Channel, bytes: &[[bool; 8]]) -> Vec<[bool; 8]> {
        let c = &self.circuit;
        let n = bytes.len();
        let mut v = vec![vec![false; c.wires]; n];
        for (s, b) in v.iter_mut().zip(bytes) {
            for i in 0..8 {
                s[c.inputs[i]] = b[i];
            }
        }
        let max = *self.depth.iter().max().unwrap();
        let p0 = self.party == 0;
        let mut done = vec![false; c.gates.len()];
        for layer in 0..=max {
            // Linear gates whose output is at this depth.
            for (gi, g) in c.gates.iter().enumerate() {
                if g.op != Op::And && self.depth[g.out] == layer && !done[gi] {
                    for s in v.iter_mut() {
                        s[g.out] = s[g.a] ^ s[g.b] ^ (g.op == Op::Xnor && p0);
                    }
                    done[gi] = true;
                }
            }
            // ANDs at depth layer + 1, all S-boxes in one round.
            let ands: Vec<usize> = (0..c.gates.len()).filter(|&gi| c.gates[gi].op == Op::And && self.depth[c.gates[gi].out] == layer + 1).collect();
            if ands.is_empty() {
                continue;
            }
            let k = ands.len();
            let tr = &self.triples[self.next..self.next + n * k];
            self.next += n * k;
            let mine: Vec<bool> = (0..n)
                .flat_map(|s| ands.iter().enumerate().flat_map({
                    let v = &v;
                    move |(q, &gi)| {
                        let g = &c.gates[gi];
                        let (a, b, _) = tr[s * k + q];
                        [v[s][g.a] ^ a, v[s][g.b] ^ b]
                    }
                }))
                .collect();
            ch.send_bits(&mine);
            let theirs = ch.recv_bits(mine.len());
            for s in 0..n {
                for (q, &gi) in ands.iter().enumerate() {
                    let g = &c.gates[gi];
                    let t = 2 * (s * k + q);
                    let (d, e) = (mine[t] ^ theirs[t], mine[t + 1] ^ theirs[t + 1]);
                    let (a, b, cc) = tr[s * k + q];
                    v[s][g.out] = cc ^ (d & b) ^ (e & a) ^ (d & e & p0);
                    done[gi] = true;
                }
            }
        }
        assert!(done.iter().all(|&d| d));
        v.iter()
            .map(|s| std::array::from_fn(|i| s[c.outputs[i]] ^ (c.out_const >> i & 1 == 1 && p0)))
            .collect()
    }
}
