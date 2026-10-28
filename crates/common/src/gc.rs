//! Semi-honest Yao garbling with free-XOR, point-and-permute and half-gates
//! (Zahur–Rosulek–Evans 2015). This is the Obliv-C protocol Floram runs in.
//!
//! AND gates are garbled and evaluated by emp-tool's half-gates
//! (`halfgates_garble` / `halfgates_eval`, the gate code of emp-sh2pc's
//! `HalfGateGen` / `HalfGateEva`) through [`dpf_ot_sys::HalfGates`], with
//! emp's MITCCRH hash keyed by a uniform public S that the garbler samples
//! and sends at setup. Inputs follow Obliv-C (one OT per shared bit, emp-ot's
//! IKNP on Naor–Pinkas), and outputs are revealed by their permute bits.
//!
//! A circuit is written once against [`GcParty`], and the garbler (party 0 =
//! Floram's party 1) and the evaluator (party 1) each run the same code. A wire
//! is a single [`Block`]: the 0-label for the garbler, the active label for the
//! evaluator.

use crate::block::Block;
use dpf_ot_sys::HalfGates;
use crate::net::Channel;
use crate::ot::{IknpReceiver, IknpSender};
use rand::{CryptoRng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;

pub type Wire = Block;

pub trait GcParty {
    /// Inputs a value that is XOR-shared between the parties; each party passes
    /// its own share bits. Follows Obliv-C's `ocFromShared_impl`: one OT per bit.
    fn input_shared(&mut self, ch: &mut Channel, share: &[bool]) -> Vec<Wire>;

    /// AND of each pair. All tables travel garbler → evaluator in one message.
    fn and_many(&mut self, ch: &mut Channel, pairs: &[(Wire, Wire)]) -> Vec<Wire>;

    fn not(&self, a: Wire) -> Wire;

    /// Reveals the wires to both parties: to the evaluator first, then to the
    /// garbler, as `ocRevealShared`/`revealObliv*(…, 2)` then `(…, 1)` does.
    fn reveal_both(&mut self, ch: &mut Channel, w: &[Wire]) -> Vec<bool>;

    /// Number of AND gates garbled or evaluated so far.
    fn and_count(&self) -> usize;

    #[inline]
    fn xor(&self, a: Wire, b: Wire) -> Wire {
        a ^ b
    }

    /// `if sel { a } else { b }` for each pair, as `b ⊕ sel·(a ⊕ b)`, with one AND
    /// gate per bit.
    fn mux(&mut self, ch: &mut Channel, sel: Wire, a: &[Wire], b: &[Wire]) -> Vec<Wire> {
        let pairs: Vec<_> = a.iter().zip(b).map(|(x, y)| (sel, *x ^ *y)).collect();
        let prod = self.and_many(ch, &pairs);
        prod.iter().zip(b).map(|(p, y)| *p ^ *y).collect()
    }
}

pub struct Garbler {
    hg: HalfGates,
    delta: Block,
    ands: usize,
    ot: IknpSender,
    rng: ChaCha20Rng,
}

impl Garbler {
    pub fn setup<R: RngCore + CryptoRng>(ch: &mut Channel, rng: &mut R) -> Self {
        let mut delta = Block::random(rng);
        delta.0 |= 1; // point-and-permute: lsb(R) = 1
        let s = Block::random(rng);
        ch.send_blocks(&[s]);
        let ot = IknpSender::setup(ch, rng);
        Garbler { hg: HalfGates::new(s.0), delta, ands: 0, ot, rng: ChaCha20Rng::from_rng(rng).unwrap() }
    }
}

impl GcParty for Garbler {
    fn input_shared(&mut self, ch: &mut Channel, share: &[bool]) -> Vec<Wire> {
        let pairs: Vec<(Block, Block)> = share
            .iter()
            .map(|_| {
                let k0 = Block::random(&mut self.rng);
                (k0, k0 ^ self.delta)
            })
            .collect();
        self.ot.send(ch, &pairs);
        // The evaluator now holds k_b. Taking k_a as the 0-label makes k_b encode a ⊕ b.
        pairs.iter().zip(share).map(|((k0, k1), &a)| if a { *k1 } else { *k0 }).collect()
    }

    fn and_many(&mut self, ch: &mut Channel, pairs: &[(Wire, Wire)]) -> Vec<Wire> {
        let a0: Vec<u128> = pairs.iter().map(|p| p.0 .0).collect();
        let b0: Vec<u128> = pairs.iter().map(|p| p.1 .0).collect();
        let (out, tables) = self.hg.garble(self.delta.0, &a0, &b0);
        self.ands += pairs.len();
        ch.send_blocks(&tables.into_iter().map(Block).collect::<Vec<_>>());
        out.into_iter().map(Block).collect()
    }

    fn not(&self, a: Wire) -> Wire {
        a ^ self.delta
    }

    fn reveal_both(&mut self, ch: &mut Channel, w: &[Wire]) -> Vec<bool> {
        let flips: Vec<bool> = w.iter().map(|x| x.lsb()).collect();
        ch.send_bits(&flips);
        ch.recv_bits(w.len())
    }

    fn and_count(&self) -> usize {
        self.ands
    }
}

pub struct Evaluator {
    hg: HalfGates,
    ands: usize,
    ot: IknpReceiver,
}

impl Evaluator {
    pub fn setup<R: RngCore + CryptoRng>(ch: &mut Channel, rng: &mut R) -> Self {
        let s = ch.recv_blocks(1)[0];
        Evaluator { hg: HalfGates::new(s.0), ands: 0, ot: IknpReceiver::setup(ch, rng) }
    }
}

impl GcParty for Evaluator {
    fn input_shared(&mut self, ch: &mut Channel, share: &[bool]) -> Vec<Wire> {
        self.ot.recv(ch, share)
    }

    fn and_many(&mut self, ch: &mut Channel, pairs: &[(Wire, Wire)]) -> Vec<Wire> {
        let tables: Vec<u128> = ch.recv_blocks(2 * pairs.len()).into_iter().map(|b| b.0).collect();
        let a: Vec<u128> = pairs.iter().map(|p| p.0 .0).collect();
        let b: Vec<u128> = pairs.iter().map(|p| p.1 .0).collect();
        self.ands += pairs.len();
        self.hg.eval(&a, &b, &tables).into_iter().map(Block).collect()
    }

    fn not(&self, a: Wire) -> Wire {
        a
    }

    fn reveal_both(&mut self, ch: &mut Channel, w: &[Wire]) -> Vec<bool> {
        let flips = ch.recv_bits(w.len());
        let vals: Vec<bool> = w.iter().zip(&flips).map(|(x, f)| x.lsb() ^ f).collect();
        ch.send_bits(&vals);
        vals
    }

    fn and_count(&self) -> usize {
        self.ands
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::run_two_party;
    use rand::Rng;

    /// Runs a few shared-input gates and returns the revealed bits.
    fn circuit<P: GcParty>(p: &mut P, ch: &mut Channel, a: &[bool], b: &[bool], s: &[bool]) -> Vec<bool> {
        let wa = p.input_shared(ch, a);
        let wb = p.input_shared(ch, b);
        let ws = p.input_shared(ch, s);
        let pairs: Vec<_> = wa.iter().zip(&wb).map(|(x, y)| (*x, *y)).collect();
        let and = p.and_many(ch, &pairs);
        let xor: Vec<_> = wa.iter().zip(&wb).map(|(x, y)| p.xor(*x, *y)).collect();
        let not: Vec<_> = wa.iter().map(|x| p.not(*x)).collect();
        let mux = p.mux(ch, ws[0], &wa, &wb);
        let all: Vec<Wire> = [and, xor, not, mux].concat();
        p.reveal_both(ch, &all)
    }

    #[test]
    fn gates_match_plaintext() {
        let mut rng = ChaCha20Rng::seed_from_u64(11);
        for _ in 0..8 {
            let n = 64;
            let sh = |rng: &mut ChaCha20Rng| -> Vec<bool> { (0..n).map(|_| rng.gen()).collect() };
            let (a0, a1, b0, b1) = (sh(&mut rng), sh(&mut rng), sh(&mut rng), sh(&mut rng));
            let (s0, s1): (bool, bool) = (rng.gen(), rng.gen());
            let (x, y) = (a0.clone(), b0.clone());
            let (u, v) = (a1.clone(), b1.clone());
            let (r0, r1) = run_two_party(
                move |c| {
                    let mut r = ChaCha20Rng::seed_from_u64(1);
                    let mut g = Garbler::setup(c, &mut r);
                    circuit(&mut g, c, &x, &y, &[s0])
                },
                move |c| {
                    let mut r = ChaCha20Rng::seed_from_u64(2);
                    let mut e = Evaluator::setup(c, &mut r);
                    circuit(&mut e, c, &u, &v, &[s1])
                },
            );
            assert_eq!(r0, r1);
            let a: Vec<bool> = a0.iter().zip(&a1).map(|(p, q)| p ^ q).collect();
            let b: Vec<bool> = b0.iter().zip(&b1).map(|(p, q)| p ^ q).collect();
            let s = s0 ^ s1;
            let mut expect = Vec::new();
            expect.extend(a.iter().zip(&b).map(|(p, q)| p & q));
            expect.extend(a.iter().zip(&b).map(|(p, q)| p ^ q));
            expect.extend(a.iter().map(|p| !p));
            expect.extend(a.iter().zip(&b).map(|(p, q)| if s { *p } else { *q }));
            assert_eq!(r0, expect);
        }
    }
}
