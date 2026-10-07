//! Semi-honest two-party computation on XOR-shared bits and blocks, with the
//! instantiations XLH+25 (NDSS'25) App. A names and its reference code
//! (`src/mpc/secure_ops.cpp`) uses:
//!
//! * F_AND: Beaver bit triples from CrypTFlow2's generator. One 1-out-of-8
//!   KKOT of 2-bit messages yields a pair of correlated triples (`_8KKOT`,
//!   CrypTFlow2 App. A.2). As in the reference `and_wrapper`, every AND uses
//!   the first triple of its own pair, so no two ANDs share a triple
//!   component. Online: open `x ⊕ a`, `y ⊕ b` (2 bits, one round).
//! * F_OR: `x ∨ y = 1 ⊕ ((1 ⊕ x) ∧ (1 ⊕ y))`.
//! * F_MUX^{B,λ}: `z = x ⊕ c·(x ⊕ y)` on λ-bit blocks, with the product from
//!   two parallel correlated OTs (`multiplexer2` / `multiplexer`).
//!
//! Party 0 is the reference's SERVER (CrypTFlow2's ALICE, the KKOT sender), party
//! 1 the CLIENT. Constants in a sharing are held by party 1, as in the
//! reference (`party_id − 2`).

use crate::block::Block;
use crate::hash::cot_hash;
use crate::net::Channel;
use crate::ot::kkot::{KkotReceiver, KkotSender};
use crate::ot::CotPair;
use crate::coin::Abort;
use rand::{CryptoRng, Rng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;

enum Kkot {
    Sender(KkotSender),
    Receiver(KkotReceiver),
}

/// One party's Boolean 2PC engine.
pub struct BoolParty {
    party: usize,
    kkot: Kkot,
    rng: ChaCha20Rng,
    /// F_AND invocations so far.
    pub ands: usize,
}

impl BoolParty {
    /// Runs the 256 base OTs of the KKOT instance (party 0 sends KKOTs).
    pub fn setup<R: RngCore + CryptoRng>(ch: &mut Channel, rng: &mut R) -> Self {
        let party = ch.party();
        let kkot = if party == 0 {
            Kkot::Sender(KkotSender::setup(ch, rng))
        } else {
            Kkot::Receiver(KkotReceiver::setup(ch, rng))
        };
        BoolParty { party, kkot, rng: ChaCha20Rng::from_rng(rng).unwrap(), ands: 0 }
    }

    pub fn party(&self) -> usize {
        self.party
    }

    /// This party's share of the public bit `c`.
    #[inline]
    pub fn constant(&self, c: bool) -> bool {
        c && self.party == 1
    }

    /// `m` bit triples `(a, b, c)` with `c = a ∧ b`, each the first of a
    /// correlated pair from one 1-out-of-8 KKOT₂ (CrypTFlow2 `_8KKOT`).
    fn triples(&mut self, ch: &mut Channel, m: usize) -> Vec<(bool, bool, bool)> {
        // Per pair: a (shared by the pair), b[0], b[1], c[0], c[1].
        let a: Vec<bool> = (0..m).map(|_| self.rng.gen()).collect();
        let b: Vec<[bool; 2]> = (0..m).map(|_| [self.rng.gen(), self.rng.gen()]).collect();
        match &mut self.kkot {
            Kkot::Sender(s) => {
                let c: Vec<[bool; 2]> = (0..m).map(|_| [self.rng.gen(), self.rng.gen()]).collect();
                let msgs: Vec<Vec<u8>> = (0..m)
                    .map(|i| {
                        (0..8u8)
                            .map(|j| {
                                // j = a_1 ∥ b_1[0] ∥ b_1[1] (LSB → MSB).
                                let (ja, jb0, jb1) = (j & 1 == 1, j & 2 == 2, j & 4 == 4);
                                let t0 = ((a[i] ^ ja) & (b[i][0] ^ jb0)) ^ c[i][0];
                                let t1 = ((a[i] ^ ja) & (b[i][1] ^ jb1)) ^ c[i][1];
                                (t1 as u8) << 1 | t0 as u8
                            })
                            .collect()
                    })
                    .collect();
                s.send(ch, &msgs, 8, 2);
                (0..m).map(|i| (a[i], b[i][0], c[i][0])).collect()
            }
            Kkot::Receiver(r) => {
                let sel: Vec<u8> = (0..m).map(|i| (b[i][1] as u8) << 2 | (b[i][0] as u8) << 1 | a[i] as u8).collect();
                let res = r.recv(ch, &sel, 8, 2);
                (0..m).map(|i| (a[i], b[i][0], res[i] & 1 == 1)).collect()
            }
        }
    }

    /// F_AND on each pair of XOR-shared bits, all in one round after the
    /// triple generation.
    pub fn and_many(&mut self, ch: &mut Channel, pairs: &[(bool, bool)]) -> Vec<bool> {
        let t = self.triples(ch, pairs.len());
        self.ands += pairs.len();
        let ef: Vec<bool> = pairs.iter().zip(&t).flat_map(|(&(x, y), &(a, b, _))| [x ^ a, y ^ b]).collect();
        ch.send_bits(&ef);
        let theirs = ch.recv_bits(ef.len());
        pairs
            .iter()
            .zip(&t)
            .enumerate()
            .map(|(i, (&(x, y), &(_, _, c)))| {
                let (e, f) = (ef[2 * i] ^ theirs[2 * i], ef[2 * i + 1] ^ theirs[2 * i + 1]);
                (self.party == 1 && e && f) ^ (f && x) ^ (e && y) ^ c
            })
            .collect()
    }

    pub fn and1(&mut self, ch: &mut Channel, x: bool, y: bool) -> bool {
        self.and_many(ch, &[(x, y)])[0]
    }

    /// The F_AND variant with one private input per party: party 0 inputs `x`,
    /// party 1 inputs `y`, and both get shares of `x ∧ y` (each passes its own
    /// bit as `mine`).
    pub fn and_cross(&mut self, ch: &mut Channel, mine: bool) -> bool {
        if self.party == 0 {
            self.and1(ch, mine, false)
        } else {
            self.and1(ch, false, mine)
        }
    }

    /// F_OR via `1 ⊕ ((1 ⊕ x) ∧ (1 ⊕ y))`.
    pub fn or1(&mut self, ch: &mut Channel, x: bool, y: bool) -> bool {
        let one = self.constant(true);
        one ^ self.and1(ch, x ^ one, y ^ one)
    }

    /// Opens XOR-shared bits to both parties. One flight each way.
    pub fn reveal_bits(&self, ch: &mut Channel, bits: &[bool]) -> Vec<bool> {
        ch.send_bits(bits);
        let theirs = ch.recv_bits(bits.len());
        bits.iter().zip(theirs).map(|(a, b)| a ^ b).collect()
    }
}

/// F_MUX^{B,λ}: shares of `x_i` if `c = 0` and of `y_i` if `c = 1`, for
/// XOR-shared blocks and one XOR-shared choice bit `c`.
///
/// `c·d` with `d = x ⊕ y` is `c_0d_0 ⊕ c_1d_1 ⊕ c_1·d_0 ⊕ c_0·d_1`; each party
/// is COT sender for its own `d_b` (it keeps `H(K)` and sends
/// `H(K) ⊕ H(K ⊕ Δ) ⊕ d_b`) and receiver with choice `c_b` for the peer's.
pub fn mux_block<R: RngCore + CryptoRng>(
    ch: &mut Channel,
    cot: &mut CotPair,
    c: bool,
    x: &[Block],
    y: &[Block],
    rng: &mut R,
) -> Result<Vec<Block>, Abort> {
    let n = x.len();
    assert_eq!(y.len(), n);
    let (k, mm) = cot.extend(ch, &vec![c; n], n, rng)?;
    let delta = cot.delta();
    let h = cot_hash();
    let mut out = Vec::with_capacity(n);
    let mut msgs = Vec::with_capacity(n);
    for i in 0..n {
        let d = x[i] ^ y[i];
        let x0 = h.h(k[i], i as u64);
        msgs.push(x0 ^ h.h(k[i] ^ delta, i as u64) ^ d);
        out.push(x[i] ^ d.and_bit(c) ^ x0);
    }
    ch.send_blocks(&msgs);
    let theirs = ch.recv_blocks(n);
    for i in 0..n {
        out[i] ^= h.h(mm[i], i as u64) ^ theirs[i].and_bit(c);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::run_two_party;

    fn split(rng: &mut ChaCha20Rng, v: bool) -> (bool, bool) {
        let a: bool = rng.gen();
        (a, a ^ v)
    }

    #[test]
    fn and_or_cross_match_plaintext() {
        let mut rng = ChaCha20Rng::seed_from_u64(1);
        let cases: Vec<(bool, bool)> = (0..40).map(|_| (rng.gen(), rng.gen())).collect();
        let sh: Vec<((bool, bool), (bool, bool))> = cases.iter().map(|&(x, y)| (split(&mut rng, x), split(&mut rng, y))).collect();
        let (s0, s1) = (sh.clone(), sh.clone());
        let party = |me: usize, sh: Vec<((bool, bool), (bool, bool))>| {
            move |c: &mut Channel| {
                let mut p = BoolParty::setup(c, &mut ChaCha20Rng::seed_from_u64(10 + me as u64));
                let pick = |s: &(bool, bool)| if me == 0 { s.0 } else { s.1 };
                let pairs: Vec<(bool, bool)> = sh.iter().map(|(x, y)| (pick(x), pick(y))).collect();
                let and = p.and_many(c, &pairs);
                let or: Vec<bool> = pairs.iter().map(|&(x, y)| p.or1(c, x, y)).collect();
                // and_cross: party 0's private bit is x, party 1's is y.
                let cross: Vec<bool> = sh.iter().map(|(x, y)| {
                    let mine = if me == 0 { x.0 ^ x.1 } else { y.0 ^ y.1 };
                    p.and_cross(c, mine)
                }).collect();
                (and, or, cross)
            }
        };
        let (r0, r1) = run_two_party(party(0, s0), party(1, s1));
        for (i, &(x, y)) in cases.iter().enumerate() {
            assert_eq!(r0.0[i] ^ r1.0[i], x & y, "and {i}");
            assert_eq!(r0.1[i] ^ r1.1[i], x | y, "or {i}");
            assert_eq!(r0.2[i] ^ r1.2[i], x & y, "and_cross {i}");
        }
    }

    #[test]
    fn mux_block_selects() {
        let mut rng = ChaCha20Rng::seed_from_u64(2);
        for c in [false, true] {
            let x: Vec<Block> = (0..5).map(|_| Block::random(&mut rng)).collect();
            let y: Vec<Block> = (0..5).map(|_| Block::random(&mut rng)).collect();
            let x0: Vec<Block> = (0..5).map(|_| Block::random(&mut rng)).collect();
            let y0: Vec<Block> = (0..5).map(|_| Block::random(&mut rng)).collect();
            let x1: Vec<Block> = x.iter().zip(&x0).map(|(a, b)| *a ^ *b).collect();
            let y1: Vec<Block> = y.iter().zip(&y0).map(|(a, b)| *a ^ *b).collect();
            let c0: bool = rng.gen();
            let (z0, z1) = run_two_party(
                move |ch| {
                    let mut r = ChaCha20Rng::seed_from_u64(3);
                    let d = Block::random(&mut r);
                    let mut cot = CotPair::setup(ch, &mut r, d, false).unwrap();
                    mux_block(ch, &mut cot, c0, &x0, &y0, &mut r).unwrap()
                },
                move |ch| {
                    let mut r = ChaCha20Rng::seed_from_u64(4);
                    let d = Block::random(&mut r);
                    let mut cot = CotPair::setup(ch, &mut r, d, false).unwrap();
                    mux_block(ch, &mut cot, c0 ^ c, &x1, &y1, &mut r).unwrap()
                },
            );
            for i in 0..5 {
                assert_eq!(z0[i] ^ z1[i], if c { y[i] } else { x[i] });
            }
        }
    }
}
