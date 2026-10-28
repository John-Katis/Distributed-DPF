//! Semi-honest two-party computation on XOR-shared bits and blocks, with the
//! instantiations XLH+25 (NDSS'25) App. A names and its reference code
//! (`src/mpc/secure_ops.cpp`) uses:
//!
//! * F_AND: Beaver bit triples from CrypTFlow2's generator, run by SCI
//!   ([`crate::ot::sci`], its `TripleGenerator` with `_8KKOT`). One 1-out-of-8
//!   KKOT of 2-bit messages yields a pair of correlated triples (CrypTFlow2
//!   App. A.2). As in the reference `and_wrapper`, every AND uses
//!   the first triple of its own pair, so no two ANDs share a triple
//!   component. Online: open `x ⊕ a`, `y ⊕ b` (2 bits, one round).
//!   [`BoolParty::precompute`] makes the triples for a whole protocol in one
//!   KKOT batch before the inputs are known. Alternatively ([`BoolParty::with_triples`]) the triples come from a
//!   pool, e.g. [`rot_triples`]: ABY's random-OT triples on (silent) random
//!   COTs, as FssNN generates its triples with Ferret.
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
use crate::ot::sci::Sci;
use crate::ot::{CotPair, RandomCots};
use crate::coin::Abort;
use rand::{CryptoRng, RngCore};

enum Kkot {
    /// SCI's OTPack and triple generator.
    Sci(Sci),
    /// Precomputed triples, used front to back.
    Pool(std::vec::IntoIter<(bool, bool, bool)>),
}

/// One party's Boolean 2PC engine.
pub struct BoolParty {
    party: usize,
    kkot: Kkot,
    /// F_AND invocations so far.
    pub ands: usize,
}

impl BoolParty {
    /// Runs SCI's setup (party 0 sends KKOTs).
    /// `_rng` is unused: SCI draws its own randomness.
    pub fn setup<R: RngCore + CryptoRng>(ch: &mut Channel, _rng: &mut R) -> Self {
        let party = ch.party();
        let kkot = Kkot::Sci(Sci::setup(ch).expect("SCI setup"));
        BoolParty { party, kkot, ands: 0 }
    }

    /// SCI's state, for its other functionalities (e.g. SiRNN's multiplexer,
    /// [`crate::arith::mux_sci`]). Panics for a party made by
    /// [`with_triples`](Self::with_triples).
    pub fn sci(&mut self) -> &mut Sci {
        match &mut self.kkot {
            Kkot::Sci(s) => s,
            Kkot::Pool(_) => panic!("this BoolParty has no SCI state"),
        }
    }

    /// A party that takes its F_AND triples from `triples` (no setup, no
    /// triple traffic) instead of KKOT; it panics when they run out.
    pub fn with_triples<R: RngCore + CryptoRng>(party: usize, triples: Vec<(bool, bool, bool)>, _rng: &mut R) -> Self {
        BoolParty { party, kkot: Kkot::Pool(triples.into_iter()), ands: 0 }
    }

    /// Preprocessing: makes `m` triples now, in one KKOT batch, for the F_AND
    /// calls that follow; it panics when they run out.
    pub fn precompute(&mut self, ch: &mut Channel, m: usize) {
        assert!(!matches!(self.kkot, Kkot::Pool(_)), "triples already precomputed");
        let t = self.triples(ch, m);
        self.kkot = Kkot::Pool(t.into_iter());
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
        if let Kkot::Pool(p) = &mut self.kkot {
            let t: Vec<_> = p.by_ref().take(m).collect();
            assert_eq!(t.len(), m, "triple pool exhausted");
            return t;
        }
        let Kkot::Sci(s) = &mut self.kkot else { unreachable!() };
        let t = s.triples(ch, 2 * m).expect("SCI triples");
        // The first triple of each correlated pair, as the reference
        // `and_wrapper` uses it.
        (0..m).map(|i| t[2 * i]).collect()
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

    /// Opens XOR-shared bits to both parties. One round.
    pub fn reveal_bits(&self, ch: &mut Channel, bits: &[bool]) -> Vec<bool> {
        ch.send_bits(bits);
        let theirs = ch.recv_bits(bits.len());
        bits.iter().zip(theirs).map(|(a, b)| a ^ b).collect()
    }
}

/// `m` bit triples from random COTs, one per direction (ABY's R-OT triples,
/// Demmler et al. NDSS'15 §III-B). In the direction where party s sends,
/// a random OT `(x_0, x_1) = lsb H(K), lsb H(K ⊕ Δ)` and `(r, x_r)` gives
/// `x_0 ⊕ x_r = r·(x_0 ⊕ x_1)`, i.e. XOR shares of `a_s·b_{1−s}` with
/// `a_s = x_0 ⊕ x_1` and `b_{1−s} = r`. With both directions,
/// `c_b = a_b·b_b ⊕ (cross shares)` makes `c_0 ⊕ c_1 = (a_0 ⊕ a_1)(b_0 ⊕ b_1)`.
/// On Ferret COTs this sends nothing beyond Ferret's own refills.
pub fn rot_triples<R: RngCore + CryptoRng>(ch: &mut Channel, cot: &mut CotPair, m: usize, rng: &mut R) -> Vec<(bool, bool, bool)> {
    let me = ch.party();
    let delta = cot.delta();
    let h = |x: Block, i: usize| cot_hash().h(x, (1 << 62) | i as u64).lsb();
    let (mut a, mut b, mut c) = (vec![false; m], vec![false; m], vec![false; m]);
    for s in 0..2 {
        match cot.random_cots(ch, s, m, rng).expect("semi-honest COT") {
            RandomCots::Sender(k) => {
                debug_assert_eq!(me, s);
                for i in 0..m {
                    let (x0, x1) = (h(k[i], i), h(k[i] ^ delta, i));
                    a[i] = x0 ^ x1;
                    c[i] ^= x0;
                }
            }
            RandomCots::Receiver(r, macs) => {
                for i in 0..m {
                    b[i] = r[i];
                    c[i] ^= h(macs[i], i);
                }
            }
        }
    }
    (0..m).map(|i| (a[i], b[i], c[i] ^ (a[i] & b[i]))).collect()
}

/// `m` bit-times-block triples `(a, B, C = a·B)`, XOR-shared, from random COTs
/// one per direction: [`rot_triples`] with the hashes kept at 128 bits. In the
/// direction where party s sends, `H(K) ⊕ H(M) = r·(H(K) ⊕ H(K ⊕ Δ))` shares
/// `a_{1−s}·B_s` with `a_{1−s} = r` and `B_s = H(K) ⊕ H(K ⊕ Δ)`. On Ferret COTs
/// this sends nothing beyond Ferret's own refills.
pub fn rot_string_triples<R: RngCore + CryptoRng>(ch: &mut Channel, cot: &mut CotPair, m: usize, rng: &mut R) -> Vec<(bool, Block, Block)> {
    let me = ch.party();
    let delta = cot.delta();
    let h = |x: Block, i: usize| cot_hash().h(x, (3 << 61) | i as u64);
    let (mut a, mut b, mut c) = (vec![false; m], vec![Block::ZERO; m], vec![Block::ZERO; m]);
    for s in 0..2 {
        match cot.random_cots(ch, s, m, rng).expect("semi-honest COT") {
            RandomCots::Sender(k) => {
                debug_assert_eq!(me, s);
                for i in 0..m {
                    let (x0, x1) = (h(k[i], i), h(k[i] ^ delta, i));
                    b[i] = x0 ^ x1;
                    c[i] ^= x0;
                }
            }
            RandomCots::Receiver(r, macs) => {
                for i in 0..m {
                    a[i] = r[i];
                    c[i] ^= h(macs[i], i);
                }
            }
        }
    }
    (0..m).map(|i| (a[i], b[i], c[i] ^ b[i].and_bit(a[i]))).collect()
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
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha20Rng;

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

    #[test]
    fn precomputed_triples_serve_and() {
        let party = |seed: u64| {
            move |ch: &mut Channel| {
                let mut r = ChaCha20Rng::seed_from_u64(seed);
                let mut p = BoolParty::setup(ch, &mut r);
                p.precompute(ch, 50);
                let before = ch.stats();
                let x: Vec<(bool, bool)> = (0..50).map(|_| (r.gen(), r.gen())).collect();
                let z = p.and_many(ch, &x);
                (x, z, ch.stats().since(&before))
            }
        };
        let ((x0, z0, s0), (x1, z1, _)) = run_two_party(party(1), party(2));
        for i in 0..50 {
            assert_eq!(z0[i] ^ z1[i], (x0[i].0 ^ x1[i].0) & (x0[i].1 ^ x1[i].1));
        }
        // Online: 2 bits per AND, one round.
        assert_eq!((s0.bytes_sent, s0.rounds), (100usize.div_ceil(8), 1));
    }

    #[test]
    fn rot_string_triples_are_triples() {
        let party = |seed: u64| {
            move |ch: &mut Channel| {
                let mut r = ChaCha20Rng::seed_from_u64(seed);
                let d = Block::random(&mut r);
                let mut cot = CotPair::setup(ch, &mut r, d, false).unwrap();
                rot_string_triples(ch, &mut cot, 200, &mut r)
            }
        };
        let (t0, t1) = run_two_party(party(5), party(6));
        for (x, y) in t0.iter().zip(&t1) {
            assert_eq!(x.2 ^ y.2, (x.1 ^ y.1).and_bit(x.0 ^ y.0));
        }
        assert!(t0.iter().any(|t| t.0) && t1.iter().any(|t| t.0));
    }

    #[test]
    fn rot_triples_are_triples() {
        for ferret in [false, true] {
            let party = |seed: u64| {
                move |ch: &mut Channel| {
                    let mut r = ChaCha20Rng::seed_from_u64(seed);
                    let d = Block::random(&mut r);
                    let mut cot = CotPair::setup(ch, &mut r, d, false).unwrap();
                    if ferret {
                        cot.enable_ferret(ch, crate::ot::FerretConfig::TOY, &mut r).unwrap();
                    }
                    let before = ch.stats().bytes_sent;
                    let t = rot_triples(ch, &mut cot, 300, &mut r);
                    (t, ch.stats().bytes_sent - before)
                }
            };
            let ((t0, sent), (t1, _)) = run_two_party(party(1), party(2));
            for (x, y) in t0.iter().zip(&t1) {
                assert_eq!(x.2 ^ y.2, (x.0 ^ y.0) & (x.1 ^ y.1), "ferret={ferret}");
            }
            // Both a and b are random, not constant.
            assert!(t0.iter().any(|t| t.0) && t0.iter().any(|t| t.1));
            if ferret {
                assert_eq!(sent, 0, "silent triples send nothing from a full buffer");
            }
        }
    }
}
