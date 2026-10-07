//! Du–Atallah products for Duoram's preprocessing (Duoram §2.2.1, App. A),
//! with the correlations dealt by the helper P2 (3P-Duoram) or generated
//! from OT between P0 and P1 (2P-Duoram).
//!
//! Two products are needed:
//!
//! * **compute_CW** (`dpfgen.h`): per level, the Floram correction word
//!   `CW = c ? L : R` for XOR-shared `c, L, R`, i.e. `R ⊕ c·(L ⊕ R)`. With a
//!   bit-times-block AND triple (Def. 4) `(rand_b, bit_b, γ_b)`,
//!   `γ_0 ⊕ γ_1 = bit_1·rand_0 ⊕ bit_0·rand_1`, each party sends
//!   `(L_b ⊕ R_b ⊕ rand_b, c_b ⊕ bit_b)`, then its share
//!   `R_b ⊕ γ_b ⊕ c_b·(D_b ⊕ D̂_{1−b}) ⊕ ĉ_{1−b}·rand_b`, and both shares are
//!   opened. Two flights per level.
//! * **cross**: shares of `x·y mod 2^64` for P0's `x` and P1's `y` (the
//!   reference's `xor_to_additive` and `du_attalah_Pb`). With a triple
//!   `(X, Z_0 = X·Y − T)`, `(Y, Z_1 = T)`: P0 sends `x + X`, P1 sends `y + Y`,
//!   and the shares are `x·(y + Y) + Z_0` and `−Y·(x + X) + Z_1`.
//!
//! The reference code is marked "for performance testing only": its P2 sends
//! `γ_0 = bit_1·rand_0` without the mask T of Def. 4 (so P0 learns `bit_1`,
//! hence `c_1`) and reuses one triple for all levels and bits. Here every
//! product uses a fresh triple with T, as the paper defines them.
//!
//! In 2P mode the correlations come from IKNP COTs: the AND triples from
//! derandomised OTs of `rand_b` on the peer's choice `bit_{1−b}` (both
//! directions in one flight), and `cross` is a Gilboa product, one COT per
//! bit of `y`.

use dpf_common::block::Block;
use dpf_common::hash::FixedKeyHash;
use dpf_common::net::{Channel, Peers};
use dpf_common::ot::CotPair;
use rand::{CryptoRng, Rng, RngCore};
use std::sync::OnceLock;

fn ot_hash() -> &'static FixedKeyHash {
    static H: OnceLock<FixedKeyHash> = OnceLock::new();
    H.get_or_init(|| FixedKeyHash::new(b"duoram/ot-hash!!"))
}

/// One party's AND triple for compute_CW.
#[derive(Clone, Copy, Debug)]
pub struct CwCorr {
    pub rand: Block,
    pub bit: bool,
    pub gamma: Block,
}

/// Where this party's correlations come from.
pub enum Helper<'a> {
    /// Dealt by P2 in advance.
    Dealt { cw: Vec<CwCorr>, cross: Vec<(u64, u64)> },
    /// Generated from COTs with the peer.
    Ot(&'a mut CotPair),
}

/// What P2 deals to one party.
fn encode(cw: &[CwCorr], cross: &[(u64, u64)]) -> Vec<u8> {
    let mut m = Vec::with_capacity(cw.len() * 33 + cross.len() * 16);
    for c in cw {
        m.extend(c.rand.to_bytes());
        m.extend(c.gamma.to_bytes());
        m.push(c.bit as u8);
    }
    for (a, z) in cross {
        m.extend(a.to_le_bytes());
        m.extend(z.to_le_bytes());
    }
    m
}

fn decode(m: &[u8], levels: usize, crosses: usize) -> Helper<'static> {
    assert_eq!(m.len(), levels * 33 + crosses * 16, "unexpected message length");
    let (a, b) = m.split_at(levels * 33);
    let cw = a
        .chunks(33)
        .map(|c| CwCorr { rand: Block::from_bytes(&c[..16]), gamma: Block::from_bytes(&c[16..32]), bit: c[32] == 1 })
        .collect();
    let u = |c: &[u8]| u64::from_le_bytes(c.try_into().unwrap());
    let cross = b.chunks(16).map(|c| (u(&c[..8]), u(&c[8..]))).collect();
    Helper::Dealt { cw, cross }
}

/// P2's whole role in the DPF preprocessing: one message to each party with
/// `levels` AND triples and `crosses` multiplication triples.
pub fn deal<R: RngCore + CryptoRng>(p2: &mut Peers, levels: usize, crosses: usize, rng: &mut R) {
    let (mut cw0, mut cw1) = (Vec::with_capacity(levels), Vec::with_capacity(levels));
    for _ in 0..levels {
        let (r0, r1, t) = (Block::random(rng), Block::random(rng), Block::random(rng));
        let (b0, b1): (bool, bool) = (rng.gen(), rng.gen());
        cw0.push(CwCorr { rand: r0, bit: b0, gamma: r0.and_bit(b1) ^ t });
        cw1.push(CwCorr { rand: r1, bit: b1, gamma: r1.and_bit(b0) ^ t });
    }
    let (mut x0, mut x1) = (Vec::with_capacity(crosses), Vec::with_capacity(crosses));
    for _ in 0..crosses {
        let (x, y, t): (u64, u64, u64) = (rng.gen(), rng.gen(), rng.gen());
        x0.push((x, x.wrapping_mul(y).wrapping_sub(t)));
        x1.push((y, t));
    }
    p2.to(0).send(encode(&cw0, &x0));
    p2.to(1).send(encode(&cw1, &x1));
}

/// Receives what [`deal`] sent this party.
pub fn receive_dealt(from_p2: &mut Channel, levels: usize, crosses: usize) -> Helper<'static> {
    decode(&from_p2.recv(), levels, crosses)
}

impl Helper<'_> {
    /// AND triples for `levels` correction words. 2P: one COT per triple in
    /// each direction, plus one flight of derandomisation words.
    pub fn cw_corr<R: RngCore + CryptoRng>(&mut self, ch: &mut Channel, levels: usize, rng: &mut R) -> Vec<CwCorr> {
        match self {
            Helper::Dealt { cw, .. } => {
                assert_eq!(cw.len(), levels);
                std::mem::take(cw)
            }
            Helper::Ot(cot) => {
                let rand: Vec<Block> = (0..levels).map(|_| Block::random(rng)).collect();
                let bit: Vec<bool> = (0..levels).map(|_| rng.gen()).collect();
                let (k, m) = cot.extend(ch, &bit, levels, rng).expect("semi-honest COT");
                let (d, h) = (cot.delta(), ot_hash());
                let mine: Vec<Block> = (0..levels).map(|i| h.h(k[i], i as u64) ^ h.h(k[i] ^ d, i as u64) ^ rand[i]).collect();
                ch.send_blocks(&mine);
                let theirs = ch.recv_blocks(levels);
                (0..levels)
                    .map(|i| {
                        // Sender share H(K) plus receiver share H(K' ⊕ bit·Δ') ⊕ bit·c'.
                        let gamma = h.h(k[i], i as u64) ^ h.h(m[i], i as u64) ^ theirs[i].and_bit(bit[i]);
                        CwCorr { rand: rand[i], bit: bit[i], gamma }
                    })
                    .collect()
            }
        }
    }

    /// Shares of `x_k · y_k mod 2^64`, where party 0 passes the `x_k` and party
    /// 1 the `y_k` as `mine`. `ybits[k]` bounds the width of `y_k` (the cost of
    /// the 2P Gilboa product).
    pub fn cross<R: RngCore + CryptoRng>(&mut self, ch: &mut Channel, mine: &[u64], ybits: &[usize], rng: &mut R) -> Vec<u64> {
        let first = ch.party() == 0;
        match self {
            Helper::Dealt { cross, .. } => {
                assert!(cross.len() >= mine.len(), "not enough dealt triples");
                let tr: Vec<(u64, u64)> = cross.drain(..mine.len()).collect();
                let masked: Vec<u8> = mine.iter().zip(&tr).flat_map(|(v, (a, _))| v.wrapping_add(*a).to_le_bytes()).collect();
                ch.send(masked);
                let got = ch.recv();
                assert_eq!(got.len(), 8 * mine.len(), "unexpected message length");
                (0..mine.len())
                    .map(|k| {
                        let other = u64::from_le_bytes(got[8 * k..8 * k + 8].try_into().unwrap());
                        let (a, z) = tr[k];
                        if first {
                            mine[k].wrapping_mul(other).wrapping_add(z)
                        } else {
                            a.wrapping_neg().wrapping_mul(other).wrapping_add(z)
                        }
                    })
                    .collect()
            }
            Helper::Ot(cot) => {
                assert_eq!(ybits.len(), mine.len());
                let total: usize = ybits.iter().sum();
                let h = ot_hash();
                let h64 = |x: Block, j: usize| h.h(x, (1 << 40) | j as u64).0 as u64;
                if first {
                    let (k, _) = cot.extend(ch, &[], total, rng).expect("semi-honest COT");
                    let d = cot.delta();
                    let mut out = vec![0u64; mine.len()];
                    let mut msg = Vec::with_capacity(8 * total);
                    let mut j = 0;
                    for (it, &w) in ybits.iter().enumerate() {
                        for l in 0..w {
                            let (h0, h1) = (h64(k[j], j), h64(k[j] ^ d, j));
                            msg.extend(h1.wrapping_sub(h0).wrapping_sub(mine[it] << l).to_le_bytes());
                            out[it] = out[it].wrapping_sub(h0);
                            j += 1;
                        }
                    }
                    ch.send(msg);
                    out
                } else {
                    let choices: Vec<bool> = mine.iter().zip(ybits).flat_map(|(&y, &w)| (0..w).map(move |l| (y >> l) & 1 == 1)).collect();
                    let (_, m) = cot.extend(ch, &choices, 0, rng).expect("semi-honest COT");
                    let got = ch.recv();
                    assert_eq!(got.len(), 8 * total, "unexpected message length");
                    let mut out = vec![0u64; mine.len()];
                    let mut j = 0;
                    for (it, &w) in ybits.iter().enumerate() {
                        for _ in 0..w {
                            let dj = u64::from_le_bytes(got[8 * j..8 * j + 8].try_into().unwrap());
                            let v = h64(m[j], j).wrapping_sub(if choices[j] { dj } else { 0 });
                            out[it] = out[it].wrapping_add(v);
                            j += 1;
                        }
                    }
                    out
                }
            }
        }
    }
}

/// compute_CW: opens `CW = c ? L : R` from XOR shares, with this level's AND
/// triple, and in the same last flight the XOR-shared bits `extra` (the
/// reference's `cwbit`). Two flights.
pub fn compute_cw(ch: &mut Channel, corr: &CwCorr, l: Block, r: Block, c: bool, extra: [bool; 2]) -> (Block, [bool; 2]) {
    let d = l ^ r;
    let mut msg = (d ^ corr.rand).to_bytes().to_vec();
    msg.push((c ^ corr.bit) as u8);
    ch.send(msg);
    let got = ch.recv();
    assert_eq!(got.len(), 17, "unexpected message length");
    let (d_hat, c_hat) = (Block::from_bytes(&got[..16]), got[16] == 1);
    let share = r ^ corr.gamma ^ (d ^ d_hat).and_bit(c) ^ corr.rand.and_bit(c_hat);
    let mut msg = share.to_bytes().to_vec();
    msg.push(extra[0] as u8 | (extra[1] as u8) << 1);
    ch.send(msg);
    let got = ch.recv();
    assert_eq!(got.len(), 17, "unexpected message length");
    (share ^ Block::from_bytes(&got[..16]), [extra[0] ^ (got[16] & 1 == 1), extra[1] ^ (got[16] & 2 == 2)])
}

#[cfg(test)]
mod tests {
    use super::*;
    use dpf_common::net::{run_three_party, run_two_party};
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    /// Runs compute_CW and cross with either helper and checks the results.
    fn check(cws: Vec<Block>, crosses: Vec<u64>) {
        let mut rng = ChaCha20Rng::seed_from_u64(1);
        let (l, r): (Vec<Block>, Vec<Block>) = (0..3).map(|_| (Block::random(&mut rng), Block::random(&mut rng))).unzip();
        let c: Vec<bool> = (0..3).map(|i| i % 2 == 0).collect();
        for (i, cw) in cws.iter().enumerate() {
            assert_eq!(*cw, if c[i] { l[i] } else { r[i] }, "compute_CW {i}");
        }
        let (x, y) = (0xdead_beef_u64.wrapping_mul(77), 5u64);
        assert_eq!(crosses[0], x.wrapping_mul(y), "cross word");
        assert_eq!(crosses[1], 1, "cross bit");
        assert_eq!(crosses[2], 0, "cross bit");
    }

    fn party(ch: &mut Channel, helper: &mut Helper, me: usize) -> (Vec<Block>, Vec<u64>) {
        let mut rng = ChaCha20Rng::seed_from_u64(1);
        let (l, r): (Vec<Block>, Vec<Block>) = (0..3).map(|_| (Block::random(&mut rng), Block::random(&mut rng))).unzip();
        let mut prng = ChaCha20Rng::seed_from_u64(50 + me as u64);
        // Party 0's shares are random; party 1 derives the complement from the same stream.
        let mut srng = ChaCha20Rng::seed_from_u64(9);
        let sh: Vec<(Block, Block, bool)> = (0..3).map(|_| (Block::random(&mut srng), Block::random(&mut srng), srng.gen())).collect();
        let corr = helper.cw_corr(ch, 3, &mut prng);
        let cws = (0..3)
            .map(|i| {
                let (ls, rs, cs) = sh[i];
                let (lm, rm, cm) = if me == 0 { (ls, rs, cs) } else { (l[i] ^ ls, r[i] ^ rs, (i % 2 == 0) ^ cs) };
                compute_cw(ch, &corr[i], lm, rm, cm, [false; 2]).0
            })
            .collect();
        let mine = if me == 0 { vec![0xdead_beef_u64.wrapping_mul(77), 1, 1] } else { vec![5, 1, 0] };
        let z = helper.cross(ch, &mine, &[64, 1, 1], &mut prng);
        ch.send(z.iter().flat_map(|v| v.to_le_bytes()).collect());
        let got = ch.recv();
        let sum = (0..3).map(|k| z[k].wrapping_add(u64::from_le_bytes(got[8 * k..8 * k + 8].try_into().unwrap()))).collect();
        (cws, sum)
    }

    #[test]
    fn three_party_products() {
        let (a, _, _) = run_three_party(
            |p| {
                let mut h = receive_dealt(p.to(2), 3, 3);
                party(p.to(1), &mut h, 0)
            },
            |p| {
                let mut h = receive_dealt(p.to(2), 3, 3);
                party(p.to(0), &mut h, 1)
            },
            |p| deal(p, 3, 3, &mut ChaCha20Rng::seed_from_u64(7)),
        );
        check(a.0, a.1);
    }

    #[test]
    fn two_party_products() {
        let (a, _) = run_two_party(
            |ch| {
                let mut r = ChaCha20Rng::seed_from_u64(3);
                let d = Block::random(&mut r);
                let mut cot = CotPair::setup(ch, &mut r, d, false).unwrap();
                party(ch, &mut Helper::Ot(&mut cot), 0)
            },
            |ch| {
                let mut r = ChaCha20Rng::seed_from_u64(4);
                let d = Block::random(&mut r);
                let mut cot = CotPair::setup(ch, &mut r, d, false).unwrap();
                party(ch, &mut Helper::Ot(&mut cot), 1)
            },
        );
        check(a.0, a.1);
    }
}
