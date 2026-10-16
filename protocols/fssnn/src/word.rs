//! Output words of up to 256 bits: `{0,1}^ℓ` under XOR or the ring Z_2^ℓ,
//! `1 ≤ ℓ ≤ 256`, and the OT-based arithmetic multiplexer over them.
//!
//! A [`Word`] is two `u128` limbs, low limb first; ring operations wrap mod
//! 2^256 and are reduced with [`Word::masked`]. [`mux`] is the same SIRNN
//! F^{A,ℓ}_MUX as [`dpf_common::arith::mux`], for words wider than 64 bits.

use dpf_common::block::Block;
use dpf_common::coin::Abort;
use dpf_common::hash::cot_hash;
use dpf_common::net::Channel;
use dpf_common::ot::CotPair;
use rand::{CryptoRng, Rng, RngCore};
use std::ops::{Add, BitXor, Neg, Sub};

/// Widest supported output.
pub const MAX_BITS: usize = 256;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Word(pub [u128; 2]);

impl Word {
    pub const ZERO: Word = Word([0, 0]);

    /// `2^bits − 1`.
    pub fn mask(bits: usize) -> Word {
        assert!((1..=MAX_BITS).contains(&bits), "output width must be 1..=256 bits");
        let m = |b: usize| if b >= 128 { u128::MAX } else { (1u128 << b) - 1 };
        Word([m(bits), if bits > 128 { m(bits - 128) } else { 0 }])
    }

    pub fn masked(self, bits: usize) -> Word {
        let m = Word::mask(bits);
        Word([self.0[0] & m.0[0], self.0[1] & m.0[1]])
    }

    /// `2^i`.
    pub fn pow2(i: usize) -> Word {
        assert!(i < MAX_BITS);
        if i < 128 { Word([1 << i, 0]) } else { Word([0, 1 << (i - 128)]) }
    }

    pub fn bit(self, i: usize) -> bool {
        (self.0[i / 128] >> (i % 128)) & 1 == 1
    }

    pub fn random<R: Rng + ?Sized>(rng: &mut R, bits: usize) -> Word {
        Word([rng.gen(), rng.gen()]).masked(bits)
    }

    /// `(−1)^b · self mod 2^bits`.
    pub fn signed(self, b: bool, bits: usize) -> Word {
        (if b { -self } else { self }).masked(bits)
    }

    /// The low `ceil(bits / 8)` bytes, little endian.
    pub fn to_bytes(self, bits: usize) -> Vec<u8> {
        let mut b = self.0[0].to_le_bytes().to_vec();
        b.extend(self.0[1].to_le_bytes());
        b.truncate(bits.div_ceil(8));
        b
    }

    /// Inverse of [`to_bytes`](Self::to_bytes) (at most 32 bytes).
    pub fn from_bytes(bytes: &[u8]) -> Word {
        assert!(bytes.len() <= 32, "a word has at most 32 bytes");
        let mut buf = [0u8; 32];
        buf[..bytes.len()].copy_from_slice(bytes);
        Word([u128::from_le_bytes(buf[..16].try_into().unwrap()), u128::from_le_bytes(buf[16..].try_into().unwrap())])
    }
}

impl From<u64> for Word {
    fn from(x: u64) -> Word {
        Word([x as u128, 0])
    }
}

impl Add for Word {
    type Output = Word;
    fn add(self, o: Word) -> Word {
        let (lo, c) = self.0[0].overflowing_add(o.0[0]);
        Word([lo, self.0[1].wrapping_add(o.0[1]).wrapping_add(c as u128)])
    }
}

impl Neg for Word {
    type Output = Word;
    fn neg(self) -> Word {
        Word([!self.0[0], !self.0[1]]) + Word([1, 0])
    }
}

impl Sub for Word {
    type Output = Word;
    fn sub(self, o: Word) -> Word {
        self + -o
    }
}

impl BitXor for Word {
    type Output = Word;
    fn bitxor(self, o: Word) -> Word {
        Word([self.0[0] ^ o.0[0], self.0[1] ^ o.0[1]])
    }
}

/// A COT key as a ring element: `H(k, 2i) ∥ H(k, 2i + 1)` truncated.
fn pad(k: Block, i: usize, bits: usize) -> Word {
    let h = cot_hash();
    let hi = if bits > 128 { h.h(k, 2 * i as u64 + 1).0 } else { 0 };
    Word([h.h(k, 2 * i as u64).0, hi]).masked(bits)
}

/// Additive shares of `W_{g_i}` for each i, given this party's XOR share of
/// every `g_i` and additive shares of `W0_i`, `W1_i` in Z_2^bits.
///
/// [`dpf_common::arith::mux`] for `bits ≤ 256`: with `D = W1 − W0`, party b is
/// the COT sender for `c_b = (1 − 2g_b)·D_b` and sends `H(K ⊕ Δ) − H(K) − c_b`
/// in `ceil(bits / 8)` bytes; the receiver gets `H(M) − g_{1−b}·u`.
pub fn mux<R: RngCore + CryptoRng>(
    ch: &mut Channel,
    cot: &mut CotPair,
    g: &[bool],
    w0: &[Word],
    w1: &[Word],
    bits: usize,
    rng: &mut R,
) -> Result<Vec<Word>, Abort> {
    let n = g.len();
    assert!(w0.len() == n && w1.len() == n);
    let len = bits.div_ceil(8);
    let (k, mm) = cot.extend(ch, g, n, rng)?;
    let delta = cot.delta();

    let mut out = Vec::with_capacity(n);
    let mut msg = Vec::with_capacity(n * len);
    for i in 0..n {
        let d = (w1[i] - w0[i]).masked(bits);
        let c = d.signed(g[i], bits);
        let x0 = pad(k[i], i, bits);
        let x1 = pad(k[i] ^ delta, i, bits);
        msg.extend((x1 - x0 - c).to_bytes(bits));
        let local = if g[i] { d } else { Word::ZERO };
        out.push((w0[i] + local - x0).masked(bits));
    }
    ch.send(msg);

    let theirs = ch.recv();
    if theirs.len() != n * len {
        return Err(Abort("malformed MUX message"));
    }
    for i in 0..n {
        let u = Word::from_bytes(&theirs[i * len..(i + 1) * len]);
        let y = pad(mm[i], i, bits) - if g[i] { u } else { Word::ZERO };
        out[i] = (out[i] + y).masked(bits);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use dpf_common::net::run_two_party;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn ring_ops_wrap_mod_2_pow_bits() {
        let max = Word::mask(256);
        assert_eq!(max + Word::from(1), Word::ZERO);
        assert_eq!(Word([u128::MAX, 0]) + Word::from(1), Word([0, 1]));
        assert_eq!(Word::ZERO - Word::from(1), max);
        assert_eq!((Word::ZERO - Word::from(1)).masked(130), Word::mask(130));
        assert_eq!(Word::pow2(200).masked(200), Word::ZERO);
        let w = Word::random(&mut ChaCha20Rng::seed_from_u64(1), 256);
        assert_eq!(Word::from_bytes(&w.to_bytes(256)), w);
        assert_eq!(Word::from_bytes(&w.to_bytes(100)), w.masked(104));
    }

    #[test]
    fn mux_selects() {
        for bits in [1usize, 64, 127, 128, 129, 256] {
            let mut rng = ChaCha20Rng::seed_from_u64(bits as u64);
            let n = 40;
            let g: Vec<bool> = (0..n).map(|_| rng.gen()).collect();
            let w0: Vec<Word> = (0..n).map(|_| Word::random(&mut rng, bits)).collect();
            let w1: Vec<Word> = (0..n).map(|_| Word::random(&mut rng, bits)).collect();
            let g0: Vec<bool> = (0..n).map(|_| rng.gen()).collect();
            let g1: Vec<bool> = g.iter().zip(&g0).map(|(a, b)| a ^ b).collect();
            let a0: Vec<Word> = (0..n).map(|_| Word::random(&mut rng, bits)).collect();
            let b0: Vec<Word> = (0..n).map(|_| Word::random(&mut rng, bits)).collect();
            let a1: Vec<Word> = w0.iter().zip(&a0).map(|(w, a)| (*w - *a).masked(bits)).collect();
            let b1: Vec<Word> = w1.iter().zip(&b0).map(|(w, b)| (*w - *b).masked(bits)).collect();
            let party = |seed: u64, g: Vec<bool>, a: Vec<Word>, b: Vec<Word>| {
                move |c: &mut Channel| {
                    let mut r = ChaCha20Rng::seed_from_u64(seed);
                    let d = Block::random(&mut r);
                    let mut cot = CotPair::setup(c, &mut r, d, false).unwrap();
                    mux(c, &mut cot, &g, &a, &b, bits, &mut r).unwrap()
                }
            };
            let (y0, y1) = run_two_party(party(1, g0, a0, b0), party(2, g1, a1, b1));
            for i in 0..n {
                let want = if g[i] { w1[i] } else { w0[i] };
                assert_eq!((y0[i] + y1[i]).masked(bits), want, "bits={bits} i={i}");
            }
        }
    }
}
