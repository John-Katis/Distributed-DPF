//! 1-out-of-N OT extension of Kolesnikov–Kumaresan (KK13), as implemented in
//! SCI's `kkot.h` and used by CrypTFlow2 [44] for its bit-triple generator.
//!
//! The extension sender plays receiver in λ' = 256 base OTs with a secret
//! `s ∈ {0,1}^256`. To choose `r ∈ [N]` (N ≤ 256) the receiver encodes it with
//! the Walsh–Hadamard code `C(r)_j = ⟨r, j⟩ mod 2` (256 bits, distance 128) and
//! sends the columns `u^i = G(k_i^0) ⊕ G(k_i^1) ⊕ C(r)_i`. The sender's rows are
//! then `q = t ⊕ (C(r) ∧ s)`, and message x is padded with
//! `H(q ⊕ (C(x) ∧ s))`, which equals the receiver's `H(t)` only for x = r. H is
//! SCI's `CCRF`: AES-256 keyed by the 256-bit row, applied to the block 1.
//!
//! Each batch of m OTs costs 256·m bits of columns plus N·l bits per OT, i.e.
//! the 2λ + N·l of CrypTFlow2 §2.2.2. Semi-honest; the base OTs are
//! Naor–Pinkas.

// `aes` 0.8 re-exports generic-array 0.14, whose newest patch release marks it deprecated.
#![allow(deprecated)]

use super::iknp::{pack_words, transpose, words_to_bytes};
use super::np;
use crate::block::Block;
use crate::hash::CtrPrg;
use crate::net::Channel;
use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockEncrypt, KeyInit};
use aes::Aes256;
use rand::{CryptoRng, Rng, RngCore};

/// Number of base OTs and codeword length.
pub const KK_CODE_BITS: usize = 256;

/// Walsh–Hadamard codeword of `x` as (bits 0..128, bits 128..256).
fn codeword(x: usize) -> [u128; 2] {
    let mut c = [0u128; 2];
    for j in 0..KK_CODE_BITS {
        if (x & j).count_ones() & 1 == 1 {
            c[j / 128] |= 1 << (j % 128);
        }
    }
    c
}

/// SCI's CCRF, truncated to `l` bits.
fn ccrf(row: [u128; 2], l: usize) -> u8 {
    let mut key = [0u8; 32];
    key[..16].copy_from_slice(&row[0].to_le_bytes());
    key[16..].copy_from_slice(&row[1].to_le_bytes());
    let aes = Aes256::new(GenericArray::from_slice(&key));
    let mut b = GenericArray::from(1u128.to_le_bytes());
    aes.encrypt_block(&mut b);
    b[0] & ((1u16 << l) - 1) as u8
}

/// Splits 256 columns into rows of two 128-bit halves.
fn rows256(cols: &[Vec<u128>], m: usize) -> Vec<[u128; 2]> {
    let lo = transpose(&cols[..128], m);
    let hi = transpose(&cols[128..], m);
    lo.into_iter().zip(hi).map(|(a, b)| [a, b]).collect()
}

fn check_params(n: usize, l: usize) {
    assert!((2..=KK_CODE_BITS).contains(&n), "1-out-of-N needs 2 ≤ N ≤ 256");
    assert!((1..=8).contains(&l), "messages are 1..=8 bits");
}

pub struct KkotSender {
    s: [u128; 2],
    prgs: Vec<CtrPrg>,
}

impl KkotSender {
    pub fn setup<R: RngCore + CryptoRng>(ch: &mut Channel, rng: &mut R) -> Self {
        let s_bits: Vec<bool> = (0..KK_CODE_BITS).map(|_| rng.gen()).collect();
        let seeds = np::recv_random(ch, &s_bits, rng).expect("base OT");
        let s = [Block::from_bits(&s_bits[..128]).0, Block::from_bits(&s_bits[128..]).0];
        KkotSender { s, prgs: seeds.into_iter().map(CtrPrg::new).collect() }
    }

    /// Sends one batch of 1-out-of-N OTs of `l`-bit messages: the receiver of
    /// OT j learns `msgs[j][r_j]`.
    pub fn send(&mut self, ch: &mut Channel, msgs: &[Vec<u8>], n: usize, l: usize) {
        check_params(n, l);
        let m = msgs.len();
        let words = m.div_ceil(128);
        let u = ch.recv();
        assert_eq!(u.len(), KK_CODE_BITS * words * 16, "unexpected KKOT column length");
        let cols: Vec<Vec<u128>> = self
            .prgs
            .iter_mut()
            .enumerate()
            .map(|(i, prg)| {
                let mut q = prg.next_words(words);
                if (self.s[i / 128] >> (i % 128)) & 1 == 1 {
                    for (w, qw) in q.iter_mut().enumerate() {
                        let off = (i * words + w) * 16;
                        *qw ^= u128::from_le_bytes(u[off..off + 16].try_into().unwrap());
                    }
                }
                q
            })
            .collect();
        let rows = rows256(&cols, m);
        let masks: Vec<[u128; 2]> = (0..n).map(|x| {
            let c = codeword(x);
            [c[0] & self.s[0], c[1] & self.s[1]]
        }).collect();
        let mut out = Vec::with_capacity(m * n);
        for (q, msg) in rows.iter().zip(msgs) {
            assert_eq!(msg.len(), n);
            for x in 0..n {
                out.push(msg[x] ^ ccrf([q[0] ^ masks[x][0], q[1] ^ masks[x][1]], l));
            }
        }
        ch.send(out);
    }
}

pub struct KkotReceiver {
    prgs: Vec<(CtrPrg, CtrPrg)>,
}

impl KkotReceiver {
    pub fn setup<R: RngCore + CryptoRng>(ch: &mut Channel, rng: &mut R) -> Self {
        let pairs = np::send_random(ch, KK_CODE_BITS, rng).expect("base OT");
        KkotReceiver { prgs: pairs.into_iter().map(|(a, b)| (CtrPrg::new(a), CtrPrg::new(b))).collect() }
    }

    /// Receives one batch with choices `r_j ∈ [N]`.
    pub fn recv(&mut self, ch: &mut Channel, choices: &[u8], n: usize, l: usize) -> Vec<u8> {
        check_params(n, l);
        let m = choices.len();
        let words = m.div_ceil(128);
        let code: Vec<[u128; 2]> = choices.iter().map(|&r| {
            assert!((r as usize) < n, "choice out of range");
            codeword(r as usize)
        }).collect();
        let mut ts = Vec::with_capacity(KK_CODE_BITS);
        let mut us = Vec::with_capacity(KK_CODE_BITS);
        for (i, (p0, p1)) in self.prgs.iter_mut().enumerate() {
            let t = p0.next_words(words);
            let g1 = p1.next_words(words);
            let d: Vec<bool> = code.iter().map(|c| (c[i / 128] >> (i % 128)) & 1 == 1).collect();
            let dw = pack_words(&d);
            us.push(t.iter().zip(&g1).zip(&dw).map(|((a, b), c)| a ^ b ^ c).collect::<Vec<_>>());
            ts.push(t);
        }
        ch.send(words_to_bytes(&us));
        let rows = rows256(&ts, m);
        let y = ch.recv();
        assert_eq!(y.len(), m * n, "unexpected KKOT message length");
        (0..m).map(|j| y[j * n + choices[j] as usize] ^ ccrf(rows[j], l)).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::run_two_party;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn codewords_have_distance_128() {
        for a in 0..16 {
            for b in (a + 1)..16 {
                let (x, y) = (codeword(a), codeword(b));
                assert_eq!((x[0] ^ y[0]).count_ones() + (x[1] ^ y[1]).count_ones(), 128);
            }
        }
    }

    #[test]
    fn one_of_n_ots_are_correct() {
        let mut rng = ChaCha20Rng::seed_from_u64(1);
        for (n, l, m) in [(8usize, 2usize, 1usize), (8, 2, 300), (16, 2, 129), (4, 1, 7)] {
            let msgs: Vec<Vec<u8>> = (0..m).map(|_| (0..n).map(|_| rng.gen::<u8>() & ((1 << l) - 1) as u8).collect()).collect();
            let choices: Vec<u8> = (0..m).map(|_| rng.gen_range(0..n) as u8).collect();
            let (m2, c2) = (msgs.clone(), choices.clone());
            let (_, got) = run_two_party(
                move |c| {
                    let mut s = KkotSender::setup(c, &mut ChaCha20Rng::seed_from_u64(2));
                    s.send(c, &m2, n, l);
                    s.send(c, &m2, n, l);
                },
                move |c| {
                    let mut r = KkotReceiver::setup(c, &mut ChaCha20Rng::seed_from_u64(3));
                    (r.recv(c, &c2, n, l), r.recv(c, &c2, n, l))
                },
            );
            for j in 0..m {
                assert_eq!(got.0[j], msgs[j][choices[j] as usize], "n={n} l={l} j={j}");
                assert_eq!(got.1[j], msgs[j][choices[j] as usize], "second batch n={n} l={l} j={j}");
            }
        }
    }
}
