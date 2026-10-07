//! Semi-honest IKNP OT extension, after Obliv-C's `honestOTExt*` in `ot.c`.
//!
//! The extension sender (Floram party 1, the garbler) plays *receiver* in the
//! `OT_KEY_BITS` base OTs with a secret choice vector `s`. The extension receiver
//! plays base-OT *sender*. Every later batch of `m` OTs costs one flight each way:
//! the receiver sends `OT_KEY_BITS × m` bits of columns, and the sender sends `2m`
//! padded messages.

use super::np;
use crate::block::Block;
use crate::hash::{ot_hash, CtrPrg};
use crate::net::Channel;
use rand::{CryptoRng, Rng, RngCore};

/// Number of base OTs, i.e. the OT-extension key width. Obliv-C uses
/// `OT_KEY_BYTES_HONEST = 10`, so 80 bits. Set this to 128 for a 128-bit
/// computational security level. Must be at most 128.
pub const OT_KEY_BITS: usize = 80;

pub(crate) fn pack_words(bits: &[bool]) -> Vec<u128> {
    let mut w = vec![0u128; bits.len().div_ceil(128)];
    for (j, &b) in bits.iter().enumerate() {
        w[j / 128] |= (b as u128) << (j % 128);
    }
    w
}

/// Turns `k` columns of `m` bits into `m` rows of `k` bits each.
pub(crate) fn transpose(cols: &[Vec<u128>], m: usize) -> Vec<u128> {
    let mut rows = vec![0u128; m];
    for (i, col) in cols.iter().enumerate() {
        for (j, row) in rows.iter_mut().enumerate() {
            *row |= ((col[j / 128] >> (j % 128)) & 1) << i;
        }
    }
    rows
}

/// Serialises columns of `m` bits each, sending only the ⌈m/8⌉ bytes that
/// carry those bits (the rest of the last word is never used).
pub(crate) fn words_to_bytes(cols: &[Vec<u128>], m: usize) -> Vec<u8> {
    let nb = m.div_ceil(8);
    cols.iter().flat_map(|c| c.iter().flat_map(|w| w.to_le_bytes()).take(nb)).collect()
}

/// Inverse of [`words_to_bytes`]: `ncols` columns of `m` bits, zero-padded to
/// whole 128-bit words.
pub(crate) fn bytes_to_cols(u: &[u8], ncols: usize, m: usize) -> Vec<Vec<u128>> {
    let nb = m.div_ceil(8);
    let words = m.div_ceil(128);
    assert_eq!(u.len(), ncols * nb, "unexpected OT-extension column length");
    if nb == 0 {
        return vec![Vec::new(); ncols];
    }
    u.chunks_exact(nb)
        .map(|c| {
            let mut buf = vec![0u8; words * 16];
            buf[..nb].copy_from_slice(&c[..nb]);
            buf.chunks_exact(16).map(|w| u128::from_le_bytes(w.try_into().unwrap())).collect()
        })
        .collect()
}

pub struct IknpSender {
    s: u128,
    prgs: Vec<CtrPrg>,
    nonce: u64,
}

impl IknpSender {
    pub fn setup<R: RngCore + CryptoRng>(ch: &mut Channel, rng: &mut R) -> Self {
        let s_bits: Vec<bool> = (0..OT_KEY_BITS).map(|_| rng.gen()).collect();
        // Semi-honest IKNP: a malformed base-OT message is a protocol violation.
        let seeds = np::recv_random(ch, &s_bits, rng).expect("base OT");
        IknpSender {
            s: Block::from_bits(&s_bits).0,
            prgs: seeds.into_iter().map(CtrPrg::new).collect(),
            nonce: 0,
        }
    }

    /// Sends one batch of chosen-message OTs. The receiver gets `msgs[j].0` or
    /// `msgs[j].1` according to its j-th choice bit.
    pub fn send(&mut self, ch: &mut Channel, msgs: &[(Block, Block)]) {
        let m = msgs.len();
        let words = m.div_ceil(128);
        let u = bytes_to_cols(&ch.recv(), OT_KEY_BITS, m);

        let cols: Vec<Vec<u128>> = self
            .prgs
            .iter_mut()
            .zip(&u)
            .enumerate()
            .map(|(i, (prg, ui))| {
                let mut q = prg.next_words(words);
                if (self.s >> i) & 1 == 1 {
                    for (qw, uw) in q.iter_mut().zip(ui) {
                        *qw ^= uw;
                    }
                }
                q
            })
            .collect();
        let rows = transpose(&cols, m);

        let h = ot_hash();
        let mut out = Vec::with_capacity(2 * m);
        for (j, ((x0, x1), q)) in msgs.iter().zip(&rows).enumerate() {
            let t = self.nonce + j as u64;
            out.push(*x0 ^ h.h(Block(*q), t));
            out.push(*x1 ^ h.h(Block(*q ^ self.s), t));
        }
        self.nonce += m as u64;
        ch.send_blocks(&out);
    }
}

pub struct IknpReceiver {
    prgs: Vec<(CtrPrg, CtrPrg)>,
    nonce: u64,
}

impl IknpReceiver {
    pub fn setup<R: RngCore + CryptoRng>(ch: &mut Channel, rng: &mut R) -> Self {
        let pairs = np::send_random(ch, OT_KEY_BITS, rng).expect("base OT");
        IknpReceiver {
            prgs: pairs.into_iter().map(|(a, b)| (CtrPrg::new(a), CtrPrg::new(b))).collect(),
            nonce: 0,
        }
    }

    /// Receives one batch of OTs with the given choice bits.
    pub fn recv(&mut self, ch: &mut Channel, choices: &[bool]) -> Vec<Block> {
        let m = choices.len();
        let words = m.div_ceil(128);
        let r = pack_words(choices);

        let mut ts = Vec::with_capacity(OT_KEY_BITS);
        let mut us = Vec::with_capacity(OT_KEY_BITS);
        for (p0, p1) in self.prgs.iter_mut() {
            let t = p0.next_words(words);
            let g1 = p1.next_words(words);
            us.push(t.iter().zip(&g1).zip(&r).map(|((a, b), c)| a ^ b ^ c).collect::<Vec<_>>());
            ts.push(t);
        }
        ch.send(words_to_bytes(&us, m));
        let rows = transpose(&ts, m);

        let y = ch.recv_blocks(2 * m);
        let h = ot_hash();
        let out = (0..m)
            .map(|j| y[2 * j + choices[j] as usize] ^ h.h(Block(rows[j]), self.nonce + j as u64))
            .collect();
        self.nonce += m as u64;
        out
    }
}
