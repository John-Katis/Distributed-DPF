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

pub(crate) fn words_to_bytes(cols: &[Vec<u128>]) -> Vec<u8> {
    cols.iter().flat_map(|c| c.iter().flat_map(|w| w.to_le_bytes())).collect()
}

pub struct IknpSender {
    s: u128,
    prgs: Vec<CtrPrg>,
    nonce: u64,
}

impl IknpSender {
    pub fn setup<R: RngCore + CryptoRng>(ch: &mut Channel, rng: &mut R) -> Self {
        let s_bits: Vec<bool> = (0..OT_KEY_BITS).map(|_| rng.gen()).collect();
        let seeds = np::recv_random(ch, &s_bits, rng);
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
        let u = ch.recv();
        assert_eq!(u.len(), OT_KEY_BITS * words * 16);

        let cols: Vec<Vec<u128>> = self
            .prgs
            .iter_mut()
            .enumerate()
            .map(|(i, prg)| {
                let mut q = prg.next_words(words);
                if (self.s >> i) & 1 == 1 {
                    for (w, qw) in q.iter_mut().enumerate() {
                        let off = (i * words + w) * 16;
                        *qw ^= u128::from_le_bytes(u[off..off + 16].try_into().unwrap());
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
        let pairs = np::send_random(ch, OT_KEY_BITS, rng);
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
        ch.send(words_to_bytes(&us));
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
