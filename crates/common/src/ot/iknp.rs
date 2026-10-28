//! Semi-honest IKNP OT extension (chosen messages, as Obliv-C's
//! `honestOTExt*` in `ot.c`), from emp-ot's `IKNP` through [`dpf_ot_sys`].
//!
//! The extension sender (Floram party 1, the garbler) plays *receiver* in the
//! `OT_KEY_BITS` Naor–Pinkas base OTs with a secret choice vector `s`. The
//! extension receiver plays base-OT *sender*. Every batch of `m` OTs costs two
//! rounds: the receiver sends `OT_KEY_BITS × m` bits of columns, then the
//! sender sends `2m` padded messages.
//!
//! `precompute` moves the column message into an input-independent
//! preprocessing phase: it makes random OTs (random pads, random choices) in
//! advance, and every later batch derandomises them as Beaver does. The
//! receiver sends `d = c ⊕ r` (one bit per OT), the sender `x_0 ⊕ p_d` and
//! `x_1 ⊕ p_{1⊕d}`; still two rounds.
//!
//! The column helpers below are those of the KK13 extension ([`super::kkot`]).

use super::np;
use crate::block::Block;
use crate::net::Channel;
use dpf_ot_sys::Iknp;
use rand::{CryptoRng, Rng, RngCore};


/// Number of base OTs, i.e. the OT-extension key width. 128 bits, the
/// computational security level of every other protocol here; Obliv-C's
/// default is `OT_KEY_BYTES_HONEST = 10`, i.e. 80 bits. Must be at most 128.
pub const OT_KEY_BITS: usize = 128;

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

/// Serialises columns of `m` bits each into exactly the bits they carry:
/// every column's ⌊m/8⌋ whole bytes, then the remaining `m mod 8` bits of all
/// columns packed together. A batch of one OT thus costs `ncols` bits, not
/// `ncols` bytes.
pub(crate) fn words_to_bytes(cols: &[Vec<u128>], m: usize) -> Vec<u8> {
    let (full, tail) = (m / 8, m % 8);
    let mut out: Vec<u8> = cols.iter().flat_map(|c| c.iter().flat_map(|w| w.to_le_bytes()).take(full)).collect();
    let mut tail_bits = Vec::with_capacity(cols.len() * tail);
    for c in cols {
        let byte = c.get(full / 16).map_or(0, |w| (w >> (8 * (full % 16))) as u8);
        tail_bits.extend((0..tail).map(|k| (byte >> k) & 1 == 1));
    }
    out.extend(crate::block::pack_bits(&tail_bits));
    out
}

/// Inverse of [`words_to_bytes`]: `ncols` columns of `m` bits, zero-padded to
/// whole 128-bit words.
pub(crate) fn bytes_to_cols(u: &[u8], ncols: usize, m: usize) -> Vec<Vec<u128>> {
    let (full, tail) = (m / 8, m % 8);
    let words = m.div_ceil(128);
    assert_eq!(u.len(), ncols * full + (ncols * tail).div_ceil(8), "unexpected OT-extension column length");
    let tail_bits = crate::block::unpack_bits(&u[ncols * full..], ncols * tail);
    (0..ncols)
        .map(|i| {
            let mut buf = vec![0u8; words * 16];
            buf[..full].copy_from_slice(&u[i * full..(i + 1) * full]);
            if tail > 0 {
                buf[full] = (0..tail).fold(0u8, |b, k| b | (tail_bits[i * tail + k] as u8) << k);
            }
            buf.chunks_exact(16).map(|w| u128::from_le_bytes(w.try_into().unwrap())).collect()
        })
        .collect()
}


pub struct IknpSender {
    ot: Iknp,
    /// Random-OT pads `(p_0, p_1)` from [`precompute`](Self::precompute).
    pool: Option<Vec<(Block, Block)>>,
}

impl IknpSender {
    pub fn setup<R: RngCore + CryptoRng>(ch: &mut Channel, rng: &mut R) -> Self {
        let s: [bool; OT_KEY_BITS] = std::array::from_fn(|_| rng.gen());
        // Semi-honest IKNP: a malformed base-OT message is a protocol violation.
        let seeds = np::recv_random(ch, &s, rng).expect("base OT");
        let k0: [u128; OT_KEY_BITS] = std::array::from_fn(|i| seeds[i].0);
        let mut ot = Iknp::new(false);
        ot.setup_send(ch, &s, &k0).expect("IKNP setup");
        IknpSender { ot, pool: None }
    }

    /// Preprocessing: `m` random OTs for the `send` calls that follow, which
    /// then only derandomise and must not ask for more.
    pub fn precompute(&mut self, ch: &mut Channel, m: usize) {
        assert!(self.pool.is_none(), "OTs already precomputed");
        let (p0, p1) = self.ot.send_rot(ch, m).expect("IKNP random OT");
        self.pool = Some(p0.into_iter().zip(p1).map(|(a, b)| (Block(a), Block(b))).collect());
    }

    /// Sends one batch of chosen-message OTs. The receiver gets `msgs[j].0` or
    /// `msgs[j].1` according to its j-th choice bit.
    pub fn send(&mut self, ch: &mut Channel, msgs: &[(Block, Block)]) {
        let m = msgs.len();
        if let Some(pool) = self.pool.as_mut() {
            assert!(m <= pool.len(), "OT pool exhausted");
            let d = ch.recv_bits(m);
            let mut out = Vec::with_capacity(2 * m);
            for (((x0, x1), (p0, p1)), dj) in msgs.iter().zip(pool.drain(..m)).zip(d) {
                let (q0, q1) = if dj { (p1, p0) } else { (p0, p1) };
                out.push(*x0 ^ q0);
                out.push(*x1 ^ q1);
            }
            ch.send_blocks(&out);
            return;
        }
        let m0: Vec<u128> = msgs.iter().map(|x| x.0 .0).collect();
        let m1: Vec<u128> = msgs.iter().map(|x| x.1 .0).collect();
        self.ot.send(ch, &m0, &m1).expect("IKNP send");
    }
}

pub struct IknpReceiver {
    ot: Iknp,
    /// Random choices `r_j` and pads `p_{r_j}` from
    /// [`precompute`](Self::precompute).
    pool: Option<(Vec<bool>, Vec<Block>)>,
}

impl IknpReceiver {
    pub fn setup<R: RngCore + CryptoRng>(ch: &mut Channel, rng: &mut R) -> Self {
        let pairs = np::send_random(ch, OT_KEY_BITS, rng).expect("base OT");
        let k0: [u128; OT_KEY_BITS] = std::array::from_fn(|i| pairs[i].0 .0);
        let k1: [u128; OT_KEY_BITS] = std::array::from_fn(|i| pairs[i].1 .0);
        let mut ot = Iknp::new(false);
        ot.setup_recv(ch, &k0, &k1).expect("IKNP setup");
        IknpReceiver { ot, pool: None }
    }

    /// Preprocessing: `m` random OTs for the `recv` calls that follow, which
    /// then only derandomise and must not ask for more.
    pub fn precompute<R: RngCore + CryptoRng>(&mut self, ch: &mut Channel, m: usize, rng: &mut R) {
        assert!(self.pool.is_none(), "OTs already precomputed");
        let r: Vec<bool> = (0..m).map(|_| rng.gen()).collect();
        let pads = self.ot.recv_rot(ch, &r).expect("IKNP random OT");
        self.pool = Some((r, pads.into_iter().map(Block).collect()));
    }

    /// Receives one batch of OTs with the given choice bits.
    pub fn recv(&mut self, ch: &mut Channel, choices: &[bool]) -> Vec<Block> {
        let m = choices.len();
        match self.pool.as_mut() {
            Some((r, p)) => {
                assert!(m <= r.len(), "OT pool exhausted");
                let d: Vec<bool> = choices.iter().zip(r.drain(..m)).map(|(c, r)| c ^ r).collect();
                ch.send_bits(&d);
                let pads: Vec<Block> = p.drain(..m).collect();
                // y_c = x_c ⊕ p_{c ⊕ d} = x_c ⊕ p_r.
                let y = ch.recv_blocks(2 * m);
                (0..m).map(|j| y[2 * j + choices[j] as usize] ^ pads[j]).collect()
            }
            None => self.ot.recv(ch, choices).expect("IKNP recv").into_iter().map(Block).collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::run_two_party;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    /// Two batches, with or without a pool made beforehand.
    fn run(pre: bool) {
        let mut rng = ChaCha20Rng::seed_from_u64(5);
        let msgs: Vec<(Block, Block)> = (0..200).map(|_| (Block::random(&mut rng), Block::random(&mut rng))).collect();
        let choices: Vec<bool> = (0..200).map(|_| rng.gen()).collect();
        let (m, c) = (msgs.clone(), choices.clone());
        let (_, got) = run_two_party(
            move |ch| {
                let mut r = ChaCha20Rng::seed_from_u64(1);
                let mut s = IknpSender::setup(ch, &mut r);
                if pre {
                    s.precompute(ch, 200);
                }
                s.send(ch, &m[..120]);
                s.send(ch, &m[120..]);
            },
            move |ch| {
                let mut r = ChaCha20Rng::seed_from_u64(2);
                let mut rc = IknpReceiver::setup(ch, &mut r);
                if pre {
                    rc.precompute(ch, 200, &mut r);
                }
                let mut out = rc.recv(ch, &c[..120]);
                out.extend(rc.recv(ch, &c[120..]));
                out
            },
        );
        for j in 0..200 {
            assert_eq!(got[j], if choices[j] { msgs[j].1 } else { msgs[j].0 }, "pre={pre} j={j}");
        }
    }

    #[test]
    fn chosen_and_precomputed_ots() {
        run(false);
        run(true);
    }
}
