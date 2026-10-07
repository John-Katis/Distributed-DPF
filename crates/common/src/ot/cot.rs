//! Correlated OT (COT) from IKNP with 128 columns and a sender-chosen Δ.
//!
//! After `extend`, the sender holds `K_j` and the receiver holds `(r_j, M_j)` with
//!
//! ```text
//! M_j = K_j ⊕ r_j · Δ
//! ```
//!
//! for the receiver's choice bits `r_j` and the sender's global key `Δ`. This is
//! F_COT of Ferret / Half-Tree and F_aBit of the malicious DPF paper: `M_j` is an
//! IT-MAC on `r_j` under `(Δ, K_j)`. The sender picks Δ itself (it is its choice
//! vector in the base OTs), so callers can fix `lsb(Δ)`.
//!
//! With `malicious = true` every `extend` runs the KOS15 consistency check: the
//! receiver pads its choices with [`KOS_EXTRA`] random bits, both parties toss a
//! coin for χ, the receiver sends `x = Σ χ_j r_j` and `t = Σ χ_j M_j`, and the
//! sender checks `t = Σ χ_j K_j ⊕ x·Δ`. A cheating receiver that sent
//! inconsistent columns is caught except with probability 2^-40, at the cost of
//! a few bits of Δ leaking, as in KOS15. Malicious mode also bootstraps from
//! the maliciously secure endemic base OT ([`super::endemic`], Masny–Rindal);
//! semi-honest mode keeps the cheaper Naor–Pinkas base OT.
//!
//! [`CotPair`] holds both directions for one party: it is the sender (with its
//! own Δ) in one instance and the receiver in the other, and `extend` runs both
//! directions with shared flights.

use super::iknp::{pack_words, transpose, words_to_bytes};
use super::{endemic, np};
use crate::block::Block;
use crate::coin::{coin_block, Abort};
use crate::gf128;
use crate::hash::CtrPrg;
use crate::net::Channel;
use rand::{CryptoRng, Rng, RngCore};

/// Column count, i.e. the bit length of Δ.
pub const COT_KEY_BITS: usize = 128;

/// Padding COTs sacrificed by the KOS check: κ + s = 128 + 40.
pub const KOS_EXTRA: usize = 128 + 40;

fn bytes_to_cols(u: &[u8], words: usize) -> Vec<Vec<u128>> {
    assert_eq!(u.len(), COT_KEY_BITS * words * 16);
    u.chunks_exact(words * 16)
        .map(|c| c.chunks_exact(16).map(|w| u128::from_le_bytes(w.try_into().unwrap())).collect())
        .collect()
}

/// Which base OT bootstraps the extension.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BaseOt {
    /// Naor–Pinkas, semi-honest.
    NaorPinkas,
    /// Masny–Rindal endemic OT, malicious (ROM).
    Endemic,
}

impl BaseOt {
    fn recv<R: RngCore + CryptoRng>(self, ch: &mut Channel, choices: &[bool], rng: &mut R) -> Result<Vec<Block>, Abort> {
        match self {
            BaseOt::NaorPinkas => np::recv_random(ch, choices, rng),
            BaseOt::Endemic => endemic::recv_random(ch, choices, rng),
        }
    }

    fn send<R: RngCore + CryptoRng>(self, ch: &mut Channel, k: usize, rng: &mut R) -> Result<Vec<(Block, Block)>, Abort> {
        match self {
            BaseOt::NaorPinkas => np::send_random(ch, k, rng),
            BaseOt::Endemic => endemic::send_random(ch, k, rng),
        }
    }
}

pub struct CotSender {
    delta: Block,
    prgs: Vec<CtrPrg>,
}

impl CotSender {
    /// Runs the base OTs as base-OT receiver with choice bits `delta`.
    pub fn setup<R: RngCore + CryptoRng>(ch: &mut Channel, rng: &mut R, delta: Block, base: BaseOt) -> Result<Self, Abort> {
        let seeds = base.recv(ch, &delta.to_bits(), rng)?;
        Ok(CotSender { delta, prgs: seeds.into_iter().map(CtrPrg::new).collect() })
    }

    pub fn delta(&self) -> Block {
        self.delta
    }

    /// Receives the receiver's correction columns for `m` COTs and returns `K`.
    pub fn recv_extend(&mut self, ch: &mut Channel, m: usize) -> Vec<Block> {
        let words = m.div_ceil(128);
        let u = bytes_to_cols(&ch.recv(), words);
        let cols: Vec<Vec<u128>> = self
            .prgs
            .iter_mut()
            .zip(&u)
            .enumerate()
            .map(|(i, (prg, ui))| {
                let mut q = prg.next_words(words);
                if self.delta.bit(i) {
                    for (qw, uw) in q.iter_mut().zip(ui) {
                        *qw ^= uw;
                    }
                }
                q
            })
            .collect();
        transpose(&cols, m).into_iter().map(Block).collect()
    }
}

pub struct CotReceiver {
    prgs: Vec<(CtrPrg, CtrPrg)>,
}

impl CotReceiver {
    /// Runs the base OTs as base-OT sender.
    pub fn setup<R: RngCore + CryptoRng>(ch: &mut Channel, rng: &mut R, base: BaseOt) -> Result<Self, Abort> {
        let pairs = base.send(ch, COT_KEY_BITS, rng)?;
        Ok(CotReceiver { prgs: pairs.into_iter().map(|(a, b)| (CtrPrg::new(a), CtrPrg::new(b))).collect() })
    }

    /// Sends the correction columns for the given choice bits and returns `M`.
    pub fn send_extend(&mut self, ch: &mut Channel, choices: &[bool]) -> Vec<Block> {
        let m = choices.len();
        let words = m.div_ceil(128);
        let r = pack_words(choices);
        let mut ts = Vec::with_capacity(COT_KEY_BITS);
        let mut us = Vec::with_capacity(COT_KEY_BITS);
        for (p0, p1) in self.prgs.iter_mut() {
            let t = p0.next_words(words);
            let g1 = p1.next_words(words);
            us.push(t.iter().zip(&g1).zip(&r).map(|((a, b), c)| a ^ b ^ c).collect::<Vec<_>>());
            ts.push(t);
        }
        ch.send(words_to_bytes(&us));
        transpose(&ts, m).into_iter().map(Block).collect()
    }
}

/// χ_j for the KOS check of the instance whose receiver is party `recv_party`.
fn kos_chi(seed: Block, recv_party: usize, n: usize) -> Vec<Block> {
    CtrPrg::new(seed ^ Block(recv_party as u128 + 1)).next_words(n).into_iter().map(Block).collect()
}

/// Both COT directions of one party.
pub struct CotPair {
    party: usize,
    malicious: bool,
    pub sender: CotSender,
    pub receiver: CotReceiver,
    /// COTs produced so far (as receiver plus as sender), for cost reporting.
    pub produced: usize,
}

impl CotPair {
    /// Base OTs for both directions. `delta` is this party's global key.
    /// Malicious mode uses the endemic base OT and KOS-checks every extension;
    /// semi-honest mode uses Naor–Pinkas.
    pub fn setup<R: RngCore + CryptoRng>(ch: &mut Channel, rng: &mut R, delta: Block, malicious: bool) -> Result<Self, Abort> {
        let party = ch.party();
        let base = if malicious { BaseOt::Endemic } else { BaseOt::NaorPinkas };
        let (sender, receiver) = if party == 0 {
            let s = CotSender::setup(ch, rng, delta, base)?;
            (s, CotReceiver::setup(ch, rng, base)?)
        } else {
            let r = CotReceiver::setup(ch, rng, base)?;
            (CotSender::setup(ch, rng, delta, base)?, r)
        };
        Ok(CotPair { party, malicious, sender, receiver, produced: 0 })
    }

    pub fn delta(&self) -> Block {
        self.sender.delta()
    }

    pub fn is_malicious(&self) -> bool {
        self.malicious
    }

    /// Runs both directions at once. This party receives COTs on its choice bits
    /// `mine` (returned `M`, with `M = K_peer ⊕ r·Δ_peer`) and sends `theirs` COTs
    /// to the peer (returned `K`, with `M_peer = K ⊕ r_peer·Δ`).
    ///
    /// Semi-honest: one flight. Malicious: four (columns, coin, proof).
    pub fn extend<R: RngCore + CryptoRng>(
        &mut self,
        ch: &mut Channel,
        mine: &[bool],
        theirs: usize,
        rng: &mut R,
    ) -> Result<(Vec<Block>, Vec<Block>), Abort> {
        self.produced += mine.len() + theirs;
        if !self.malicious {
            let m = self.receiver.send_extend(ch, mine);
            let k = self.sender.recv_extend(ch, theirs);
            return Ok((k, m));
        }

        let mut padded = mine.to_vec();
        padded.extend((0..KOS_EXTRA).map(|_| rng.gen::<bool>()));
        let mut m = self.receiver.send_extend(ch, &padded);
        let mut k = self.sender.recv_extend(ch, theirs + KOS_EXTRA);

        let seed = coin_block(ch, rng)?;
        // Proof as receiver.
        let chi = kos_chi(seed, self.party, padded.len());
        let x = padded.iter().zip(&chi).fold(Block::ZERO, |a, (&r, c)| a ^ c.and_bit(r));
        let t = gf128::inner(&chi, &m);
        ch.send_blocks(&[x, t]);
        // Check as sender.
        let proof = ch.recv_blocks(2);
        let chi = kos_chi(seed, 1 - self.party, k.len());
        let q = gf128::inner(&chi, &k);
        if proof[1] != q ^ gf128::mul(proof[0], self.delta()) {
            return Err(Abort("KOS consistency check failed"));
        }
        m.truncate(mine.len());
        k.truncate(theirs);
        Ok((k, m))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::run_two_party;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    fn run(malicious: bool) {
        let mut rng = ChaCha20Rng::seed_from_u64(9);
        let d0 = Block::random(&mut rng);
        let d1 = Block::random(&mut rng);
        let c0: Vec<bool> = (0..300).map(|_| rng.gen()).collect();
        let c1: Vec<bool> = (0..77).map(|_| rng.gen()).collect();
        let (a, b) = (c0.clone(), c1.clone());
        let ((k0, m0), (k1, m1)) = run_two_party(
            move |c| {
                let mut r = ChaCha20Rng::seed_from_u64(1);
                let mut p = CotPair::setup(c, &mut r, d0, malicious).unwrap();
                p.extend(c, &a, 77, &mut r).unwrap()
            },
            move |c| {
                let mut r = ChaCha20Rng::seed_from_u64(2);
                let mut p = CotPair::setup(c, &mut r, d1, malicious).unwrap();
                p.extend(c, &b, 300, &mut r).unwrap()
            },
        );
        assert_eq!((k0.len(), m0.len(), k1.len(), m1.len()), (77, 300, 300, 77));
        for j in 0..300 {
            assert_eq!(m0[j], k1[j] ^ d1.and_bit(c0[j]));
        }
        for j in 0..77 {
            assert_eq!(m1[j], k0[j] ^ d0.and_bit(c1[j]));
        }
    }

    #[test]
    fn correlation_holds() {
        run(false);
        run(true);
    }

    #[test]
    fn kos_catches_inconsistent_columns() {
        let (r0, _) = run_two_party(
            |c| {
                let mut r = ChaCha20Rng::seed_from_u64(1);
                let mut p = CotPair::setup(c, &mut r, Block(5), true).unwrap();
                p.extend(c, &[true; 10], 10, &mut r).map(|_| ())
            },
            |c| {
                let mut r = ChaCha20Rng::seed_from_u64(2);
                let mut p = CotPair::setup(c, &mut r, Block(6), true).unwrap();
                // Cheating receiver: column 2 uses the flipped choice vector, the
                // proof is computed honestly from its own rows.
                let padded: Vec<bool> = (0..10 + KOS_EXTRA).map(|_| r.gen()).collect();
                let words = padded.len().div_ceil(128);
                let rw = pack_words(&padded);
                let (mut ts, mut us) = (Vec::new(), Vec::new());
                for (i, (p0, p1)) in p.receiver.prgs.iter_mut().enumerate() {
                    let t = p0.next_words(words);
                    let g1 = p1.next_words(words);
                    let flip = if i == 2 { u128::MAX } else { 0 };
                    us.push(t.iter().zip(&g1).zip(&rw).map(|((a, b), c)| a ^ b ^ c ^ flip).collect::<Vec<_>>());
                    ts.push(t);
                }
                c.send(words_to_bytes(&us));
                let m: Vec<Block> = transpose(&ts, padded.len()).into_iter().map(Block).collect();
                let _ = p.sender.recv_extend(c, 10 + KOS_EXTRA);
                let seed = coin_block(c, &mut r).unwrap();
                let chi = kos_chi(seed, 1, padded.len());
                let x = padded.iter().zip(&chi).fold(Block::ZERO, |a, (&b, c)| a ^ c.and_bit(b));
                c.send_blocks(&[x, gf128::inner(&chi, &m)]);
                c.recv_blocks(2);
            },
        );
        assert_eq!(r0, Err(Abort("KOS consistency check failed")));
    }
}
