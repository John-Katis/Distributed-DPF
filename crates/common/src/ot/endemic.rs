//! Maliciously secure random base OT: the "endemic OT" of Masny–Rindal
//! ("Endemic Oblivious Transfer", CCS'19), from libOTe (`MasnyRindal`, over
//! Curve25519 in the random-oracle model) through [`dpf_ot_sys`]. libOTe uses
//! this construction to bootstrap KOS-style OT extension.
//!
//! The receiver sends a pair of encodings per OT, one of them derived from a
//! key-agreement key and the other from a random-oracle image of it. A
//! malicious receiver cannot know the secrets of both. The sender's message
//! does not depend on the receiver's, so both are in flight in one round.
//! A malformed message makes the calls return [`Abort`].

use crate::block::Block;
use crate::coin::Abort;
use crate::net::Channel;
use rand::{CryptoRng, RngCore};

fn seed<R: RngCore + CryptoRng>(rng: &mut R) -> [u8; 16] {
    let mut s = [0u8; 16];
    rng.fill_bytes(&mut s);
    s
}

/// Base-OT sender. Returns `k` random key pairs `(K_i^0, K_i^1)`.
pub fn send_random<R: RngCore + CryptoRng>(ch: &mut Channel, k: usize, rng: &mut R) -> Result<Vec<(Block, Block)>, Abort> {
    let pairs = dpf_ot_sys::mr_send(ch, seed(rng), k, None).map_err(|e| super::abort(e, "Masny–Rindal base OT failed"))?;
    Ok(pairs.into_iter().map(|(a, b)| (Block(a), Block(b))).collect())
}

/// Base-OT receiver with the given choice bits. Returns `K_i^{c_i}`.
pub fn recv_random<R: RngCore + CryptoRng>(ch: &mut Channel, choices: &[bool], rng: &mut R) -> Result<Vec<Block>, Abort> {
    let got = dpf_ot_sys::mr_recv(ch, seed(rng), choices, None).map_err(|e| super::abort(e, "Masny–Rindal base OT failed"))?;
    Ok(got.into_iter().map(Block).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::run_two_party;
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn random_ots_are_correct() {
        let mut rng = ChaCha20Rng::seed_from_u64(1);
        for k in [1usize, 2, 37, 128] {
            let choices: Vec<bool> = (0..k).map(|_| rng.gen()).collect();
            let ch2 = choices.clone();
            let (pairs, got) = run_two_party(
                move |c| send_random(c, k, &mut ChaCha20Rng::seed_from_u64(2)).unwrap(),
                move |c| recv_random(c, &ch2, &mut ChaCha20Rng::seed_from_u64(3)).unwrap(),
            );
            for i in 0..k {
                let (k0, k1) = pairs[i];
                assert_ne!(k0, k1);
                assert_eq!(got[i], if choices[i] { k1 } else { k0 });
            }
        }
    }

    #[test]
    fn bad_messages_abort() {
        // A receiver that sends bytes that are not a protocol message.
        let (r, _) = run_two_party(
            |c| send_random(c, 1, &mut ChaCha20Rng::seed_from_u64(2)),
            |c| {
                c.send(vec![0x07u8; 70]);
                let _ = c.try_recv();
            },
        );
        assert!(r.is_err());

        // A sender that answers with junk.
        let (_, r) = run_two_party(
            |c| {
                c.send(vec![0u8; 40]);
                let _ = c.try_recv();
            },
            |c| recv_random(c, &[true], &mut ChaCha20Rng::seed_from_u64(3)),
        );
        assert!(r.is_err());
    }
}
