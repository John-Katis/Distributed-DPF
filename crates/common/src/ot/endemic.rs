//! Maliciously secure random base OT: the "endemic OT" of Masny–Rindal
//! ("Endemic Oblivious Transfer", CCS'19), built from Diffie–Hellman over
//! secp256r1 with hash-to-curve, in the random-oracle model. libOTe uses this
//! construction to bootstrap KOS-style OT extension.
//!
//! For OT `i` with receiver choice `c`:
//!
//! ```text
//! receiver: sk ← Z_q, m_c = g^sk, r_{1−c} uniform, r_c = m_c − H(i, r_{1−c})
//!           sends (r_0, r_1)
//! sender:   s ← Z_q, sends S = g^s (one point for the whole batch)
//!           m_j = r_j + H(i, r_{1−j}),  K_i^j = KDF(S, i, j, m_j^s)
//! receiver: K_i^c = KDF(S, i, c, S^sk)
//! ```
//!
//! A malicious receiver cannot know the discrete logs of both `m_0` and `m_1`,
//! because each depends on a random-oracle image of the other. A malicious
//! sender sees `(r_0, r_1)`, which are uniform whatever `c` is. Malformed,
//! off-curve and identity points make the calls return [`Abort`].
//!
//! Message order: the base-OT receiver speaks first, then the sender. That is
//! the reverse of Naor–Pinkas.

use super::np::{decode, encode};
use crate::block::Block;
use crate::coin::Abort;
use crate::net::Channel;
use p256::elliptic_curve::hash2curve::{ExpandMsgXmd, GroupDigest};
use p256::elliptic_curve::Field;
use p256::{NistP256, ProjectivePoint, Scalar};
use rand::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};

const POINT_BYTES: usize = 33;
const DST: &[u8] = b"dpf-common/endemic-ot/P256_XMD:SHA-256_SSWU_RO_";

/// The random oracle into the group, domain-separated per OT index.
fn h(i: usize, r: &ProjectivePoint) -> Result<ProjectivePoint, Abort> {
    let idx = (i as u64).to_le_bytes();
    let enc = encode(r);
    NistP256::hash_from_bytes::<ExpandMsgXmd<Sha256>>(&[&idx, &enc], &[DST]).map_err(|_| Abort("hash to curve failed"))
}

fn kdf(s: &ProjectivePoint, i: usize, j: bool, p: &ProjectivePoint) -> Block {
    let mut d = Sha256::new();
    d.update(b"dpf-common/endemic-ot/kdf");
    d.update(encode(s));
    d.update((i as u64).to_le_bytes());
    d.update([j as u8]);
    d.update(encode(p));
    Block::from_bytes(&d.finalize()[..16])
}

/// Base-OT sender. Returns `k` random key pairs `(K_i^0, K_i^1)`.
pub fn send_random<R: RngCore + CryptoRng>(ch: &mut Channel, k: usize, rng: &mut R) -> Result<Vec<(Block, Block)>, Abort> {
    let msg = ch.recv();
    if msg.len() != 2 * k * POINT_BYTES {
        return Err(Abort("unexpected base-OT message length"));
    }
    // Validate every point before answering.
    let ms = msg
        .chunks_exact(2 * POINT_BYTES)
        .enumerate()
        .map(|(i, pair)| {
            let r0 = decode(&pair[..POINT_BYTES])?;
            let r1 = decode(&pair[POINT_BYTES..])?;
            Ok((r0 + h(i, &r1)?, r1 + h(i, &r0)?))
        })
        .collect::<Result<Vec<_>, Abort>>()?;
    let s = Scalar::random(&mut *rng);
    let big_s = ProjectivePoint::GENERATOR * s;
    ch.send(encode(&big_s).to_vec());
    Ok(ms
        .iter()
        .enumerate()
        .map(|(i, (m0, m1))| (kdf(&big_s, i, false, &(*m0 * s)), kdf(&big_s, i, true, &(*m1 * s))))
        .collect())
}

/// Base-OT receiver with choice bits `choices`. Returns `K_i^{choices[i]}`.
pub fn recv_random<R: RngCore + CryptoRng>(ch: &mut Channel, choices: &[bool], rng: &mut R) -> Result<Vec<Block>, Abort> {
    let g = ProjectivePoint::GENERATOR;
    let mut msg = Vec::with_capacity(2 * choices.len() * POINT_BYTES);
    let mut sks = Vec::with_capacity(choices.len());
    for (i, &c) in choices.iter().enumerate() {
        let sk = Scalar::random(&mut *rng);
        let other = g * Scalar::random(&mut *rng);
        let mine = g * sk - h(i, &other)?;
        let (r0, r1) = if c { (other, mine) } else { (mine, other) };
        msg.extend_from_slice(&encode(&r0));
        msg.extend_from_slice(&encode(&r1));
        sks.push(sk);
    }
    ch.send(msg);
    let s = ch.recv();
    if s.len() != POINT_BYTES {
        return Err(Abort("unexpected base-OT message length"));
    }
    let big_s = decode(&s)?;
    Ok(sks.iter().zip(choices).enumerate().map(|(i, (sk, &c))| kdf(&big_s, i, c, &(big_s * sk))).collect())
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
    fn bad_points_abort() {
        // A receiver that sends bytes that are not a point.
        let (r, _) = run_two_party(
            |c| send_random(c, 1, &mut ChaCha20Rng::seed_from_u64(2)),
            |c| {
                let mut junk = vec![0x02u8; 2 * POINT_BYTES];
                junk[1] = 0xff;
                junk[POINT_BYTES] = 0x07; // invalid SEC1 tag
                c.send(junk);
            },
        );
        assert!(r.is_err());

        // A sender that answers with the identity encoding.
        let (_, r) = run_two_party(
            |c| {
                c.recv();
                c.send(vec![0u8; POINT_BYTES]);
            },
            |c| recv_random(c, &[true], &mut ChaCha20Rng::seed_from_u64(3)),
        );
        assert!(r.is_err());
    }
}
