//! Commitments (F_com) and coin tossing (F_coin), both in the random-oracle
//! model with SHA-256.
//!
//! A commitment to `v` is `SHA-256("dpf-common/com" ∥ r ∥ v)` with a fresh
//! 128-bit opening `r`. Coin tossing is two flights: both parties commit to a
//! random seed, then both open; the coin is the XOR of the seeds. A party that
//! sends a bad opening makes the call return [`Abort`].

use crate::block::{blocks_from_bytes, blocks_to_bytes, Block};
use crate::hash::CtrPrg;
use crate::net::Channel;
use rand::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};

/// A malicious-security check failed. The protocol must stop.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Abort(pub &'static str);

impl std::fmt::Display for Abort {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "abort: {}", self.0)
    }
}

impl std::error::Error for Abort {}

fn digest(opening: &[u8; 16], value: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"dpf-common/com");
    h.update(opening);
    h.update((value.len() as u64).to_le_bytes());
    h.update(value);
    h.finalize().into()
}

/// Commits to `value`. Returns `(commitment, opening)`.
pub fn commit<R: RngCore + CryptoRng>(value: &[u8], rng: &mut R) -> ([u8; 32], [u8; 16]) {
    let mut r = [0u8; 16];
    rng.fill_bytes(&mut r);
    (digest(&r, value), r)
}

pub fn verify(com: &[u8; 32], value: &[u8], opening: &[u8; 16]) -> bool {
    digest(opening, value) == *com
}

/// Commits to `value`, exchanges commitments, then exchanges openings. Returns
/// the peer's value once its opening verifies. Two flights.
pub fn commit_and_open<R: RngCore + CryptoRng>(ch: &mut Channel, value: &[u8], rng: &mut R) -> Result<Vec<u8>, Abort> {
    let (com, r) = commit(value, rng);
    ch.send(com.to_vec());
    let their_com: [u8; 32] = ch.recv().try_into().map_err(|_| Abort("malformed commitment"))?;
    let mut msg = r.to_vec();
    msg.extend_from_slice(value);
    ch.send(msg);
    let theirs = ch.recv();
    if theirs.len() < 16 {
        return Err(Abort("malformed opening"));
    }
    let (r1, v1) = theirs.split_at(16);
    if !verify(&their_com, v1, r1.try_into().unwrap()) {
        return Err(Abort("commitment opening does not verify"));
    }
    Ok(v1.to_vec())
}

/// [`commit_and_open`] for blocks.
pub fn commit_and_open_blocks<R: RngCore + CryptoRng>(
    ch: &mut Channel,
    value: &[Block],
    rng: &mut R,
) -> Result<Vec<Block>, Abort> {
    let v = commit_and_open(ch, &blocks_to_bytes(value), rng)?;
    if v.len() != value.len() * 16 {
        return Err(Abort("opened value has the wrong length"));
    }
    Ok(blocks_from_bytes(&v))
}

/// F_coin: a uniformly random 128-bit seed known to both parties.
pub fn coin_block<R: RngCore + CryptoRng>(ch: &mut Channel, rng: &mut R) -> Result<Block, Abort> {
    let mine = Block::random(rng);
    let theirs = commit_and_open_blocks(ch, &[mine], rng)?;
    Ok(mine ^ theirs[0])
}

/// F_coin for many values: one coin toss expanded with AES-CTR.
pub fn coin_blocks<R: RngCore + CryptoRng>(ch: &mut Channel, n: usize, rng: &mut R) -> Result<Vec<Block>, Abort> {
    let seed = coin_block(ch, rng)?;
    Ok(CtrPrg::new(seed).next_words(n).into_iter().map(Block).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::run_two_party;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn coins_agree() {
        let (a, b) = run_two_party(
            |c| coin_blocks(c, 5, &mut ChaCha20Rng::seed_from_u64(1)).unwrap(),
            |c| coin_blocks(c, 5, &mut ChaCha20Rng::seed_from_u64(2)).unwrap(),
        );
        assert_eq!(a, b);
        assert_ne!(a[0], a[1]);
    }

    #[test]
    fn bad_opening_aborts() {
        let (a, _) = run_two_party(
            |c| commit_and_open(c, b"hello", &mut ChaCha20Rng::seed_from_u64(1)),
            |c| {
                let mut rng = ChaCha20Rng::seed_from_u64(2);
                let (com, r) = commit(b"world", &mut rng);
                c.send(com.to_vec());
                c.recv();
                let mut msg = r.to_vec();
                msg.extend_from_slice(b"WORLD"); // opens to a different value
                c.send(msg);
                c.recv()
            },
        );
        assert_eq!(a, Err(Abort("commitment opening does not verify")));
    }
}
