//! Cleartext references shared by the protocols' tests and benchmarks.

use crate::block::{blocks_for_bits, mask_to_bits, Block};
use rand::{CryptoRng, RngCore};

/// The cleartext point function `f_{α,β}(x) = β if x = α, else 0`.
pub fn point_fn(alpha: u64, beta: &[Block], x: u64) -> Vec<Block> {
    if x == alpha { beta.to_vec() } else { vec![Block::ZERO; beta.len()] }
}

/// A random payload of `out_bits` bits, as `ceil(out_bits/128)` blocks with the
/// unused high bits cleared.
pub fn random_beta<R: RngCore + CryptoRng>(rng: &mut R, out_bits: usize) -> Vec<Block> {
    let mut b: Vec<Block> = (0..blocks_for_bits(out_bits)).map(|_| Block::random(rng)).collect();
    mask_to_bits(&mut b, out_bits);
    b
}
