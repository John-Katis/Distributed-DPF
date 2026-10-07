//! Half-Tree distributed DPFs.
//!
//! * [`semi_honest`]: ΠDPF of Guo et al., "Half-Tree: Halving the Cost of Tree
//!   Expansion in COT and DPF" (EC'23, §5.2), binary-field payload.
//!
//! [`tree`] holds the per-party tree expansion they share. The shared machinery
//! (blocks, hashes, network, COT) lives in `dpf-common`.

pub mod semi_honest;
pub mod tree;

pub use dpf_common::{block, net};

pub use block::Block;
pub use tree::{Convert, FullEval};

use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use std::time::{Duration, Instant};

/// XOR-shares `α < N` (as u64) and `β` at random from `rng`.
pub fn share_inputs(rng: &mut ChaCha20Rng, alpha: u64, beta: &[Block]) -> ([u64; 2], [Vec<Block>; 2]) {
    let a0: u64 = rng.gen();
    let b0: Vec<Block> = beta.iter().map(|_| Block::random(rng)).collect();
    let b1 = dpf_common::block::xor_blocks(&b0, beta);
    ([a0, a0 ^ alpha], [b0, b1])
}

/// Result of one two-party semi-honest generation run.
pub struct TwoPartyRun {
    pub outs: [semi_honest::GenOutput; 2],
    /// Wall-clock time of each party's call, setup included.
    pub times: [Duration; 2],
    pub seeds: [[u8; 32]; 2],
}

/// Shares α and β and runs [`semi_honest::gen`] for both parties on two threads.
pub fn run_gen(n_size: u64, out_bits: usize, alpha: u64, beta: &[Block], seed: u64) -> TwoPartyRun {
    assert!(alpha < n_size);
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let seeds: [[u8; 32]; 2] = [rng.gen(), rng.gen()];
    let (a, b) = share_inputs(&mut rng, alpha, beta);
    let (r0, r1) = dpf_common::net::run_two_party(
        |c| {
            let t = Instant::now();
            let o = semi_honest::gen(c, n_size, out_bits, a[0], &b[0], seeds[0]);
            (o, t.elapsed())
        },
        |c| {
            let t = Instant::now();
            let o = semi_honest::gen(c, n_size, out_bits, a[1], &b[1], seeds[1]);
            (o, t.elapsed())
        },
    );
    TwoPartyRun { outs: [r0.0, r1.0], times: [r0.1, r1.1], seeds }
}
