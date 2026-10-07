//! Floram-CPRG distributed DPF (Doerner–shelat, "Scaling ORAM for Secure
//! Computation", CCS'17, §5), ported from the Obliv-C/C reference code.
//!
//! * [`cprg::gen`]: two-party key generation over a garbled circuit, with OT from
//!   Naor–Pinkas + IKNP, as in Obliv-C.
//! * [`key::DpfKey`]: the resulting BGI key, with point and full-domain eval.
//!
//! The shared machinery (blocks, PRG, network, OT, GC) lives in `dpf-common`.

pub mod cprg;
pub mod key;

// Re-exported so callers can reach the shared types through this crate.
pub use dpf_common::{block, net};

pub use block::Block;
pub use cprg::{gen, gen_reference, FullEval, GenOutput};
pub use key::{CorrectionWord, DpfKey};

use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use std::time::{Duration, Instant};

/// Result of one two-party generation run.
pub struct TwoPartyRun {
    pub outs: [GenOutput; 2],
    /// Wall-clock time of each party's `gen` call, including OT setup.
    pub times: [Duration; 2],
    /// The per-party seeds, so `gen_reference` can reproduce the run.
    pub seeds: [[u8; 32]; 2],
}

/// XOR-shares α and β at random and runs [`cprg::gen`] for both parties on two
/// threads. All randomness derives from `seed`.
pub fn run_gen(n_size: u64, out_bits: usize, alpha: u64, beta: &[Block], seed: u64) -> TwoPartyRun {
    assert!(alpha < n_size);
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let seeds: [[u8; 32]; 2] = [rng.gen(), rng.gen()];
    let a0: u64 = rng.gen();
    let a1 = a0 ^ alpha;
    let b0: Vec<Block> = beta.iter().map(|_| Block::random(&mut rng)).collect();
    let b1 = dpf_common::block::xor_blocks(&b0, beta);
    let (r0, r1) = dpf_common::net::run_two_party(
        |c| {
            let t = Instant::now();
            let o = gen(c, n_size, out_bits, a0, &b0, seeds[0]);
            (o, t.elapsed())
        },
        |c| {
            let t = Instant::now();
            let o = gen(c, n_size, out_bits, a1, &b1, seeds[1]);
            (o, t.elapsed())
        },
    );
    TwoPartyRun { outs: [r0.0, r1.0], times: [r0.1, r1.1], seeds }
}
