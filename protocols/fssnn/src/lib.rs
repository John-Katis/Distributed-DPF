//! A distributed DPF in the style of FssNN (Yang et al., "FssNN:
//! Communication-Efficient Secure Neural Network Training via Function Secret
//! Sharing", ProvSec'24, full version ePrint 2023/073).
//!
//! FssNN builds a key-reduced DCF with output group Z2 and generates its keys
//! without a dealer by evaluating the PRG in 2PC (Alg. 5, F_SecPRG via the
//! MPC-friendly PRG of DGH+21). This crate keeps that key generation and the
//! tree (Alg. 4, early termination) but drops the comparison bit, so the
//! result is a DPF over Z2 that can be compared with the other protocols:
//!
//! * [`lpn_prg`]: the DGH+21 LPN-PRG (public matrices, cleartext evaluation).
//! * [`tree`]: the tree of Alg. 4 without `v`, with early termination.
//! * [`semi_honest`]: Alg. 5 for the DPF ([`semi_honest::gen`]), the
//!   cleartext Gen ([`semi_honest::deal`]), the semi-honest 2PC of the PRG
//!   ([`semi_honest::sec_prg`]) and the key ([`semi_honest::FssKey`]).
//!
//! Shared parts (PRG, tree) sit at the crate root so that a malicious variant
//! can live next to `semi_honest`, as in the `half-tree` crate.

pub mod lpn_prg;
pub mod semi_honest;
pub mod tree;

pub use tree::CorrectionWord;

use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use std::time::{Duration, Instant};

/// Result of one two-party semi-honest generation run.
pub struct TwoPartyRun {
    pub outs: [semi_honest::GenOutput; 2],
    pub times: [Duration; 2],
    pub seeds: [[u8; 32]; 2],
}

/// XOR-shares α and β and runs [`semi_honest::gen`] for both parties.
pub fn run_gen(n_size: u64, alpha: u64, beta: bool, seed: u64) -> TwoPartyRun {
    assert!(alpha < n_size);
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let seeds: [[u8; 32]; 2] = [rng.gen(), rng.gen()];
    let a0: u64 = rng.gen::<u64>() & dpf_common::arith::mask(dpf_common::block::depth_for(n_size));
    let b0: bool = rng.gen();
    let (r0, r1) = dpf_common::net::run_two_party(
        |c| {
            let t = Instant::now();
            let o = semi_honest::gen(c, n_size, a0, b0, seeds[0]);
            (o, t.elapsed())
        },
        |c| {
            let t = Instant::now();
            let o = semi_honest::gen(c, n_size, alpha ^ a0, beta ^ b0, seeds[1]);
            (o, t.elapsed())
        },
    );
    TwoPartyRun { outs: [r0.0, r1.0], times: [r0.1, r1.1], seeds }
}
