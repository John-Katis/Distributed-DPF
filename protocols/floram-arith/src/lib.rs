//! Dealer-less DPF with arithmetic-shared input and output (Xing et al.,
//! "Distributed Function Secret Sharing and Applications", NDSS'25), built on
//! the Floram-CPRG tree:
//!
//! * [`gen::gen`]: A2B of the additively shared α in the garbled circuit,
//!   Floram's GC-selected correction words, and CCMP + arithmetic MUX for the
//!   final correction word over Z_2^ℓ.
//! * [`key::ArithKey`]: point and full-domain evaluation.
//!
//! Semi-honest only, as in the paper.

pub mod gen;
pub mod key;

pub use gen::{deal, gen, gen_reference, GenOutput};
pub use key::ArithKey;

use dpf_common::arith::mask;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use std::time::{Duration, Instant};

pub struct TwoPartyRun {
    pub outs: [GenOutput; 2],
    pub times: [Duration; 2],
    pub seeds: [[u8; 32]; 2],
    /// The additive shares of α that were used, so tests can cover wrap-around.
    pub alpha_shares: [u64; 2],
}

/// Additively shares α (mod 2^n) and β (mod 2^bits) and runs [`gen`] for both
/// parties.
pub fn run_gen(n_size: u64, bits: usize, alpha: u64, beta: u64, seed: u64) -> TwoPartyRun {
    assert!(alpha < n_size);
    let n = dpf_common::block::depth_for(n_size);
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let seeds: [[u8; 32]; 2] = [rng.gen(), rng.gen()];
    let an = mask(n);
    let a0 = rng.gen::<u64>() & an;
    let a1 = alpha.wrapping_sub(a0) & an;
    let m = mask(bits);
    let b0 = rng.gen::<u64>() & m;
    let b1 = beta.wrapping_sub(b0) & m;
    let (r0, r1) = dpf_common::net::run_two_party(
        |c| {
            let t = Instant::now();
            let o = gen(c, n_size, bits, a0, b0, seeds[0]);
            (o, t.elapsed())
        },
        |c| {
            let t = Instant::now();
            let o = gen(c, n_size, bits, a1, b1, seeds[1]);
            (o, t.elapsed())
        },
    );
    TwoPartyRun { outs: [r0.0, r1.0], times: [r0.1, r1.1], seeds, alpha_shares: [a0, a1] }
}
