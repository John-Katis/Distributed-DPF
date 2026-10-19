//! The DPF part of Duoram (Vadapalli, Henry, Goldberg, "Duoram: A
//! Bandwidth-Efficient Distributed ORAM for 2- and 3-Party Computation",
//! USENIX Security 2023), following the authors' code
//! (git-crysp.uwaterloo.ca/avadapal/duoram, `preprocessing/` and
//! `2p-preprocessing/`):
//!
//! * [`gen::correlate`]: the input-independent correlations, AND triples and
//!   product triples (3P: dealt by P2; 2P: from OT).
//! * [`gen::preprocess`]: a Floram-style DPF at a random target `r`, with the
//!   correction words from Du–Atallah products, the deferred final CW, and
//!   the conversion of the XOR-shared tree into additive shares (App. D).
//! * [`gen::online`]: one round that shifts the DPF to an additively shared
//!   α and sets the payload to an additively shared β ∈ Z_2^w.
//! * [`key::DuoramKey`]: point and full-domain evaluation.
//!
//! Two variants: [`run_gen_3p`] with the helper P2 dealing the correlations
//! (3P-Duoram) and [`run_gen_2p`] with the correlations from OT (2P-Duoram).
//! Duoram's ORAM operations (READ, UPDATE, REFRESHBLINDS, the SPIR read) are
//! not implemented. Semi-honest, as in the paper.

pub mod du_atallah;
pub mod gen;
pub mod key;
pub mod tree;

pub use dpf_common::stream::TreeMode;
pub use gen::{deal, deal_mode, gen_2p, gen_2p_mode, gen_3p, gen_3p_helper, gen_3p_mode, gen_reference, gen_reference_mode, GenOutput};
pub use key::DuoramKey;
pub use tree::Lanes;

use dpf_common::arith::mask;
use dpf_common::block::depth_for;
use dpf_common::net::CommStats;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use std::time::{Duration, Instant};

/// A generation run over words of type `R`: `u64` for an output ring of up
/// to 64 bits, `u128` for up to 128 bits.
pub struct Run<R: Lanes = u64> {
    pub outs: [GenOutput<R>; 2],
    /// Wall-clock time of P0 and P1.
    pub times: [Duration; 2],
    /// P2's traffic (3P only).
    pub helper: Option<CommStats>,
    pub alpha_shares: [u64; 2],
}

fn shares<R: Lanes>(n_size: u64, bits: usize, alpha: u64, beta: R, rng: &mut ChaCha20Rng) -> ([u64; 2], [R; 2]) {
    assert!(alpha < n_size);
    let (an, m) = (mask(depth_for(n_size)), R::mask(bits));
    let a0 = rng.gen::<u64>() & an;
    let b0 = R::random(rng).and(m);
    ([a0, alpha.wrapping_sub(a0) & an], [b0, beta.sub(b0).and(m)])
}

/// Additively shares α (mod 2^n) and β (mod 2^bits) and runs 2P-Duoram.
pub fn run_gen_2p<R: Lanes>(n_size: u64, bits: usize, alpha: u64, beta: R, seed: u64) -> Run<R> {
    run_gen_2p_mode(n_size, bits, alpha, beta, seed, TreeMode::Stored)
}

/// [`run_gen_2p`] with the tree held as `mode` says.
pub fn run_gen_2p_mode<R: Lanes>(n_size: u64, bits: usize, alpha: u64, beta: R, seed: u64, mode: TreeMode) -> Run<R> {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let seeds: [[u8; 32]; 2] = [rng.gen(), rng.gen()];
    let (a, b) = shares(n_size, bits, alpha, beta, &mut rng);
    let (r0, r1) = dpf_common::net::run_two_party(
        |c| {
            let t = Instant::now();
            (gen_2p_mode(c, n_size, bits, a[0], b[0], seeds[0], mode), t.elapsed())
        },
        |c| {
            let t = Instant::now();
            (gen_2p_mode(c, n_size, bits, a[1], b[1], seeds[1], mode), t.elapsed())
        },
    );
    Run { outs: [r0.0, r1.0], times: [r0.1, r1.1], helper: None, alpha_shares: a }
}

/// Additively shares α and β and runs 3P-Duoram with the helper P2.
pub fn run_gen_3p<R: Lanes>(n_size: u64, bits: usize, alpha: u64, beta: R, seed: u64) -> Run<R> {
    run_gen_3p_mode(n_size, bits, alpha, beta, seed, TreeMode::Stored)
}

/// [`run_gen_3p`] with the tree held as `mode` says.
pub fn run_gen_3p_mode<R: Lanes>(n_size: u64, bits: usize, alpha: u64, beta: R, seed: u64, mode: TreeMode) -> Run<R> {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let seeds: [[u8; 32]; 3] = [rng.gen(), rng.gen(), rng.gen()];
    let (a, b) = shares(n_size, bits, alpha, beta, &mut rng);
    let (r0, r1, h) = dpf_common::net::run_three_party(
        |p| {
            let t = Instant::now();
            (gen_3p_mode(p, n_size, bits, a[0], b[0], seeds[0], mode), t.elapsed())
        },
        |p| {
            let t = Instant::now();
            (gen_3p_mode(p, n_size, bits, a[1], b[1], seeds[1], mode), t.elapsed())
        },
        |p| gen_3p_helper::<R>(p, n_size, seeds[2]),
    );
    Run { outs: [r0.0, r1.0], times: [r0.1, r1.1], helper: Some(h), alpha_shares: a }
}
