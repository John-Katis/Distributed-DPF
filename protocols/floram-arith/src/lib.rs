//! Dealer-less DPF with arithmetic-shared input and output (Xing et al.,
//! "Distributed Function Secret Sharing and Applications", NDSS'25, Alg. 2),
//! as in the authors' reference implementation:
//!
//! * [`gen::gen`]: BitDec of the additively shared α (Alg. 14), Floram-style
//!   layer correction words selected with F_MUX^{B,λ}, and CCMP (Alg. 1) plus
//!   F_MUX^{A,ℓ} for the final correction word over Z_2^ℓ.
//! * [`key::ArithKey`]: point and full-domain evaluation.
//! * [`tree`]: the GGM tree with the reference's keyed-AES PRG.
//!
//! Semi-honest only, as in the paper.

pub mod gen;
pub mod key;
pub mod tree;

pub use dpf_common::stream::TreeMode;
pub use gen::{deal, deal_mode, gen, gen_mode, gen_reference, gen_reference_mode, GenOutput};
pub use key::ArithKey;
pub use tree::CorrectionWord;

use dpf_common::arith::{mask, Ring};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use std::time::{Duration, Instant};

pub struct TwoPartyRun<R: Ring = u64> {
    pub outs: [GenOutput<R>; 2],
    pub times: [Duration; 2],
    pub seeds: [[u8; 32]; 2],
    /// The additive shares of α that were used, so tests can cover wrap-around.
    pub alpha_shares: [u64; 2],
}

/// Additively shares α (mod 2^n) and β (mod 2^bits) and runs [`gen`] for both
/// parties, over words of type `R` (`u64` for ℓ ≤ 64, `u128` for ℓ ≤ 128).
pub fn run_gen<R: Ring>(n_size: u64, bits: usize, alpha: u64, beta: R, seed: u64) -> TwoPartyRun<R> {
    run_gen_mode(n_size, bits, alpha, beta, seed, TreeMode::Stored)
}

/// [`run_gen`] with the tree held as `mode` says.
pub fn run_gen_mode<R: Ring>(n_size: u64, bits: usize, alpha: u64, beta: R, seed: u64, mode: TreeMode) -> TwoPartyRun<R> {
    assert!(alpha < n_size);
    let n = dpf_common::block::depth_for(n_size);
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let seeds: [[u8; 32]; 2] = [rng.gen(), rng.gen()];
    let an = mask(n);
    let a0 = rng.gen::<u64>() & an;
    let a1 = alpha.wrapping_sub(a0) & an;
    let m = R::mask(bits);
    let b0 = R::random(&mut rng).and(m);
    let b1 = beta.sub(b0).and(m);
    let (r0, r1) = dpf_common::net::run_two_party(
        |c| {
            let t = Instant::now();
            let o = gen_mode(c, n_size, bits, a0, b0, seeds[0], mode);
            (o, t.elapsed())
        },
        |c| {
            let t = Instant::now();
            let o = gen_mode(c, n_size, bits, a1, b1, seeds[1], mode);
            (o, t.elapsed())
        },
    );
    TwoPartyRun { outs: [r0.0, r1.0], times: [r0.1, r1.1], seeds, alpha_shares: [a0, a1] }
}
