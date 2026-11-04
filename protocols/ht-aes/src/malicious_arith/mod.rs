//! Malicious variant with an arithmetic payload (the paper's "Full protocols
//! in the malicious setting"): the semi-honest Gen in its session (one K, one
//! ⟨Δ⟩, glue level ν ≥ 1) with the additions (A) the payload-MAC word under
//! the persistent `⟦δ⟧` and the keys `K^mac_j`, (B) one product per bottom
//! level, (C) the glue residual ω, and Π_Verify on the outputs and the
//! residuals. Payload in F, MAC in E ⊇ F: the
//! paper's [`crate::field::BabyBear`] with [`crate::field::BabyBear4`], or
//! [`crate::field::Gold`] / [`crate::field::M127`] in both roles for wider
//! payloads.

pub mod gen;
pub mod key;

pub use gen::{arith_mal_ands, arith_mal_calls, deal, deal_mask, gen_reference, leaf_counts, run_mal_arith, ArithMalGen, ArithMalRun, ArithMalSession};
pub use key::{open_checked, verify, verify_and_open, ArithMalKey, VerifyMask};
