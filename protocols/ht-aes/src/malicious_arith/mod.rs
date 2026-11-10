//! Malicious variant with an arithmetic payload (Figures `Π_GenMal` and
//! `Π_Verify` of the paper): the semi-honest Gen in its session with the
//! additions (A) the leaf MAC under the persistent `⟦δ⟧` and (B) the glue
//! residual ω, and Π_Verify on the outputs and the residuals. Payload in F, MAC
//! in E ⊇ F: the paper's [`crate::field::BabyBear`] with
//! [`crate::field::BabyBear4`], or [`crate::field::Gold`] / [`crate::field::M127`]
//! in both roles for wider payloads.

pub mod gen;
pub mod key;

pub use crate::verify::{deal_mask, deal_triple, open_checked, VerifyMask};
pub use gen::{arith_mal_ands, arith_mal_calls, deal, gen_reference, run_mal_arith, ArithMalRun, ArithMalSession};
pub use key::{verify, verify_and_open, ArithMalKey};
