//! Malicious variant with a Boolean payload (the paper's paragraph "Boolean
//! payloads"): the semi-honest Boolean Gen in its session with the leaf MAC
//! under the persistent `⟨δ⟩`, δ ∈ `F_{2^k}`, and Π_Verify on the outputs. No
//! glue residual: a swap does not change a Boolean output.

pub mod gen;
pub mod key;

pub use crate::semi_honest::gen::{Fault, Word};
pub use gen::{bin_tau, deal, gen_reference, run_mal, MalRun, MalSession};
pub use key::{low, open_checked, verify, verify_and_open, MalKey};
