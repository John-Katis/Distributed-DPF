//! Malicious variant with an arithmetic payload (the paper's "Full protocols
//! in the malicious setting" for G = F_p): the semi-honest Gen on the same
//! preprocessing, plus the persistent payload-MAC key `⟨δ⟩ ∈ F_p`, the MAC
//! mask `F^mac`, the payload-MAC word `W^MAC_CW` and Π_Verify over F_p.
//! [`crate::field::Gold`] for ℓ ≤ 64, [`crate::field::M127`] above.

pub mod gen;
pub mod key;

pub use gen::{deal, gen_reference, leaf_counts, run_mal_arith, ArithMalRun, ArithMalSession};
pub use key::{verify, ArithMalKey};
