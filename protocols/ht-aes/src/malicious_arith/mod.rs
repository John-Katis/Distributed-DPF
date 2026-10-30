//! Malicious variant with an arithmetic payload (the paper's "Full protocols
//! in the malicious setting"): the semi-honest Gen on the same preprocessing,
//! plus the persistent payload-MAC key `⟨δ⟩`, the MAC mask `F^mac`, the
//! payload-MAC word `W^MAC_CW` and Π_Verify. Payload in F, MAC in E ⊇ F: the
//! paper's [`crate::field::BabyBear`] with [`crate::field::BabyBear4`], or
//! [`crate::field::Gold`] / [`crate::field::M127`] in both roles for wider
//! payloads.

pub mod gen;
pub mod key;

pub use gen::{arith_mal_ands, arith_mal_calls, deal, deal_mask, gen_reference, leaf_counts, run_mal_arith, ArithMalRun, ArithMalSession};
pub use key::{verify, ArithMalKey, VerifyMask};
