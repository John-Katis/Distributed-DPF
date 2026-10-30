//! Malicious variant (the paper's "Full protocols in the malicious setting"):
//! the semi-honest Gen on the same preprocessing (the OT tower's Ferret
//! COTs, string triples), plus the persistent payload-MAC key `⟨δ⟩`, the
//! MAC mask `F^mac`, the payload-MAC word `W^MAC_CW` and Π_Verify on the
//! outputs. Payload in `{0,1}^ℓ ⊂ GF(2^128)`.

pub mod gen;
pub mod key;

pub use gen::{deal, deal_mask, gen_reference, mal_ands, mal_calls, run_mal, Fault, MalRun, MalSession};
pub use key::{low, open_checked, verify, verify_and_open, MalKey};
