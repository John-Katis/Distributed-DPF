//! Malicious variant: authenticated shares throughout, payload in
//! `{0,1}^ℓ ⊂ GF(2^128)` with a payload MAC, Π_Verify on the outputs.

pub mod gen;
pub mod key;

pub use gen::{deal, gen_reference, mal_products, run_mal, Fault, MalRun, MalSession};
pub use key::{low, verify, MalKey};
