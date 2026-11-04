//! Malicious variant with a binary payload (the paper's "Full protocols in
//! the malicious setting", ported to characteristic 2): the semi-honest Gen
//! in its session (one K, one ⟨Δ⟩), with the additions (A) the payload-MAC
//! word under the persistent `⟨δ⟩` and `K^mac`, and (B) one product per bottom
//! level, and Π_Verify on the outputs. No glue residual (C): a swap does not
//! change a binary output. Payload in `{0,1}^ℓ ⊂ GF(2^128)`.

pub mod gen;
pub mod key;

pub use gen::{deal, deal_mask, gen_reference, mal_ands, mal_calls, run_mal, Fault, MalPre, MalRun, MalSession};
pub use key::{low, open_checked, verify, verify_and_open, MalKey};
