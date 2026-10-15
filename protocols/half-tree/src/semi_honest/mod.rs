//! Semi-honest Half-Tree distributed DPF (GYW+23 §5.2) with a binary-field
//! payload.

pub mod gen;
pub mod key;

pub use gen::{deal, deal_keys, gen, gen_mode, gen_reference, gen_reference_keys, GenOutput, Session};
pub use key::HtKey;
