//! Semi-honest Half-Tree distributed DPF (GYW+23 §5.2) with a binary-field
//! payload.

pub mod gen;
pub mod key;

pub use gen::{deal, gen, gen_reference, GenOutput, Session};
pub use key::HtKey;
