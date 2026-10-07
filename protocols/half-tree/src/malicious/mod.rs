//! Actively secure distributed DPF with one-bit leakage (ZGY+24, Fig. 5),
//! built on the Half-Tree correlated tree and the MACs of
//! `dpf_common::mac::binary`.

pub mod gen;
pub mod key;

pub use gen::{gen_reference, run_mal, Fault, MalGenOutput, MalRun, MalSession};
pub use key::{MalFull, MalKey};
