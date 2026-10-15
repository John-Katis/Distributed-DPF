//! Actively secure distributed DPF with one-bit leakage (ZGY+24, Fig. 5),
//! built on the Half-Tree correlated tree and the MACs of
//! `dpf_common::mac::binary`.

pub mod gen;
pub mod key;

pub use gen::{gen_reference, gen_reference_mode, run_mal, run_mal_mode, Fault, MalGenOutput, MalRun, MalSession};
pub use key::{MalFull, MalKey};
