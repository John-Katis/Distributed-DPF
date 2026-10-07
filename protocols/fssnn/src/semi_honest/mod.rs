//! Semi-honest FssNN-style DPF: Alg. 5 key generation with the DGH+21
//! LPN-PRG evaluated in semi-honest 2PC (correlations from OT).

pub mod gen;
pub mod key;
pub mod sec_prg;

pub use gen::{deal, gen, gen_reference, GenOutput};
pub use key::FssKey;
