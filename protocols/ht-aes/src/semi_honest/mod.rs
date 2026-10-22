//! Semi-honest variant: Z_2^ℓ payload, F4 triples from FOLEAGE.

pub mod gen;
pub mod key;

pub use gen::{deal, foleage_for, gen, gen_reference, GenOutput};
pub use key::ShKey;
