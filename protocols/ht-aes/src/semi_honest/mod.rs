//! Semi-honest variant, F4 triples from FOLEAGE: payload in Z_2^ℓ ([`gen`])
//! or in F_2^ℓ ([`bin`]).

pub mod bin;
pub mod gen;
pub mod key;

pub use gen::{deal, gen, gen_reference, GenOutput};
pub use key::ShKey;
