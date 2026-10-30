//! Semi-honest variant: arithmetic payload in a prime field ([`gen`]) or
//! binary payload in F_2^ℓ ([`bin`]).

pub mod bin;
pub mod gen;
pub mod key;

pub use gen::{deal, gen, gen_reference, GenOutput};
pub use key::ShKey;
