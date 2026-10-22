//! Malicious variant with the authentication layer (A1)–(A5) of "Removing the
//! Selective-Failure Leakage": every share authenticated (bit MACs in
//! GF(2^128)), F4 triples from leaky authenticated triples with bucketing on
//! malicious-Ferret aBits, one check of every opening. Same key and Π_Verify
//! as [`crate::malicious`].

pub mod gen;

pub use crate::malicious::key::{low, verify, MalKey};
pub use gen::{auth_products, deal, gen_reference, run_mal, AuthSession, MalRun};
pub use crate::malicious::Fault;
