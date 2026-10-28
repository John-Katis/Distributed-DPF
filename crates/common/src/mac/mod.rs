//! Information-theoretic MACs for malicious two-party computation.
//!
//! * [`binary`]: BDOZ-authenticated bits and SPDZ-authenticated GF(2^128)
//!   elements, F_aBit from KOS-checked COT, and the deferred batch check.
//! * [`af4`]: SPDZ bit MACs for F4 circuits, leaky F4 triples with bucketing
//!   and the authenticated backend of [`crate::aes_tower`].

pub mod af4;
pub mod binary;
