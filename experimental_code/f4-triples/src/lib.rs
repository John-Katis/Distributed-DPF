//! Experiment, not part of ours (`protocols/ht-aes`): where the F4 triples of
//! the 2PC AES calls could come from instead of FOLEAGE with `c = 4`.
//!
//! * [`foleage`]: a copy of `dpf_common::foleage` with the compression factor
//!   `c` as a parameter ([`foleage::Params::with_c`]; the attack bound of
//!   ePrint 2025/892 allows `N ≤ 12, 16, 19` for `c = 4, 5, 6`), seed
//!   generation that recomputes each tree level from the CWs instead of
//!   holding all trees, and an expansion on all cores.
//! * [`ot_triples`]: F4 triples from Ferret random COTs, 2 bits per triple and
//!   party in one round.
//!
//! The Gen itself does not depend on where the triples come from, so the
//! per-key cost is the ht-aes Gen (setup excluded) plus the triples' cost
//! measured here (see README.md and `examples/bench.rs`).

pub mod foleage;
pub mod ot_triples;
pub mod p16;
