//! Information-theoretic MACs for malicious two-party computation.
//!
//! * [`binary`]: BDOZ-authenticated bits and SPDZ-authenticated GF(2^128)
//!   elements, F_aBit from KOS-checked COT, and the deferred batch check.
//! * [`ring`]: the generic SPDZ engine for arithmetic MACs (OT-based VOLE,
//!   open, batch MAC check) over any [`ring::MacRing`].
//! * [`z2k`]: SPDZ2k over Z_2^k.
//! * [`fp`]: SPDZ over a prime field F_p.

pub mod binary;
pub mod fp;
pub mod ring;
pub mod z2k;
