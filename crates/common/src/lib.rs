//! Building blocks shared by the distributed DPF protocols in this workspace.
//!
//! * [`block`]: 128-bit blocks and bit/byte helpers.
//! * [`prg`]: two-key Davies–Meyer AES PRG (left/right child).
//! * [`hash`]: fixed-key AES hashes and an AES-CTR stream.
//! * [`net`]: in-process two-party network with byte and flight counting.
//! * [`ot`]: Naor–Pinkas base OT + semi-honest IKNP extension.
//! * [`gc`]: semi-honest half-gates garbled circuits over shared inputs.
//! * [`testing`]: cleartext oracles for protocol tests and benchmarks.

pub mod block;
pub mod gc;
pub mod hash;
pub mod net;
pub mod ot;
pub mod prg;
pub mod testing;

pub use block::Block;
