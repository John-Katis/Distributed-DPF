//! Building blocks shared by the distributed DPF protocols in this workspace.
//!
//! * [`block`]: 128-bit blocks and bit/byte helpers.
//! * [`prg`]: two-key Davies–Meyer AES PRG (left/right child).
//! * [`hash`]: fixed-key AES hashes and an AES-CTR stream.
//! * [`net`]: in-process two-party network with byte and flight counting.
//! * [`ot`]: Naor–Pinkas base OT, semi-honest IKNP, and correlated OT with an
//!   optional KOS check.
//! * [`gf128`]: GF(2^128) multiplication.
//! * [`arith`]: Z_2^ℓ helpers and the OT-based arithmetic MUX.
//! * [`bool2pc`]: F_AND / F_OR from CrypTFlow2 bit triples and the COT-based
//!   block MUX, on XOR-shared bits.
//! * [`coin`]: commitments and coin tossing.
//! * [`mac`]: authenticated secret sharing (BDOZ/SPDZ) with batch MAC checks.
//! * [`gc`]: semi-honest half-gates garbled circuits over shared inputs.
//! * [`testing`]: cleartext oracles for protocol tests and benchmarks.
//! * [`bench`]: shared CLI and CSV rows for the protocols' benchmarks.

pub mod arith;
pub mod bench;
pub mod block;
pub mod bool2pc;
pub mod coin;
pub mod gc;
pub mod gf128;
pub mod hash;
pub mod mac;
pub mod net;
pub mod ot;
pub mod prg;
pub mod testing;

pub use block::Block;
