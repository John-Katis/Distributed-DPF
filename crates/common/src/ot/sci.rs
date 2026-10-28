//! SCI (EzPC), the library of CrypTFlow2 and SiRNN, through [`dpf_ot_sys`]:
//! its OTPack (Naor–Pinkas base OTs, IKNP in both directions, the KK13
//! 1-out-of-N extension), CrypTFlow2's bit-triple generator and SiRNN's
//! multiplexer. XLH+25's reference code is built on exactly these.
//!
//! SCI runs over three streams of one [`Channel`] (its `io`, `io_rev` and
//! `io_GC`); every message carries a one-byte stream tag, counted in the
//! bytes. Party 0 is SCI's ALICE (the KKOT sender).

use crate::coin::Abort;
use crate::net::Channel;

pub struct Sci(dpf_ot_sys::Sci);

impl Sci {
    /// SCI's setup: OTPack's base OTs and extensions for all its KKOT sizes.
    pub fn setup(ch: &mut Channel) -> Result<Self, Abort> {
        let party = ch.party();
        dpf_ot_sys::Sci::new(ch, party == 0).map(Sci).map_err(|e| super::abort(e, "SCI setup failed"))
    }

    /// `n` (even) bit triples from CrypTFlow2's `_8KKOT`: one 1-out-of-8
    /// KKOT of 2-bit messages per correlated pair `(2i, 2i+1)`.
    pub fn triples(&mut self, ch: &mut Channel, n: usize) -> Result<Vec<(bool, bool, bool)>, Abort> {
        self.0.triples(ch, n).map_err(|e| super::abort(e, "SCI triple generation failed"))
    }

    /// SiRNN's multiplexer: additive shares of `sel·x` mod 2^bw (bw ≤ 64) from
    /// XOR shares of `sel` and additive shares of `x`.
    pub fn mux(&mut self, ch: &mut Channel, sel: &[bool], x: &[u64], bw: usize) -> Result<Vec<u64>, Abort> {
        self.0.mux(ch, sel, x, bw).map_err(|e| super::abort(e, "SCI multiplexer failed"))
    }
}
