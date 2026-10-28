//! Naor–Pinkas 1-out-of-2 base OT, from emp-ot (`OTNP` over secp256r1, the
//! curve Obliv-C uses), through [`dpf_ot_sys`]. Base OTs only seed the IKNP
//! extension, so the interface is the *random*-OT one: the sender gets two
//! random keys and the receiver the one it chose. emp's OTNP transfers chosen
//! messages, so the sender draws the keys and sends them as its messages.
//!
//! Naor–Pinkas is only semi-honest secure here. The malicious COT uses
//! [`super::endemic`] instead. A malformed message makes the calls return
//! [`Abort`].

use crate::block::Block;
use crate::coin::Abort;
use crate::net::Channel;
use rand::{CryptoRng, RngCore};

/// `k` random OTs as sender: the key pairs `(K_0, K_1)`.
pub fn send_random<R: RngCore + CryptoRng>(ch: &mut Channel, k: usize, rng: &mut R) -> Result<Vec<(Block, Block)>, Abort> {
    let pairs: Vec<(Block, Block)> = (0..k).map(|_| (Block::random(rng), Block::random(rng))).collect();
    let m0: Vec<u128> = pairs.iter().map(|p| p.0 .0).collect();
    let m1: Vec<u128> = pairs.iter().map(|p| p.1 .0).collect();
    dpf_ot_sys::np_send(ch, &m0, &m1).map_err(|e| super::abort(e, "Naor–Pinkas base OT failed"))?;
    Ok(pairs)
}

/// Random OTs as receiver: `K_{c_i}` for each choice `c_i`.
pub fn recv_random<R: RngCore + CryptoRng>(ch: &mut Channel, choices: &[bool], _rng: &mut R) -> Result<Vec<Block>, Abort> {
    let got = dpf_ot_sys::np_recv(ch, choices).map_err(|e| super::abort(e, "Naor–Pinkas base OT failed"))?;
    Ok(got.into_iter().map(Block).collect())
}
