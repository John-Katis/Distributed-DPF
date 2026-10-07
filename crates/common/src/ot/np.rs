//! Naor–Pinkas 1-out-of-2 base OT over secp256r1, the curve Obliv-C uses
//! (`DHCurveName` in `obliv_common.h`). Base OTs only seed the IKNP extension,
//! so this is the *random*-OT variant: the sender gets two random keys and the
//! receiver gets the one it chose. This drops the final ciphertext flight that
//! Obliv-C's chosen-message `npotSend1Of2` sends.
//!
//! Naor–Pinkas is only semi-honest secure here (one sender secret for every
//! OT, no binding of the receiver's keys). The malicious COT uses
//! [`super::endemic`] instead. Malformed points make the calls return
//! [`Abort`] rather than panic.

use crate::block::Block;
use crate::coin::Abort;
use crate::net::Channel;
use p256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use p256::elliptic_curve::Field;
use p256::{AffinePoint, EncodedPoint, ProjectivePoint, Scalar};
use rand::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};

const POINT_BYTES: usize = 33;

pub(crate) fn encode(p: &ProjectivePoint) -> [u8; POINT_BYTES] {
    let ep = p.to_affine().to_encoded_point(true);
    ep.as_bytes().try_into().expect("compressed point is 33 bytes")
}

/// Decodes a compressed point. Rejects malformed, off-curve and identity points.
pub(crate) fn decode(b: &[u8]) -> Result<ProjectivePoint, Abort> {
    let ep = EncodedPoint::from_bytes(b).map_err(|_| Abort("malformed curve point"))?;
    let a: Option<AffinePoint> = AffinePoint::from_encoded_point(&ep).into();
    let p = ProjectivePoint::from(a.ok_or(Abort("point not on curve"))?);
    if p == ProjectivePoint::IDENTITY {
        return Err(Abort("identity point"));
    }
    Ok(p)
}

fn kdf(p: &ProjectivePoint, i: usize) -> Block {
    let mut h = Sha256::new();
    h.update(encode(p));
    h.update((i as u64).to_le_bytes());
    Block::from_bytes(&h.finalize()[..16])
}

/// Base-OT sender. Returns `k` random key pairs `(K_i^0, K_i^1)`.
pub fn send_random<R: RngCore + CryptoRng>(ch: &mut Channel, k: usize, rng: &mut R) -> Result<Vec<(Block, Block)>, Abort> {
    let g = ProjectivePoint::GENERATOR;
    let c = g * Scalar::random(&mut *rng);
    let r = Scalar::random(&mut *rng);
    let mut msg = Vec::with_capacity(2 * POINT_BYTES);
    msg.extend_from_slice(&encode(&c));
    msg.extend_from_slice(&encode(&(g * r)));
    ch.send(msg);

    let pk0s = ch.recv();
    if pk0s.len() != k * POINT_BYTES {
        return Err(Abort("unexpected base-OT message length"));
    }
    pk0s.chunks_exact(POINT_BYTES)
        .enumerate()
        .map(|(i, b)| {
            let pk0 = decode(b)?;
            let pk1 = c - pk0;
            Ok((kdf(&(pk0 * r), i), kdf(&(pk1 * r), i)))
        })
        .collect()
}

/// Base-OT receiver with choice bits `choices`. Returns `K_i^{choices[i]}`.
pub fn recv_random<R: RngCore + CryptoRng>(ch: &mut Channel, choices: &[bool], rng: &mut R) -> Result<Vec<Block>, Abort> {
    let first = ch.recv();
    if first.len() != 2 * POINT_BYTES {
        return Err(Abort("unexpected base-OT message length"));
    }
    let c = decode(&first[..POINT_BYTES])?;
    let gr = decode(&first[POINT_BYTES..])?;

    let g = ProjectivePoint::GENERATOR;
    let mut msg = Vec::with_capacity(choices.len() * POINT_BYTES);
    let mut ks = Vec::with_capacity(choices.len());
    for &sel in choices {
        let k = Scalar::random(&mut *rng);
        let pk_sel = g * k;
        let pk0 = if sel { c - pk_sel } else { pk_sel };
        msg.extend_from_slice(&encode(&pk0));
        ks.push(k);
    }
    ch.send(msg);
    Ok(ks.iter().enumerate().map(|(i, k)| kdf(&(gr * k), i)).collect())
}
