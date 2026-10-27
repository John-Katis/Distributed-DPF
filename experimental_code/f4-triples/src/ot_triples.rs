//! F4 Beaver triples from random COTs (Ferret), no PCG.

use dpf_common::block::Block;
use dpf_common::f4;
use dpf_common::hash::cot_hash;
use dpf_common::net::Channel;
use dpf_common::ot::{CotPair, RandomCots};
use rand::{CryptoRng, RngCore};

/// `m` F4 Beaver triples from random COTs, two per triple and direction
/// (Gilboa's OLE on random OTs). In the direction where party s sends, the
/// random OTs `(x_{0,i}, x_{1,i})` (2-bit hashes, `A_i = x_{0,i} ⊕ x_{1,i}`)
/// with choices `r_h, r_l` give shares of `r_h·A_h ⊕ r_l·A_l`. The receiver's
/// `a = r_h·ω + r_l` is its choice; the sender takes `b = A_l` and sends
/// `d = A_h ⊕ ω·A_l` (2 bits) so that the receiver's `x_{r_h} ⊕ r_h·d` turns
/// `A_h` into `ω·b`: shares of `a_{1−s}·b_s`. Both directions in one round,
/// then `c_b = a_b·b_b ⊕ (cross shares)`. Sends 4 bits per triple and party.
pub fn rot_f4_triples<R: RngCore + CryptoRng>(ch: &mut Channel, cot: &mut CotPair, m: usize, rng: &mut R) -> Vec<(u8, u8, u8)> {
    let delta = cot.delta();
    let h = |x: Block, i: usize| cot_hash().h(x, (9 << 60) | i as u64).0 as u8 & 3;
    let (mut a, mut b, mut c) = (vec![0u8; m], vec![0u8; m], vec![0u8; m]);
    let mut corr = vec![0u8; m.div_ceil(4)];
    let mut recv = None;
    for s in 0..2 {
        match cot.random_cots(ch, s, 2 * m, rng).expect("semi-honest COT") {
            RandomCots::Sender(k) => {
                for i in 0..m {
                    let x0 = [h(k[2 * i], 2 * i), h(k[2 * i + 1], 2 * i + 1)];
                    let x1 = [h(k[2 * i] ^ delta, 2 * i), h(k[2 * i + 1] ^ delta, 2 * i + 1)];
                    let (ah, al) = (x0[0] ^ x1[0], x0[1] ^ x1[1]);
                    b[i] = al;
                    c[i] ^= x0[0] ^ x0[1];
                    corr[i / 4] |= (ah ^ f4::mul(f4::OMEGA, al)) << (2 * (i % 4));
                }
            }
            RandomCots::Receiver(r, macs) => recv = Some((r, macs)),
        }
    }
    ch.send(corr);
    let got = ch.recv();
    assert_eq!(got.len(), m.div_ceil(4), "malformed F4 triple message");
    let (r, macs) = recv.expect("both directions");
    for i in 0..m {
        let (rh, rl) = (r[2 * i], r[2 * i + 1]);
        a[i] = (rh as u8) << 1 | rl as u8;
        let d = got[i / 4] >> (2 * (i % 4)) & 3;
        c[i] ^= h(macs[2 * i], 2 * i) ^ if rh { d } else { 0 } ^ h(macs[2 * i + 1], 2 * i + 1);
    }
    (0..m).map(|i| (a[i], b[i], c[i] ^ f4::mul(a[i], b[i]))).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use dpf_common::net::run_two_party;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn rot_f4_triples_are_triples() {
        for ferret in [false, true] {
            let party = move |seed: u64| {
                move |ch: &mut Channel| {
                    let mut rng = ChaCha20Rng::seed_from_u64(seed);
                    let d = Block::random(&mut rng).with_lsb(ch.party() == 1);
                    let mut cot = CotPair::setup(ch, &mut rng, d, false).unwrap();
                    if ferret {
                        cot.enable_ferret(ch, dpf_common::ot::FerretConfig::TOY, &mut rng).unwrap();
                    }
                    rot_f4_triples(ch, &mut cot, 1000, &mut rng)
                }
            };
            let (t0, t1) = run_two_party(party(1), party(2));
            for (x, y) in t0.iter().zip(&t1) {
                assert_eq!(x.2 ^ y.2, f4::mul(x.0 ^ y.0, x.1 ^ y.1));
            }
            assert!(t0.iter().any(|x| x.0 == 3) && t0.iter().any(|x| x.1 == 2));
        }
    }
}
