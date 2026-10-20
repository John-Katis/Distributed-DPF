//! Semi-honest F_SecPRG: the 2PC evaluation of the DGH+21 LPN-PRG
//! ([`crate::lpn_prg`]) on XOR-shared inputs, with its correlations from OT.
//!
//! **2PC on XOR-shared x** (DGH+21 §5.1, the gates of Table 2 composed as in
//! §5.1.2; two rounds, as in the "Distributed 2PC" column of Table 3):
//!
//! 1. `Lin_2^A` locally on the Z2 shares.
//! 2. π_Convert^(2,3): open `x̂ = x ⊕ x̃`, then `⟦x*⟧ = ⟦x̂⟧ + ⟦r⟧ + x̂ ⊙ ⟦r⟧ mod 3`
//!    with `r = x̃` shared over Z3.
//! 3. `Lin_3^A` locally on the Z3 shares.
//! 4. π_Convert^(3,2): open `ŷ = y + x̃' mod 3` (5 trits per byte, so
//!    ⌈512/5⌉ bytes), then the share of `y mod 2` is `1 − u − v`, `v` or `u`
//!    for `ŷ = 0, 1, 2`, with `u = x̃' mod 2`, `v = (x̃' + 1 mod 3) mod 2`.
//! 5. XOR with step 1, then `Lin_2^B` locally.
//!
//! **Correlations without a dealer** (DGH+21 §5.5, [`preprocess`]): both
//! kinds come from random COTs in which party 0 (P1) is the sender, converted
//! by Protocols 5.2 and 5.4. DGH+21 take these OT correlations from silent OT
//! ([BCG+19; YWL+20]); here they come from Ferret (YWL+20,
//! [`dpf_common::ot::ferret`]) once it is enabled on the `CotPair`, which Gen
//! does. Without Ferret the same code runs on IKNP with random choices.
//! (Protocol 5.4 writes `x̃_i + j` for `x̃_1 + j`, and `u_2 ∥ v_2 ← r_c` where
//! the receiver unmasks `r_c ⊕ z_c`.)

use crate::lpn_prg::{lpn_prg, MW, M_MID, N_IN};
use dpf_common::block::Block;
use dpf_common::hash::FixedKeyHash;
use dpf_common::net::Channel;
use dpf_common::ot::{CotPair, RandomCots};
use rand::{CryptoRng, Rng, RngCore};
use std::sync::OnceLock;

/// One party's correlated randomness for one 2PC evaluation of G.
#[derive(Clone)]
pub struct PrgCorr {
    /// Z2 share of the input mask `x̃`.
    w: u128,
    /// Z3 share of `x̃` as masks of its 1- and 2-entries.
    r1: u128,
    r2: u128,
    /// Z3 shares of the mask `x̃'` of the 512 intermediate values.
    xt: Vec<u8>,
    /// Z2 shares of `x̃' mod 2` and `(x̃' + 1 mod 3) mod 2`.
    u: [u128; MW],
    v: [u128; MW],
}

fn z3_hash() -> &'static FixedKeyHash {
    static H: OnceLock<FixedKeyHash> = OnceLock::new();
    H.get_or_init(|| FixedKeyHash::new(b"fssnn/z3-ot-hash"))
}

fn h3(x: Block, tweak: u64) -> u8 {
    (z3_hash().h(x, tweak).0 % 3) as u8
}

/// Two bits of `H(x, tweak)`.
fn h2(x: Block, tweak: u64) -> u8 {
    (z3_hash().h(x, tweak).0 & 3) as u8
}

/// Standard deviations of slack per batch in [`draws`].
const Z: f64 = 8.0;

/// Draws for `need` kept correlations when each draw is kept with
/// probability `p` (2/3 for a (2,3)-COT, 3/4 for a (3,2)-pair): the smallest
/// `k` with `k·p − Z·σ ≥ need`, `σ = √(k·p·(1−p))`, so one batch falls short
/// with probability below 10⁻¹⁵ (`z` = [`Z`]). [`preprocess`] still draws
/// again whenever a batch does fall short.
fn draws(need: usize, p: f64, z: f64) -> usize {
    if need == 0 {
        return 0;
    }
    // √k is the positive root of p·x² − z·√(p(1−p))·x − need = 0.
    let s = z * (p * (1.0 - p)).sqrt();
    let x = (s + (s * s + 4.0 * p * need as f64).sqrt()) / (2.0 * p);
    (x * x).ceil() as usize
}

/// Receiver's share `(u_2, v_2)` of a (3,2)-correlation when `x̃_2 = j`, given
/// the sender's `(x̃_1, u_1, v_1)` (Protocol 5.4's `s_j`), as two bits.
fn s_j(x1: u8, u1: bool, v1: bool, j: u8) -> u8 {
    let (u2, v2) = match (x1 + j) % 3 {
        0 => (u1, !v1),
        1 => (!u1, v1),
        _ => (u1, v1),
    };
    u2 as u8 | (v2 as u8) << 1
}

/// Correlations for `calls` 2PC evaluations of G, from random COTs in which
/// party 0 (P1 of DGH+21 §5.5) is the sender. With Ferret enabled on `cot`
/// these are silent OTs, as DGH+21 assume.
///
/// * (2,3) (Protocol 5.2): a random OT over Z3 is `z_j = H(K ⊕ jΔ) mod 3`
///   with the receiver's random choice `c`. Party 0 discards pairs with
///   `z_0 = z_1` and announces the kept ones with one bit per COT.
/// * (3,2) (Protocol 5.4): two random COTs `(K_1, K_2)` give a random
///   1-out-of-4 OT of 2-bit strings, `z_{ab} = H(K_1 ⊕ aΔ) ⊕ H(K_2 ⊕ bΔ)`,
///   with choice `c = c_1 + 2c_2`. The receiver discards `c = 3` (one bit per
///   pair; it reveals only the choice of a discarded OT), so the kept ones are
///   random 1-out-of-3 OTs with `x̃_2 = c`. Party 0 then sends
///   `s_j ⊕ z_j` for `j ∈ Z3` (6 bits, as in DGH+21).
///
/// Two rounds besides Ferret refills: the keep and discard bits cross in one,
/// the masked `s_j` follow in the next.
pub fn preprocess<R: RngCore + CryptoRng>(ch: &mut Channel, cot: &mut CotPair, calls: usize, tweak: &mut u64, rng: &mut R) -> Vec<PrgCorr> {
    preprocess_z(ch, cot, calls, tweak, rng, Z)
}

/// [`preprocess`] with `z` standard deviations of slack per batch.
fn preprocess_z<R: RngCore + CryptoRng>(ch: &mut Channel, cot: &mut CotPair, calls: usize, tweak: &mut u64, rng: &mut R, z: f64) -> Vec<PrgCorr> {
    let (need23, need32) = (calls * N_IN, calls * M_MID);
    let mut c23: Vec<(bool, u8)> = Vec::with_capacity(need23);
    let mut c32: Vec<(u8, bool, bool)> = Vec::with_capacity(need32);
    let delta = cot.delta();
    let first = ch.party() == 0;
    while c23.len() < need23 || c32.len() < need32 {
        let k23 = draws(need23 - c23.len(), 2.0 / 3.0, z);
        let k32 = draws(need32 - c32.len(), 3.0 / 4.0, z);
        let base = *tweak;
        *tweak += (k23 + 2 * k32) as u64;
        let tw = |j: usize| base + j as u64;
        match cot.random_cots(ch, 0, k23 + 2 * k32, rng).expect("semi-honest COT") {
            RandomCots::Sender(keys) => {
                assert!(first);
                let (k2, k3) = keys.split_at(k23);
                let mut keep = Vec::with_capacity(k23);
                for (j, &kj) in k2.iter().enumerate() {
                    let (z0, z1) = (h3(kj, tw(j)), h3(kj ^ delta, tw(j)));
                    keep.push(z0 != z1);
                    if z0 != z1 && c23.len() < need23 {
                        c23.push(if z1 == (z0 + 2) % 3 { (false, z0) } else { (true, z1) });
                    }
                }
                ch.send_bits(&keep);
                let used = ch.recv_bits(k32);
                let mut masked = Vec::new();
                for (p, &dropped) in used.iter().enumerate() {
                    if dropped || c32.len() >= need32 {
                        continue;
                    }
                    let (a, b) = (k3[2 * p], k3[2 * p + 1]);
                    let t = tw(k23 + 2 * p);
                    let z = |c: u8| h2(a ^ delta.and_bit(c & 1 == 1), t) ^ h2(b ^ delta.and_bit(c & 2 == 2), t + 1);
                    let (x1, u1, v1): (u8, bool, bool) = (rng.gen_range(0..3), rng.gen(), rng.gen());
                    for j in 0..3u8 {
                        let m = s_j(x1, u1, v1, j) ^ z(j);
                        masked.extend([m & 1 == 1, m & 2 == 2]);
                    }
                    c32.push((x1, u1, v1));
                }
                ch.send_bits(&masked);
            }
            RandomCots::Receiver(r, macs) => {
                assert!(!first);
                let (r3, m3) = (&r[k23..], &macs[k23..]);
                let dropped: Vec<bool> = (0..k32).map(|p| r3[2 * p] && r3[2 * p + 1]).collect();
                ch.send_bits(&dropped);
                let keep = ch.recv_bits(k23);
                for j in 0..k23 {
                    if keep[j] && c23.len() < need23 {
                        c23.push((r[j], (3 - h3(macs[j], tw(j))) % 3));
                    }
                }
                let mut kept = Vec::new();
                for (p, &d) in dropped.iter().enumerate() {
                    if !d && c32.len() + kept.len() < need32 {
                        kept.push(p);
                    }
                }
                let masked = ch.recv_bits(6 * kept.len());
                for (i, &p) in kept.iter().enumerate() {
                    let c = r3[2 * p] as u8 | (r3[2 * p + 1] as u8) << 1;
                    let t = tw(k23 + 2 * p);
                    let z = h2(m3[2 * p], t) ^ h2(m3[2 * p + 1], t + 1);
                    let m = masked[6 * i + 2 * c as usize] as u8 | (masked[6 * i + 2 * c as usize + 1] as u8) << 1;
                    let s = m ^ z;
                    c32.push((c, s & 1 == 1, s & 2 == 2));
                }
            }
        }
    }
    (0..calls)
        .map(|k| {
            let (mut w, mut r1, mut r2) = (0u128, 0u128, 0u128);
            for (j, &(wj, rj)) in c23[k * N_IN..(k + 1) * N_IN].iter().enumerate() {
                w |= (wj as u128) << j;
                r1 |= ((rj == 1) as u128) << j;
                r2 |= ((rj == 2) as u128) << j;
            }
            let part = &c32[k * M_MID..(k + 1) * M_MID];
            let (mut u, mut v) = ([0u128; MW], [0u128; MW]);
            for (i, &(_, ui, vi)) in part.iter().enumerate() {
                u[i / 128] |= (ui as u128) << (i % 128);
                v[i / 128] |= (vi as u128) << (i % 128);
            }
            PrgCorr { w, r1, r2, xt: part.iter().map(|c| c.0).collect(), u, v }
        })
        .collect()
}

fn pack_trits(t: &[u8]) -> Vec<u8> {
    t.chunks(5).map(|c| c.iter().rev().fold(0u8, |a, &x| a * 3 + x)).collect()
}

fn unpack_trits(bytes: &[u8], n: usize) -> Vec<u8> {
    assert_eq!(bytes.len(), n.div_ceil(5), "unexpected message length");
    let mut out = Vec::with_capacity(n);
    for &b in bytes {
        let mut b = b;
        for _ in 0..5 {
            if out.len() < n {
                out.push(b % 3);
            }
            b /= 3;
        }
    }
    out
}

/// XOR shares of `G(x_k)` for XOR-shared inputs `x_k`, one correlation per
/// input. Two rounds for the whole batch.
pub fn eval_shared(ch: &mut Channel, corr: &[PrgCorr], xs: &[u128]) -> Vec<[u128; 2]> {
    assert_eq!(corr.len(), xs.len());
    let p = lpn_prg();
    let first = ch.party() == 0;

    // Round 1: x̂ = x ⊕ x̃.
    let mine: Vec<Block> = xs.iter().zip(corr).map(|(x, c)| Block(x ^ c.w)).collect();
    ch.send_blocks(&mine);
    let theirs = ch.recv_blocks(xs.len());

    // Convert(2,3), Lin3, mask for Convert(3,2).
    let mut yhat = Vec::with_capacity(xs.len() * M_MID);
    for k in 0..xs.len() {
        let xhat = mine[k].0 ^ theirs[k].0;
        let c = &corr[k];
        // ⟦x*⟧ = [first]·x̂ + r·(1 + x̂) mod 3, as 1-/2-masks: where x̂ = 1 the
        // share of r doubles (1 ↔ 2) and party 0 adds 1.
        let (mut one, mut two) = ((c.r1 & !xhat) | (c.r2 & xhat), (c.r2 & !xhat) | (c.r1 & xhat));
        if first {
            // + x̂: 0 → 1, 1 → 2, 2 → 0 on the x̂ positions.
            let (o, t) = (one, two);
            one = (o & !xhat) | (xhat & !o & !t);
            two = (t & !xhat) | (xhat & o);
        }
        let y = p.lin3_a(one, two);
        yhat.extend(y.iter().zip(&c.xt).map(|(a, b)| (a + b) % 3));
    }

    // Round 2: ŷ.
    let packed: Vec<u8> = yhat.chunks(M_MID).flat_map(pack_trits).collect();
    ch.send(packed);
    let got = ch.recv();
    let per = M_MID.div_ceil(5);
    assert_eq!(got.len(), per * xs.len(), "unexpected message length");

    (0..xs.len())
        .map(|k| {
            let c = &corr[k];
            let theirs = unpack_trits(&got[k * per..(k + 1) * per], M_MID);
            let mut w = p.lin2_a(xs[k]);
            for i in 0..M_MID {
                let yh = (yhat[k * M_MID + i] + theirs[i]) % 3;
                let (u, v) = ((c.u[i / 128] >> (i % 128)) & 1, (c.v[i / 128] >> (i % 128)) & 1);
                let bit = match yh {
                    0 => first as u128 ^ u ^ v,
                    1 => v,
                    _ => u,
                };
                w[i / 128] ^= bit << (i % 128);
            }
            p.lin2_b(&w)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use dpf_common::net::run_two_party;
    use dpf_common::ot::FerretConfig;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn trit_packing_roundtrips() {
        let mut rng = ChaCha20Rng::seed_from_u64(1);
        for n in [1, 4, 5, 6, 512] {
            let t: Vec<u8> = (0..n).map(|_| rng.gen_range(0..3)).collect();
            assert_eq!(unpack_trits(&pack_trits(&t), n), t);
        }
    }

    /// Both parties' correlations and output shares, and the inputs.
    type PairRun = ([Vec<PrgCorr>; 2], [Vec<[u128; 2]>; 2], Vec<u128>);

    fn run_pair(calls: usize, seed: u64, ferret: bool) -> PairRun {
        run_pair_z(calls, seed, ferret, Z)
    }

    fn run_pair_z(calls: usize, seed: u64, ferret: bool, z: f64) -> PairRun {
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        let x: Vec<u128> = (0..calls).map(|_| rng.gen()).collect();
        let x0: Vec<u128> = (0..calls).map(|_| rng.gen()).collect();
        let x1: Vec<u128> = x.iter().zip(&x0).map(|(a, b)| a ^ b).collect();
        let party = |me: u64, xs: Vec<u128>| {
            move |ch: &mut Channel| {
                let mut r = ChaCha20Rng::seed_from_u64(seed * 10 + me);
                let d = Block::random(&mut r);
                let mut cot = CotPair::setup(ch, &mut r, d, false).unwrap();
                if ferret {
                    cot.enable_ferret(ch, FerretConfig::TOY, &mut r).unwrap();
                }
                let mut tw = 0;
                let corr = preprocess_z(ch, &mut cot, calls, &mut tw, &mut r, z);
                let y = eval_shared(ch, &corr, &xs);
                (corr, y)
            }
        };
        let ((c0, y0), (c1, y1)) = run_two_party(party(0, x0), party(1, x1));
        ([c0, c1], [y0, y1], x)
    }

    #[test]
    fn correlations_hold() {
        for ferret in [false, true] {
            correlations_hold_with(ferret);
        }
    }

    fn correlations_hold_with(ferret: bool) {
        let ([c0, c1], ..) = run_pair(3, 2, ferret);
        for (a, b) in c0.iter().zip(&c1) {
            for j in 0..N_IN {
                let w = ((a.w ^ b.w) >> j) & 1;
                let r = |c: &PrgCorr| ((c.r1 >> j) & 1) + 2 * ((c.r2 >> j) & 1);
                assert_eq!(w, (r(a) + r(b)) % 3, "(2,3) at {j}");
            }
            for i in 0..M_MID {
                let x = (a.xt[i] + b.xt[i]) % 3;
                let bit = |m: &[u128; MW]| (m[i / 128] >> (i % 128)) & 1;
                assert_eq!(bit(&a.u) ^ bit(&b.u), (x % 2) as u128, "(3,2) u at {i}");
                assert_eq!(bit(&a.v) ^ bit(&b.v), (((x + 1) % 3) % 2) as u128, "(3,2) v at {i}");
            }
        }
    }

    #[test]
    fn draws_cover_need() {
        for need in [1, 10, 128, 512, 8192, 32768] {
            for p in [2.0 / 3.0, 3.0 / 4.0] {
                let k = draws(need, p, Z) as f64;
                assert!(k * p - Z * (k * p * (1.0 - p)).sqrt() >= need as f64 - 1e-6, "need={need} p={p}");
                assert!(k < need as f64 / p * 1.25 + 600.0, "need={need} p={p}: {k} draws");
            }
        }
    }

    /// Batches sized below the expectation fall short, so preprocessing must
    /// draw again until it has every correlation.
    #[test]
    fn short_batches_are_refilled() {
        for ferret in [false, true] {
            let ([c0, c1], [y0, y1], x) = run_pair_z(4, 5, ferret, -3.0);
            assert_eq!((c0.len(), c1.len()), (4, 4));
            for (a, b) in c0.iter().zip(&c1) {
                for i in 0..M_MID {
                    let t = (a.xt[i] + b.xt[i]) % 3;
                    let bit = |m: &[u128; MW]| (m[i / 128] >> (i % 128)) & 1;
                    assert_eq!(bit(&a.u) ^ bit(&b.u), (t % 2) as u128, "ferret={ferret} (3,2) u at {i}");
                }
            }
            for k in 0..x.len() {
                assert_eq!([y0[k][0] ^ y1[k][0], y0[k][1] ^ y1[k][1]], lpn_prg().eval(x[k]), "ferret={ferret} call {k}");
            }
        }
    }

    #[test]
    fn shared_eval_matches_clear() {
        let (_, [y0, y1], x) = run_pair(5, 3, true);
        for k in 0..x.len() {
            let want = lpn_prg().eval(x[k]);
            assert_eq!([y0[k][0] ^ y1[k][0], y0[k][1] ^ y1[k][1]], want, "call {k}");
            assert_eq!([lpn_prg().eval_side(x[k], 0), lpn_prg().eval_side(x[k], 1)], want, "eval_side {k}");
        }
    }
}
