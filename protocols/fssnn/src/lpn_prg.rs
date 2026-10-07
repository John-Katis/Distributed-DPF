//! F_SecPRG of FssNN, instantiated with the LPN-PRG of Dinur et al.,
//! "MPC-Friendly Symmetric Cryptography from Alternating Moduli" (CRYPTO'21,
//! the paper FssNN cites as [9]).
//!
//! **The PRG** (DGH+21 Construction 3.4, Table 3 parameters `(n, m, t) =
//! (128, 512, 256)`): for `x ∈ Z_2^128`,
//!
//! ```text
//! G(x) = B·w,  w = (A·x mod 2) ⊕ ((A·x mod 3) mod 2)
//! ```
//!
//! with public random `A ∈ Z_2^{512×128}` and `B ∈ Z_2^{256×512}`. Row `i` of
//! `A·x` over the integers is `popcount(A_i ∧ x)`, so one popcount gives both
//! the mod-2 and the mod-3 value.
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
//! **Correlations without a dealer** (DGH+21 §5.5). Party 0 plays P1:
//!
//! * (2,3)-correlations (Protocol 5.2) from random 1-out-of-2 OTs over Z3,
//!   which are hashed correlated OTs (`z_j = H(K ⊕ jΔ) mod 3`). Pairs with
//!   `z_0 = z_1` are discarded; party 0 sends one bit per OT saying which to
//!   keep (uncompressed, where the paper suggests entropy coding).
//! * (3,2)-correlations (Protocol 5.4) from 1-out-of-3 OTs of 2-bit strings,
//!   here KK13 with N = 3. Party 0's chosen messages `s_j` are what the
//!   receiver's share must be if `x̃_2 = j`, which is Protocol 5.4 with the
//!   random-OT masking folded into the OT. (Protocol 5.4 writes `x̃_i + j` for
//!   `x̃_1 + j`, and `u_2 ∥ v_2 ← r_c` where the receiver unmasks `r_c ⊕ z_c`.)

use dpf_common::block::Block;
use dpf_common::hash::{CtrPrg, FixedKeyHash};
use dpf_common::net::Channel;
use dpf_common::ot::kkot::{KkotReceiver, KkotSender};
use dpf_common::ot::CotPair;
use rand::{CryptoRng, Rng, RngCore};
use std::sync::OnceLock;

/// Input bits.
pub const N_IN: usize = 128;
/// Rows of A, i.e. intermediate Z3 values.
pub const M_MID: usize = 512;
/// Output bits.
pub const T_OUT: usize = 256;
const MW: usize = M_MID / 128;

/// Seed of the public matrices A and B (any fixed value works; they are public).
const MATRIX_SEED: u128 = u128::from_le_bytes(*b"FssNN/DGH21-LPN!");

/// The public matrices of the LPN-PRG.
pub struct LpnPrg {
    a: Vec<u128>,
    b: Vec<[u128; MW]>,
}

/// The LPN-PRG instance used everywhere.
pub fn lpn_prg() -> &'static LpnPrg {
    static P: OnceLock<LpnPrg> = OnceLock::new();
    P.get_or_init(|| {
        let mut prg = CtrPrg::new(Block(MATRIX_SEED));
        let a = prg.next_words(M_MID);
        let bw = prg.next_words(T_OUT * MW);
        let b = bw.chunks(MW).map(|c| c.try_into().unwrap()).collect();
        LpnPrg { a, b }
    })
}

impl LpnPrg {
    /// `A·x mod 2` as 512 bits.
    fn lin2_a(&self, x: u128) -> [u128; MW] {
        let mut u = [0u128; MW];
        for (i, row) in self.a.iter().enumerate() {
            u[i / 128] |= ((row & x).count_ones() as u128 & 1) << (i % 128);
        }
        u
    }

    /// `A·x mod 3` for `x ∈ Z_3^128` given as the masks of its 1- and 2-entries.
    fn lin3_a(&self, one: u128, two: u128) -> Vec<u8> {
        self.a.iter().map(|row| (((row & one).count_ones() + 2 * (row & two).count_ones()) % 3) as u8).collect()
    }

    /// `B·w mod 2` as (bits 0..128, bits 128..256).
    fn lin2_b(&self, w: &[u128; MW]) -> [u128; 2] {
        [parity_rows(&self.b[..128], w), parity_rows(&self.b[128..], w)]
    }

    /// `G(x)` in the clear.
    pub fn eval(&self, x: u128) -> [u128; 2] {
        self.lin2_b(&mid(&self.a, x))
    }

    /// One half of `G(x)` (bits 128·side..128·side + 128), for point evaluation.
    pub fn eval_side(&self, x: u128, side: usize) -> u128 {
        parity_rows(&self.b[128 * side..128 * (side + 1)], &mid(&self.a, x))
    }
}

// The local evaluation is popcount-bound. The workspace builds for baseline
// x86-64, which has no POPCNT, so the hot loops are compiled twice and picked
// at run time (as `dpf_common::gf128` does for PCLMULQDQ).

/// `w = (A·x mod 2) ⊕ ((A·x mod 3) mod 2)`.
#[inline(always)]
fn mid_generic(a: &[u128], x: u128) -> [u128; MW] {
    let mut w = [0u128; MW];
    for (i, row) in a.iter().enumerate() {
        let c = (row & x).count_ones();
        w[i / 128] |= (((c & 1) ^ ((c % 3) & 1)) as u128) << (i % 128);
    }
    w
}

/// Bit j is the parity of `rows[j] ∧ w` (at most 128 rows).
#[inline(always)]
fn parity_rows_generic(rows: &[[u128; MW]], w: &[u128; MW]) -> u128 {
    rows.iter().enumerate().fold(0, |y, (j, row)| {
        let x = row.iter().zip(w).fold(0, |acc, (r, x)| acc ^ (r & x));
        y | ((x.count_ones() & 1) as u128) << j
    })
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "popcnt")]
unsafe fn mid_popcnt(a: &[u128], x: u128) -> [u128; MW] {
    mid_generic(a, x)
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "popcnt")]
unsafe fn parity_rows_popcnt(rows: &[[u128; MW]], w: &[u128; MW]) -> u128 {
    parity_rows_generic(rows, w)
}

#[cfg(target_arch = "x86_64")]
fn has_popcnt() -> bool {
    static HW: OnceLock<bool> = OnceLock::new();
    *HW.get_or_init(|| is_x86_feature_detected!("popcnt"))
}

fn mid(a: &[u128], x: u128) -> [u128; MW] {
    #[cfg(target_arch = "x86_64")]
    if has_popcnt() {
        // SAFETY: the CPU supports POPCNT.
        return unsafe { mid_popcnt(a, x) };
    }
    mid_generic(a, x)
}

fn parity_rows(rows: &[[u128; MW]], w: &[u128; MW]) -> u128 {
    #[cfg(target_arch = "x86_64")]
    if has_popcnt() {
        // SAFETY: the CPU supports POPCNT.
        return unsafe { parity_rows_popcnt(rows, w) };
    }
    parity_rows_generic(rows, w)
}

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

/// The 1-out-of-3 OT end of this party.
pub enum Kk {
    Sender(KkotSender),
    Receiver(KkotReceiver),
}

impl Kk {
    /// Base OTs; party 0 is the KK13 sender (P1 of DGH+21 §5.5).
    pub fn setup<R: RngCore + CryptoRng>(ch: &mut Channel, rng: &mut R) -> Self {
        if ch.party() == 0 {
            Kk::Sender(KkotSender::setup(ch, rng))
        } else {
            Kk::Receiver(KkotReceiver::setup(ch, rng))
        }
    }
}

fn z3_hash() -> &'static FixedKeyHash {
    static H: OnceLock<FixedKeyHash> = OnceLock::new();
    H.get_or_init(|| FixedKeyHash::new(b"fssnn/z3-ot-hash"))
}

fn h3(x: Block, tweak: u64) -> u8 {
    (z3_hash().h(x, tweak).0 % 3) as u8
}

/// `need` (2,3)-correlations `(w_b, r_b)` with `w_0 ⊕ w_1 = r_0 + r_1 mod 3`
/// (Protocol 5.2). `tweak` numbers the OTs across calls.
fn corr23<R: RngCore + CryptoRng>(ch: &mut Channel, cot: &mut CotPair, need: usize, tweak: &mut u64, rng: &mut R) -> Vec<(bool, u8)> {
    let mut out = Vec::with_capacity(need);
    while out.len() < need {
        let left = need - out.len();
        // 1.5 OTs per correlation on average, plus slack so one batch nearly always suffices.
        let k = left + left / 2 + left / 8 + 64;
        let base = *tweak;
        *tweak += k as u64;
        if ch.party() == 0 {
            let (keys, _) = cot.extend(ch, &[], k, rng).expect("semi-honest COT");
            let d = cot.delta();
            let mut keep = Vec::with_capacity(k);
            for (j, &kj) in keys.iter().enumerate() {
                let (z0, z1) = (h3(kj, base + j as u64), h3(kj ^ d, base + j as u64));
                keep.push(z0 != z1);
                if z0 != z1 && out.len() < need {
                    out.push(if z1 == (z0 + 2) % 3 { (false, z0) } else { (true, z1) });
                }
            }
            ch.send_bits(&keep);
        } else {
            let c: Vec<bool> = (0..k).map(|_| rng.gen()).collect();
            let (_, macs) = cot.extend(ch, &c, 0, rng).expect("semi-honest COT");
            let keep = ch.recv_bits(k);
            for j in 0..k {
                if keep[j] && out.len() < need {
                    out.push((c[j], (3 - h3(macs[j], base + j as u64)) % 3));
                }
            }
        }
    }
    out
}

/// `need` (3,2)-correlations `(x̃_b, u_b, v_b)` with `u = x̃ mod 2`,
/// `v = (x̃ + 1 mod 3) mod 2` (Protocol 5.4).
fn corr32<R: RngCore + CryptoRng>(ch: &mut Channel, kk: &mut Kk, need: usize, rng: &mut R) -> Vec<(u8, bool, bool)> {
    match kk {
        Kk::Sender(s) => {
            let mine: Vec<(u8, bool, bool)> = (0..need).map(|_| (rng.gen_range(0..3), rng.gen(), rng.gen())).collect();
            let msgs: Vec<Vec<u8>> = mine
                .iter()
                .map(|&(x1, u1, v1)| {
                    (0..3u8)
                        .map(|j| {
                            let (u2, v2) = match (x1 + j) % 3 {
                                0 => (u1, !v1),
                                1 => (!u1, v1),
                                _ => (u1, v1),
                            };
                            u2 as u8 | (v2 as u8) << 1
                        })
                        .collect()
                })
                .collect();
            s.send(ch, &msgs, 3, 2);
            mine
        }
        Kk::Receiver(r) => {
            let c: Vec<u8> = (0..need).map(|_| rng.gen_range(0..3)).collect();
            let got = r.recv(ch, &c, 3, 2);
            c.iter().zip(got).map(|(&x2, s)| (x2, s & 1 == 1, s & 2 == 2)).collect()
        }
    }
}

/// Correlations for `calls` 2PC evaluations of G, in two flights.
pub fn preprocess<R: RngCore + CryptoRng>(
    ch: &mut Channel,
    cot: &mut CotPair,
    kk: &mut Kk,
    calls: usize,
    tweak: &mut u64,
    rng: &mut R,
) -> Vec<PrgCorr> {
    let c23 = corr23(ch, cot, calls * N_IN, tweak, rng);
    let c32 = corr32(ch, kk, calls * M_MID, rng);
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
/// input. Two flights each way for the whole batch.
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

    #[test]
    fn prg_is_not_trivial() {
        // Inputs of weight ≤ 1 map to 0 (every row sum c ≤ 1 has c mod 2 =
        // (c mod 3) mod 2); random seeds have weight ≈ 64.
        let p = lpn_prg();
        assert_eq!(p.eval(1 << 5), [0, 0]);
        let mut rng = ChaCha20Rng::seed_from_u64(4);
        for _ in 0..20 {
            let y = p.eval(rng.gen());
            assert!((90..=166).contains(&(y[0].count_ones() + y[1].count_ones())), "unbalanced output");
        }
    }

    /// Both parties' correlations and output shares, and the inputs.
    type PairRun = ([Vec<PrgCorr>; 2], [Vec<[u128; 2]>; 2], Vec<u128>);

    fn run_pair(calls: usize, seed: u64) -> PairRun {
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        let x: Vec<u128> = (0..calls).map(|_| rng.gen()).collect();
        let x0: Vec<u128> = (0..calls).map(|_| rng.gen()).collect();
        let x1: Vec<u128> = x.iter().zip(&x0).map(|(a, b)| a ^ b).collect();
        let party = |me: u64, xs: Vec<u128>| {
            move |ch: &mut Channel| {
                let mut r = ChaCha20Rng::seed_from_u64(seed * 10 + me);
                let d = Block::random(&mut r);
                let mut cot = CotPair::setup(ch, &mut r, d, false).unwrap();
                let mut kk = Kk::setup(ch, &mut r);
                let mut tw = 0;
                let corr = preprocess(ch, &mut cot, &mut kk, calls, &mut tw, &mut r);
                let y = eval_shared(ch, &corr, &xs);
                (corr, y)
            }
        };
        let ((c0, y0), (c1, y1)) = run_two_party(party(0, x0), party(1, x1));
        ([c0, c1], [y0, y1], x)
    }

    #[test]
    fn correlations_hold() {
        let ([c0, c1], ..) = run_pair(3, 2);
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
    fn shared_eval_matches_clear() {
        let (_, [y0, y1], x) = run_pair(5, 3);
        for k in 0..x.len() {
            let want = lpn_prg().eval(x[k]);
            assert_eq!([y0[k][0] ^ y1[k][0], y0[k][1] ^ y1[k][1]], want, "call {k}");
            assert_eq!([lpn_prg().eval_side(x[k], 0), lpn_prg().eval_side(x[k], 1)], want, "eval_side {k}");
        }
    }
}
