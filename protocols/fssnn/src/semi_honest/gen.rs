//! Key generation: the cleartext Gen (FssNN Alg. 4 without `v`) and the
//! dealer-less Π_GenDCF of Alg. 5, adapted to the DPF.
//!
//! Alg. 5 keeps the on-path nodes of *both* trees secret-shared: party b
//! samples its root `s_b^(0)` with `t_b^(0) = b` and shares it (here the
//! trivial sharing `(s, 0)`), so every level is a 2PC on XOR shares:
//!
//! 1. Step 4, F_SecPRG on `⟨s_0^(i−1)⟩` and `⟨s_1^(i−1)⟩`: the LPN-PRG 2PC of
//!    [`super::sec_prg`]. (Step 4 prints `s^L ∥ v^L ∥ t^L ∥ s^L ∥ v^L ∥ t^L`; the
//!    second half is the right child.)
//! 2. Step 5, F_2PC for the CW: `s_CW = s_0^Lose ⊕ s_1^Lose` with Lose = L iff
//!    α_i = 1, i.e. one F_MUX^{B,λ} on `(D^R, D^L)` with selector α_i
//!    (`D^p = s_0^p ⊕ s_1^p`); `t^L_CW = t_0^L ⊕ t_1^L ⊕ α_i ⊕ 1` and
//!    `t^R_CW = t_0^R ⊕ t_1^R ⊕ α_i` are linear. All three are opened.
//! 3. Step 7, F_2PC for the next node of each tree:
//!    `s_j^(i) = s_j^Keep ⊕ t_j^(i−1)·s_CW` (MUX on α_i, run in the same batch
//!    as step 2; the product with public `s_CW` is local) and
//!    `t_j^(i) = t_j^Keep ⊕ t_j^(i−1)·t^Keep_CW` (one F_AND per tree, since
//!    `t^Keep_CW` is public but selected by the shared α_i).
//!
//! After `υ` levels the final word `Conv(s_0) ⊕ Conv(s_1) ⊕ β·e_{α_low}` is
//! opened, with the shared one-hot vector of the low `n − υ` bits of α built
//! by an AND tree. FssNN's DCF output bit `v` and its early-termination word
//! (which packs the `v^L_CW` of the cut levels) become this BGI16-style final
//! word for the DPF.
//!
//! Correlations for all `2υ` PRG evaluations are generated up front from
//! OT (DGH+21 §5.5), so no dealer is involved anywhere.

use super::key::FssKey;
use super::sec_prg::{eval_shared, preprocess, Kk};
use crate::tree::{child, conv, expand, levels_for, CorrectionWord, PACK_BITS};
use dpf_common::block::{depth_for, Block};
use dpf_common::bool2pc::{mux_block, BoolParty};
use dpf_common::net::{Channel, CommStats};
use dpf_common::ot::CotPair;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use std::time::{Duration, Instant};

/// Everything one party gets out of [`gen`].
pub struct GenOutput {
    pub key: FssKey,
    pub setup_stats: CommStats,
    pub gen_stats: CommStats,
    /// F_AND invocations (state bits, one-hot vector).
    pub and_gates: usize,
    /// COTs used (MUXes and the Z3 OTs of the PRG correlations, both directions).
    pub cots: usize,
    /// 2PC evaluations of the PRG.
    pub prg_calls: usize,
    pub setup_time: Duration,
    pub gen_time: Duration,
}

/// Opens XOR-shared 64-bit words.
fn open_u64(ch: &mut Channel, x: u64) -> u64 {
    ch.send(x.to_le_bytes().to_vec());
    x ^ u64::from_le_bytes(ch.recv().try_into().expect("8-byte share"))
}

/// XOR shares of `β·e_k` for `k ∈ [2^l]`, `k` = the low `l` bits of α, as a
/// 64-bit mask.
fn one_hot(bp: &mut BoolParty, ch: &mut Channel, alpha_low: u64, l: usize, beta: bool) -> u64 {
    let mut v = vec![bp.constant(true)];
    for k in (0..l).rev() {
        let a = (alpha_low >> k) & 1 == 1;
        let pa = bp.and_many(ch, &v.iter().map(|&p| (p, a)).collect::<Vec<_>>());
        v = v.iter().zip(&pa).flat_map(|(&p, &q)| [p ^ q, q]).collect();
    }
    let e = bp.and_many(ch, &v.iter().map(|&p| (p, beta)).collect::<Vec<_>>());
    e.iter().enumerate().fold(0, |m, (k, &b)| m | (b as u64) << k)
}

#[allow(clippy::too_many_arguments)]
fn gen_with(
    bp: &mut BoolParty,
    cot: &mut CotPair,
    kk: &mut Kk,
    rng: &mut ChaCha20Rng,
    ch: &mut Channel,
    root: Block,
    n_size: u64,
    alpha_share: u64,
    beta_share: bool,
) -> (FssKey, usize) {
    let b = ch.party();
    let n = depth_for(n_size);
    let ups = levels_for(n);
    let mut tweak = 0;
    let corr = preprocess(ch, cot, kk, 2 * ups, &mut tweak, rng);

    // Step 2: ⟨s_j^(0)⟩, own root, zero share of the peer's.
    let mut node = [Block::ZERO; 2];
    node[b] = root;
    let mut cws = Vec::with_capacity(ups);
    for i in 0..ups {
        let a = (alpha_share >> (n - 1 - i)) & 1 == 1;
        // Step 4.
        let y = eval_shared(ch, &corr[2 * i..2 * i + 2], &[node[0].0 & !1, node[1].0 & !1]);
        let (l, r) = ([Block(y[0][0]), Block(y[1][0])], [Block(y[0][1]), Block(y[1][1])]);
        let (dl, dr) = (l[0] ^ l[1], r[0] ^ r[1]);
        // Steps 5 and 7: Lose-side difference and both Keep children.
        let m = mux_block(ch, cot, a, &[dr, l[0], l[1]], &[dl, r[0], r[1]], rng).expect("semi-honest MUX");
        let tl = dl.lsb() ^ a ^ bp.constant(true);
        let tr = dr.lsb() ^ a;
        let mut msg = (m[0].0 & !1).to_le_bytes().to_vec();
        msg.push(tl as u8 | (tr as u8) << 1);
        ch.send(msg);
        let theirs = ch.recv();
        assert_eq!(theirs.len(), 17, "malformed correction-word share");
        let cw = CorrectionWord {
            s: Block((m[0].0 & !1) ^ Block::from_bytes(&theirs[..16]).0),
            t: [tl ^ (theirs[16] & 1 == 1), tr ^ (theirs[16] & 2 == 2)],
        };
        // Step 7.
        let tkeep = bp.constant(cw.t[0]) ^ (a & (cw.t[0] ^ cw.t[1]));
        let ands = bp.and_many(ch, &[(node[0].lsb(), tkeep), (node[1].lsb(), tkeep)]);
        for j in 0..2 {
            node[j] = m[1 + j] ^ cw.s.and_bit(node[j].lsb()) ^ Block(ands[j] as u128);
        }
        cws.push(cw);
    }

    let lb = n - ups;
    debug_assert!(lb <= PACK_BITS);
    let e = one_hot(bp, ch, alpha_share & ((1 << lb) - 1), lb, beta_share);
    let fcw = open_u64(ch, conv(node[0]) ^ conv(node[1]) ^ e);
    (FssKey { party: b, n_size, root, cws, fcw }, 2 * ups)
}

/// A root with `t = party` (Alg. 4 line 2).
fn sample_root(rng: &mut ChaCha20Rng, party: usize) -> Block {
    Block((rng.gen::<u128>() & !1) | party as u128)
}

/// Runs this party's side of the generation.
///
/// * `alpha_share`: XOR share of `α < N` (bit `n − 1 − i` is level i).
/// * `beta_share`: XOR share of `β ∈ Z2`.
pub fn gen(ch: &mut Channel, n_size: u64, alpha_share: u64, beta_share: bool, seed: [u8; 32]) -> GenOutput {
    let t_setup = Instant::now();
    let mut rng = ChaCha20Rng::from_seed(seed);
    let root = sample_root(&mut rng, ch.party());
    let delta = Block::random(&mut rng);
    let mut cot = CotPair::setup(ch, &mut rng, delta, false).expect("semi-honest base OT");
    let mut bp = BoolParty::setup(ch, &mut rng);
    let mut kk = Kk::setup(ch, &mut rng);
    ch.sync();
    let setup_stats = ch.stats();
    let setup_time = t_setup.elapsed();
    let t_gen = Instant::now();
    let (key, prg_calls) = gen_with(&mut bp, &mut cot, &mut kk, &mut rng, ch, root, n_size, alpha_share, beta_share);
    GenOutput {
        key,
        gen_stats: ch.stats().since(&setup_stats),
        setup_stats,
        and_gates: bp.ands,
        cots: cot.produced,
        prg_calls,
        setup_time,
        gen_time: t_gen.elapsed(),
    }
}

/// Trusted-dealer generation for given roots (bit 0 of root b must be b): the
/// cleartext Gen, and the bit-exact oracle of [`gen`].
pub fn deal(roots: [Block; 2], n_size: u64, alpha: u64, beta: bool) -> [FssKey; 2] {
    assert!(alpha < n_size);
    assert!(!roots[0].lsb() && roots[1].lsb(), "t_b^(0) = b");
    let n = depth_for(n_size);
    let ups = levels_for(n);
    let mut node = roots;
    let mut cws = Vec::with_capacity(ups);
    for i in 0..ups {
        let a = (alpha >> (n - 1 - i)) & 1 == 1;
        let (g0, g1) = (expand(node[0]), expand(node[1]));
        let lose = !a as usize;
        let d = [g0[0] ^ g1[0], g0[1] ^ g1[1]];
        let cw = CorrectionWord { s: Block(d[lose].0 & !1), t:[d[0].lsb() ^ a ^ true, d[1].lsb() ^ a] };
        node = [child(node[0], &cw, a), child(node[1], &cw, a)];
        cws.push(cw);
    }
    assert!(node[0].lsb() ^ node[1].lsb(), "α-node state bits must differ");
    let low = alpha & ((1 << (n - ups)) - 1);
    let fcw = conv(node[0]) ^ conv(node[1]) ^ ((beta as u64) << low);
    let mk = |party: usize| FssKey { party, n_size, root: roots[party], cws: cws.clone(), fcw };
    [mk(0), mk(1)]
}

/// Trusted-dealer generation from a seed.
pub fn gen_reference(n_size: u64, alpha: u64, beta: bool, seed: [u8; 32]) -> [FssKey; 2] {
    let mut rng = ChaCha20Rng::from_seed(seed);
    let roots = [sample_root(&mut rng, 0), sample_root(&mut rng, 1)];
    deal(roots, n_size, alpha, beta)
}
