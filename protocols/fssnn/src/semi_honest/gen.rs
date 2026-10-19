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
//! After all n levels the final word ([`crate::tree::Group`]) is opened. FssNN's
//! DCF output bit `v` becomes this BGI16-style final word for the DPF:
//!
//! * [`Group::Xor`]: `Conv(s_0) ⊕ Conv(s_1) ⊕ β` is linear in the shares, so it
//!   costs no AND, only the ℓ-bit opening (FssNN's final bit for ℓ = 1).
//! * [`Group::Arith`]: `(−1)^{t_1}·(β − Conv(s_0) + Conv(s_1))` with β
//!   additively shared in Z_2^ℓ. The α-leaves are XOR-shared, so each of the
//!   2ℓ bits of `Conv(s_0)`, `Conv(s_1)` is converted to an additive share of
//!   `2^i·bit` with one F_MUX^{A,ℓ} (selector the shared bit, `W0 = 0`,
//!   `W1 = 2^i`); a second F_MUX^{A,ℓ} on `t_1` picks `W` or `−W`. Both are
//!   SIRNN's MUX (as [`dpf_common::arith::mux`] in `floram-arith`, here
//!   [`crate::word::mux`] for words up to 256 bits). This output group is not
//!   in FssNN.
//!
//! For ℓ > λ = 127 the seed is too short for `Conv`, which then takes ℓ bits
//! of `G(s)`: two more F_SecPRG calls (one per tree, in one batch of two
//! rounds) on the shared α-leaves, with their correlations preprocessed with
//! the others. `Conv` is linear in G's output, so it maps the XOR shares
//! directly.
//!
//! FssNN's early termination (§3.3.2) is not used, so the full tree is
//! expanded as in the other protocols.
//!
//! Correlations for all `2n` PRG evaluations are generated up front from
//! OT (DGH+21 §5.5), so no dealer is involved anywhere. They, the `2n` AND
//! triples and the Ferret COTs of the MUXes form the preprocessing phase
//! ([`precompute`]), before α and β are used; Gen then derandomises the
//! COTs with one bit each.

use super::key::FssKey;
use super::sec_prg::{eval_shared, preprocess, PrgCorr};
use crate::tree::{child, conv, conv_prg, expand, CorrectionWord, Group, SEED_BITS};
use crate::word::{mux, Word};
use dpf_common::block::{depth_for, Block};
use dpf_common::bool2pc::{mux_block, rot_triples, BoolParty};
use dpf_common::net::{Channel, CommStats};
use dpf_common::ot::{CotPair, FerretConfig};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use std::time::{Duration, Instant};

/// Everything one party gets out of [`gen`].
pub struct GenOutput {
    pub key: FssKey,
    pub setup_stats: CommStats,
    /// Preprocessing: PRG correlations, triples and MUX COTs ([`precompute`]).
    pub pre_stats: CommStats,
    pub gen_stats: CommStats,
    /// F_AND invocations (state bits).
    pub and_gates: usize,
    /// COTs used (MUXes and the Z3 OTs of the PRG correlations, both directions).
    pub cots: usize,
    /// 2PC evaluations of the PRG.
    pub prg_calls: usize,
    pub setup_time: Duration,
    pub pre_time: Duration,
    pub gen_time: Duration,
}

/// The correlations one generation consumes.
pub struct Pre {
    /// For the PRG evaluations: two per level, plus two for `Conv` if ℓ > λ.
    pub prg: Vec<PrgCorr>,
    /// The `2n` AND triples of step 7.
    pub bp: BoolParty,
}

/// Preprocessing for a domain of depth `n`: the PRG correlations, the `2n`
/// triples (F_GenMT from Ferret, FssNN §2.2) and Ferret COTs per direction
/// for the MUXes, 3 per level (step 5 and both step-7 selections) plus
/// 2ℓ + 1 for the arithmetic final word.
pub fn precompute(ch: &mut Channel, cot: &mut CotPair, n: usize, group: Group, bits: usize, rng: &mut ChaCha20Rng) -> Pre {
    let mut tweak = 0;
    let calls = 2 * n + if bits > SEED_BITS { 2 } else { 0 };
    let prg = preprocess(ch, cot, calls, &mut tweak, rng);
    let triples = rot_triples(ch, cot, 2 * n, rng);
    let bp = BoolParty::with_triples(ch.party(), triples, rng);
    let muxes = 3 * n + if group == Group::Arith { 2 * bits + 1 } else { 0 };
    cot.precompute(ch, muxes, muxes, rng).expect("semi-honest COT");
    Pre { prg, bp }
}

/// Opens an ℓ-bit word, XOR- or additively shared per `group`.
fn open_word(ch: &mut Channel, group: Group, bits: usize, x: Word) -> Word {
    ch.send(x.to_bytes(bits));
    let theirs = ch.recv();
    assert_eq!(theirs.len(), bits.div_ceil(8), "malformed final-word share");
    let y = Word::from_bytes(&theirs);
    match group {
        Group::Xor => x ^ y,
        Group::Arith => (x + y).masked(bits),
    }
}

/// This party's share of the final word from its shares of both α-leaves.
/// For ℓ > λ, `prg` holds the two correlations for `Conv` through G.
#[allow(clippy::too_many_arguments)]
fn final_cw(
    ch: &mut Channel,
    cot: &mut CotPair,
    rng: &mut ChaCha20Rng,
    group: Group,
    bits: usize,
    leaves: [Block; 2],
    beta_share: Word,
    prg: &[PrgCorr],
) -> Word {
    let (c0, c1) = if bits <= SEED_BITS {
        (conv(leaves[0], bits), conv(leaves[1], bits))
    } else {
        // F_SecPRG on both α-leaves; Conv is linear in G's output.
        let y = eval_shared(ch, prg, &[leaves[0].0 & !1, leaves[1].0 & !1]);
        let c = |k: usize| conv_prg([Block(y[k][0]), Block(y[k][1])], bits);
        (c(0), c(1))
    };
    let share = match group {
        Group::Xor => c0 ^ c1 ^ beta_share,
        Group::Arith => {
            let b = ch.party();
            // B2A: additive shares of 2^i·bit_i, party 0 holding W1 = 2^i.
            let g: Vec<bool> = [c0, c1].iter().flat_map(|&c| (0..bits).map(move |i| c.bit(i))).collect();
            let w1: Vec<Word> = (0..2 * bits).map(|k| if b == 0 { Word::pow2(k % bits) } else { Word::ZERO }).collect();
            let y = mux(ch, cot, &g, &vec![Word::ZERO; 2 * bits], &w1, bits, rng).expect("semi-honest MUX");
            let sum = |ys: &[Word]| ys.iter().fold(Word::ZERO, |a, &v| a + v);
            let w = (beta_share - sum(&y[..bits]) + sum(&y[bits..])).masked(bits);
            // (−1)^{t_1}·W.
            mux(ch, cot, &[leaves[1].lsb()], &[w], &[(-w).masked(bits)], bits, rng).expect("semi-honest MUX")[0]
        }
    };
    open_word(ch, group, bits, share)
}

#[allow(clippy::too_many_arguments)]
fn gen_with(
    cot: &mut CotPair,
    pre: Pre,
    rng: &mut ChaCha20Rng,
    ch: &mut Channel,
    root: Block,
    n_size: u64,
    group: Group,
    bits: usize,
    alpha_share: u64,
    beta_share: Word,
) -> (FssKey, usize, usize) {
    let b = ch.party();
    let n = depth_for(n_size);
    let Pre { prg: corr, mut bp } = pre;
    let calls = corr.len();
    let bp = &mut bp;

    // Step 2: ⟨s_j^(0)⟩, own root, zero share of the peer's.
    let mut node = [Block::ZERO; 2];
    node[b] = root;
    let mut cws = Vec::with_capacity(n);
    for i in 0..n {
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

    let fcw = final_cw(ch, cot, rng, group, bits, node, beta_share, &corr[2 * n..]);
    (FssKey { party: b, n_size, group, bits, root, cws, fcw }, calls, bp.ands)
}

/// A root with `t = party` (Alg. 4 line 2).
fn sample_root(rng: &mut ChaCha20Rng, party: usize) -> Block {
    Block((rng.gen::<u128>() & !1) | party as u128)
}

/// Runs this party's side of the generation.
///
/// * `group`, `bits`: the output group and its width ℓ, `1 ≤ ℓ ≤ 256`.
/// * `alpha_share`: XOR share of `α < N` (bit `n − 1 − i` is level i).
/// * `beta_share`: share of `β` in the output group (XOR or mod 2^ℓ).
/// * `ferret`: the silent-OT parameters. Setup bootstraps Ferret on the
///   `CotPair`, so every COT of Gen (the LPN-PRG correlations and the MUXes)
///   is a Ferret COT. `FerretConfig::B13` for benchmarks, `TOY` for tests.
pub fn gen(ch: &mut Channel, n_size: u64, group: Group, bits: usize, alpha_share: u64, beta_share: Word, seed: [u8; 32], ferret: FerretConfig) -> GenOutput {
    let t_setup = Instant::now();
    let mut rng = ChaCha20Rng::from_seed(seed);
    let root = sample_root(&mut rng, ch.party());
    let delta = Block::random(&mut rng);
    let mut cot = CotPair::setup(ch, &mut rng, delta, false).expect("semi-honest base OT");
    cot.enable_ferret(ch, ferret, &mut rng).expect("semi-honest Ferret");
    ch.sync();
    let setup_stats = ch.stats();
    let setup_time = t_setup.elapsed();
    let t_pre = Instant::now();
    let pre = precompute(ch, &mut cot, depth_for(n_size), group, bits, &mut rng);
    let pre_stats = ch.stats().since(&setup_stats);
    let pre_time = t_pre.elapsed();
    // Timing only: neither party's gen time includes waiting for the other's
    // preprocessing. Counted in no phase.
    ch.sync();
    let gen_start = ch.stats();
    let t_gen = Instant::now();
    let (key, prg_calls, and_gates) = gen_with(&mut cot, pre, &mut rng, ch, root, n_size, group, bits, alpha_share, beta_share);
    GenOutput {
        key,
        gen_stats: ch.stats().since(&gen_start),
        setup_stats,
        pre_stats,
        and_gates,
        cots: cot.produced,
        prg_calls,
        setup_time,
        pre_time,
        gen_time: t_gen.elapsed(),
    }
}

/// Trusted-dealer generation for given roots (bit 0 of root b must be b): the
/// cleartext Gen, and the bit-exact oracle of [`gen`].
pub fn deal(roots: [Block; 2], n_size: u64, group: Group, bits: usize, alpha: u64, beta: Word) -> [FssKey; 2] {
    assert!(alpha < n_size);
    assert_eq!(beta, beta.masked(bits), "β must fit in the output width");
    assert!(!roots[0].lsb() && roots[1].lsb(), "t_b^(0) = b");
    let n = depth_for(n_size);
    let mut node = roots;
    let mut cws = Vec::with_capacity(n);
    for i in 0..n {
        let a = (alpha >> (n - 1 - i)) & 1 == 1;
        let (g0, g1) = (expand(node[0]), expand(node[1]));
        let lose = !a as usize;
        let d = [g0[0] ^ g1[0], g0[1] ^ g1[1]];
        let cw = CorrectionWord { s: Block(d[lose].0 & !1), t:[d[0].lsb() ^ a ^ true, d[1].lsb() ^ a] };
        node = [child(node[0], &cw, a), child(node[1], &cw, a)];
        cws.push(cw);
    }
    assert!(node[0].lsb() ^ node[1].lsb(), "α-node state bits must differ");
    let fcw = group.final_cw(bits, node, beta);
    let mk = |party: usize| FssKey { party, n_size, group, bits, root: roots[party], cws: cws.clone(), fcw };
    [mk(0), mk(1)]
}

/// Trusted-dealer generation from a seed.
pub fn gen_reference(n_size: u64, group: Group, bits: usize, alpha: u64, beta: Word, seed: [u8; 32]) -> [FssKey; 2] {
    let mut rng = ChaCha20Rng::from_seed(seed);
    let roots = [sample_root(&mut rng, 0), sample_root(&mut rng, 1)];
    deal(roots, n_size, group, bits, alpha, beta)
}
