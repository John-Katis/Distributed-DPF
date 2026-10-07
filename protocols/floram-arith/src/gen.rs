//! Dealer-less DPF key generation with arithmetic inputs and outputs, as in
//! Xing et al., "Distributed Function Secret Sharing and Applications"
//! (NDSS'25, §IV-A, Alg. 1 and 2), on top of the Floram-CPRG tree.
//!
//! 1. **A2B.** `α` is additively shared over Z_2^n. Each party feeds its share
//!    into the garbled circuit, and a ripple-carry adder (n−1 AND gates)
//!    produces the bits of `α`. They stay as wires and are never revealed (the
//!    paper's ΠBitDec computes the same carries with AND/OR on Boolean shares).
//! 2. **Tree.** Floram's per-level circuit selects the correction word
//!    `(σ_i, τ_{i,0}, τ_{i,1})` with the secret bit `α_i` (Alg. 2 lines 3–15).
//! 3. **Final correction word** (lines 16–22): `w_b = Σ_j Convert(s^j_b)` and the
//!    integer `T_b = Σ_j t^j_b`. Off-path leaves cancel, so `|T_0 − T_1| = 1`, and
//!    CCMP (Alg. 1, one AND gate) yields XOR shares of `g = 1{T_0 < T_1}`, i.e.
//!    of `t_1` at the α-leaf. With
//!    `W⁰_b = β_b + (−1)^{1−b} w_b` and `W¹_b = −β_b + (−1)^b w_b`, the arithmetic
//!    MUX gives shares of `W_CW = W^g = (−1)^{t_1}(β − Convert(s_0) + Convert(s_1))`,
//!    which are then opened.

use crate::key::ArithKey;
use dpf_common::arith::{convert, mask, mux, signed};
use dpf_common::block::{depth_for, Block};
use dpf_common::gc::{Evaluator, GcParty, Garbler, Wire};
use dpf_common::net::{Channel, CommStats};
use dpf_common::ot::CotPair;
use dpf_common::prg::Prg;
use floram_cprg::cprg::{level_circuit, CprgLocal};
use floram_cprg::CorrectionWord;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::time::{Duration, Instant};

/// Everything one party gets out of [`gen`].
pub struct GenOutput {
    pub key: ArithKey,
    /// Full-domain output shares, a by-product of generation.
    pub full: Vec<u64>,
    pub setup_stats: CommStats,
    pub gen_stats: CommStats,
    pub and_gates: usize,
    /// COTs used by the arithmetic MUX (both directions).
    pub cots: usize,
    pub setup_time: Duration,
    pub gen_time: Duration,
}

/// Bits `[x_0, …, x_{n−1}]` of `x`, least significant first.
fn bits_lsb_first(x: u64, n: usize) -> Vec<bool> {
    (0..n).map(|i| (x >> i) & 1 == 1).collect()
}

/// A2B: wires for the bits of `a_0 + a_1 mod 2^n`, most significant first.
fn a2b<P: GcParty>(p: &mut P, ch: &mut Channel, share: u64, n: usize) -> Vec<Wire> {
    let mine = bits_lsb_first(share, n);
    let zeros = vec![false; n];
    let input = if ch.party() == 0 { [mine, zeros].concat() } else { [zeros, mine].concat() };
    let w = p.input_shared(ch, &input);
    let (x, y) = w.split_at(n);
    let mut sum = Vec::with_capacity(n);
    let mut carry: Option<Wire> = None;
    for i in 0..n {
        let xy = p.xor(x[i], y[i]);
        sum.push(match carry {
            Some(c) => p.xor(xy, c),
            None => xy,
        });
        if i + 1 < n {
            // c_{i+1} = maj(x_i, y_i, c_i) = c_i ⊕ (x_i ⊕ c_i)(y_i ⊕ c_i), and x_0·y_0 for i = 0.
            carry = Some(match carry {
                Some(c) => {
                    let a = p.and_many(ch, &[(p.xor(x[i], c), p.xor(y[i], c))])[0];
                    p.xor(a, c)
                }
                None => p.and_many(ch, &[(x[i], y[i])])[0],
            });
        }
    }
    sum.reverse();
    sum
}

/// CCMP (NDSS'25 Alg. 1): XOR shares of `1{T_0 < T_1}` for integers with
/// `|T_0 − T_1| = 1`, from their last two bits and one AND gate. The gate output
/// stays shared: with `lsb(R) = 1`, the garbler's 0-label and the evaluator's
/// active label have lsbs that XOR to the wire's value.
fn ccmp<P: GcParty>(p: &mut P, ch: &mut Channel, t_count: u64) -> bool {
    let b = ch.party() == 1;
    let (h, l) = ((t_count >> 1) & 1 == 1, t_count & 1 == 1);
    let w = p.input_shared(ch, &[h, h ^ l ^ b]);
    let t = p.and_many(ch, &[(w[0], w[1])])[0];
    t.lsb() ^ (l && b)
}

/// One party's tree randomness (PRG keys, root) and protocol randomness, split
/// as in floram-cprg so the dealer can reproduce the tree.
fn party_rngs(seed: [u8; 32]) -> (ChaCha20Rng, ChaCha20Rng) {
    let tree = ChaCha20Rng::from_seed(seed);
    let mut proto = ChaCha20Rng::from_seed(seed);
    proto.set_stream(1);
    (tree, proto)
}

fn sample_root(rng: &mut ChaCha20Rng, party: usize) -> Block {
    let r = Block::random(rng);
    Block((r.0 & !1) | party as u128)
}

#[allow(clippy::too_many_arguments)]
fn gen_with<P: GcParty>(
    p: &mut P,
    cot: &mut CotPair,
    rng: &mut ChaCha20Rng,
    ch: &mut Channel,
    prg: Prg,
    root: Block,
    n_size: u64,
    bits: usize,
    alpha_share: u64,
    beta_share: u64,
) -> (ArithKey, Vec<u64>) {
    let b = ch.party();
    let n = depth_for(n_size);
    let m = mask(bits);

    // 1. A2B.
    let alpha = a2b(p, ch, alpha_share, n);

    // 2. Floram tree with GC-selected correction words.
    let (mut local, mut acc) = CprgLocal::start(prg.clone(), n_size, 1, root);
    let mut cws: Vec<CorrectionWord> = Vec::with_capacity(n);
    for &alpha_j in &alpha {
        let cw = level_circuit(p, ch, alpha_j, acc);
        cws.push(cw);
        if let Some(next) = local.step(cw.z, cw.tau_l, cw.tau_r) {
            acc = next;
        }
    }
    local.finalize();

    // 3. Final correction word.
    let (seeds, ts) = local.leaves();
    let w = seeds.iter().fold(0u64, |a, s| a.wrapping_add(convert(*s, bits))) & m;
    let t_count = ts.iter().filter(|t| **t).count() as u64;
    let g = ccmp(p, ch, t_count);
    let w0 = beta_share.wrapping_add(signed(b == 0, w, bits)) & m;
    let w1 = beta_share.wrapping_neg().wrapping_add(signed(b == 1, w, bits)) & m;
    let wcw_share = mux(ch, cot, &[g], &[w0], &[w1], bits, rng).expect("semi-honest MUX")[0];
    ch.send(wcw_share.to_le_bytes().to_vec());
    let theirs = u64::from_le_bytes(ch.recv().try_into().expect("8-byte share"));
    let w_cw = wcw_share.wrapping_add(theirs) & m;

    let key = ArithKey { party: b, n_size, bits, prg, root, cws, w_cw };
    let (seeds, ts) = local.leaves();
    let full = seeds.iter().zip(ts).map(|(s, t)| key.output(*s, *t)).collect();
    (key, full)
}

/// Runs this party's side of the generation.
///
/// * `alpha_share`: additive share of `α < N` modulo `2^n`, `n = ceil(log2 N)`.
/// * `beta_share`: additive share of `β` modulo `2^bits`, `1 ≤ bits ≤ 64`.
pub fn gen(ch: &mut Channel, n_size: u64, bits: usize, alpha_share: u64, beta_share: u64, seed: [u8; 32]) -> GenOutput {
    let party = ch.party();
    let t_setup = Instant::now();
    let (mut rng_tree, mut rng) = party_rngs(seed);
    let prg = if party == 0 {
        let (kl, kr) = (Block::random(&mut rng_tree), Block::random(&mut rng_tree));
        ch.send_blocks(&[kl, kr]);
        Prg::new(kl, kr)
    } else {
        let k = ch.recv_blocks(2);
        Prg::new(k[0], k[1])
    };
    let root = sample_root(&mut rng_tree, party);
    let delta = Block::random(&mut rng);

    let setup = |ch: &mut Channel| {
        ch.sync();
        (ch.stats(), t_setup.elapsed(), Instant::now())
    };
    let (key, full, setup_stats, setup_time, t_gen, and_gates, cots) = if party == 0 {
        let mut g = Garbler::setup(ch, &mut rng);
        let mut cot = CotPair::setup(ch, &mut rng, delta, false);
        let (s, st, tg) = setup(ch);
        let (k, f) = gen_with(&mut g, &mut cot, &mut rng, ch, prg, root, n_size, bits, alpha_share, beta_share);
        (k, f, s, st, tg, g.and_count(), cot.produced)
    } else {
        let mut e = Evaluator::setup(ch, &mut rng);
        let mut cot = CotPair::setup(ch, &mut rng, delta, false);
        let (s, st, tg) = setup(ch);
        let (k, f) = gen_with(&mut e, &mut cot, &mut rng, ch, prg, root, n_size, bits, alpha_share, beta_share);
        (k, f, s, st, tg, e.and_count(), cot.produced)
    };
    GenOutput {
        key,
        full,
        gen_stats: ch.stats().since(&setup_stats),
        setup_stats,
        and_gates,
        cots,
        setup_time,
        gen_time: t_gen.elapsed(),
    }
}

/// Trusted-dealer generation for given PRG and root shares (the plaintext
/// version of [`gen`], used as its bit-exact oracle).
pub fn deal(prg: &Prg, roots: [Block; 2], n_size: u64, bits: usize, alpha: u64, beta: u64) -> [ArithKey; 2] {
    assert!(alpha < n_size);
    assert_ne!(roots[0].lsb(), roots[1].lsb(), "root t-bits must differ");
    let n = depth_for(n_size);
    let m = mask(bits);
    let (mut l0, mut a0) = CprgLocal::start(prg.clone(), n_size, 1, roots[0]);
    let (mut l1, mut a1) = CprgLocal::start(prg.clone(), n_size, 1, roots[1]);
    let mut cws = Vec::with_capacity(n);
    for (j, aj) in dpf_common::block::bits_msb_first(alpha, n).into_iter().enumerate() {
        let (dl, dr) = (a0.0 ^ a1.0, a0.1 ^ a1.1);
        let cw = CorrectionWord { z: if aj { dl } else { dr }, tau_l: dl.lsb() ^ aj ^ true, tau_r: dr.lsb() ^ aj };
        cws.push(cw);
        let n0 = l0.step(cw.z, cw.tau_l, cw.tau_r);
        let n1 = l1.step(cw.z, cw.tau_l, cw.tau_r);
        if j + 1 < n {
            a0 = n0.unwrap();
            a1 = n1.unwrap();
        }
    }
    l0.finalize();
    l1.finalize();
    let i = alpha as usize;
    let (s0, t0) = (l0.leaves().0[i], l0.leaves().1[i]);
    let (s1, t1) = (l1.leaves().0[i], l1.leaves().1[i]);
    assert!(t0 ^ t1, "α-leaf t-bits must differ");
    let base = beta.wrapping_sub(convert(s0, bits)).wrapping_add(convert(s1, bits));
    let w_cw = signed(t1, base, bits) & m;
    let mk = |party: usize| ArithKey { party, n_size, bits, prg: prg.clone(), root: roots[party], cws: cws.clone(), w_cw };
    [mk(0), mk(1)]
}

/// Trusted-dealer generation from a seed.
pub fn gen_reference(n_size: u64, bits: usize, alpha: u64, beta: u64, seed: [u8; 32]) -> [ArithKey; 2] {
    let mut rng = ChaCha20Rng::from_seed(seed);
    let prg = Prg::new(Block::random(&mut rng), Block::random(&mut rng));
    let roots = [sample_root(&mut rng, 0), sample_root(&mut rng, 1)];
    deal(&prg, roots, n_size, bits, alpha, beta)
}
