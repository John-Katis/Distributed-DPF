//! Dealer-less DPF key generation with arithmetic input and output (Xing et
//! al., "Distributed Function Secret Sharing and Applications", NDSS'25,
//! Alg. 1, 2 and 14), following the authors' reference implementation
//! (`keyGenDPF` in `src/legacy/dpf.cpp` of xingpz2008/dealerless-FSS_public).
//!
//! 1. **BitDec** (Alg. 14, line 1): from the LSB, `y[i] = x_b[i] ⊕ q` and the
//!    carry `q := OR(AND(x_0[i], x_1[i]), AND(x[i], q))`, three F_AND calls
//!    per bit (the reference's `check_bit_overflow`). Alg. 14 line 3 prints
//!    "∧ q"; the sum bit is "⊕ q", which is what the reference computes.
//! 2. **Layer CWs** (lines 3–15): `S^{i,p}_b` is the XOR of all left (p = 0)
//!    or right (p = 1) children. `σ_b = F_MUX^{B,λ}(S^{i,0}_b, S^{i,1}_b, α_b ⊕ b)`
//!    selects the off-path side, `τ^{i,0}_b = lsb(S^{i,0}_b) ⊕ α_b ⊕ b` and
//!    `τ^{i,1}_b = lsb(S^{i,1}_b) ⊕ α_b` are local, and `(σ, τ_0, τ_1)` is
//!    revealed in one round. The lsb of a block is its control bit `t`, so
//!    σ is the `s` part only (lsb 0), as Alg. 2's `s ∥ t` split prescribes.
//! 3. **Final CW** (lines 16–22): `w_b = Σ Convert(s_b)` over the leaves (line
//!    16 says level `ℓ_in − 1`, but line 17, Alg. 3 and the reference use the
//!    leaves) and the integer `T_b = Σ t_b`, which differ by exactly one between
//!    the parties. CCMP (Alg. 1, one F_AND) gives XOR shares of
//!    `g = 1{T_0 < T_1}`, i.e. of `t_1` at the α-leaf, and
//!    `W_CW = F_MUX^{A,ℓ}(β_b + (−1)^{1−b}w_b, −β_b + (−1)^b w_b, g)`
//!    `= (−1)^{t_1}(β − Convert(s_0) + Convert(s_1))` is revealed.
//!
//! The 2PC functionalities are those of App. A: F_AND from CrypTFlow2 bit
//! triples ([`dpf_common::bool2pc`]), F_MUX^{B,λ} from two parallel COTs and
//! F_MUX^{A,ℓ} as in SIRNN ([`dpf_common::arith::mux`]), all over semi-honest
//! IKNP / KK13 OT extension.
//!
//! `Convert` reads the ℓ bits of the leaf label above its control bit, as the
//! paper's `s∥t` split implies ([`crate::tree::conv`]; for ℓ = 128 one more
//! PRG call per leaf). All of Z_2^ℓ is computed and sent in words of the
//! [`Ring`] type `R`: 64-bit words for ℓ ≤ 64 (the reference's `uint64_t`),
//! 128-bit words for 64 < ℓ ≤ 128. The reference converts the low ℓ bits
//! including the control bit; then `lsb(W_CW) = lsb(β) ⊕ τ^{n−1,0} ⊕ τ^{n−1,1} ⊕ 1`,
//! which reveals the lsb of β, so we do not copy that.

use crate::key::ArithKey;
use crate::tree::{conv, ArithTree, CorrectionWord, Tree, TreeStream};
use dpf_common::arith::{mux, signed, Ring};
use dpf_common::block::{bits_msb_first, depth_for, Block};
use dpf_common::bool2pc::{mux_block, BoolParty};
use dpf_common::net::{Channel, CommStats};
use dpf_common::ot::CotPair;
use dpf_common::stream::TreeMode;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::time::{Duration, Instant};

/// Everything one party gets out of [`gen`].
pub struct GenOutput<R: Ring = u64> {
    pub key: ArithKey<R>,
    /// Full-domain output shares, a by-product of generation. `None` unless
    /// `full_output` was set, and always `None` with the streaming tree.
    pub full: Option<Vec<R>>,
    pub setup_stats: CommStats,
    pub gen_stats: CommStats,
    /// F_AND invocations (BitDec and CCMP).
    pub and_gates: usize,
    /// COTs used by the two MUXes (both directions).
    pub cots: usize,
    pub setup_time: Duration,
    pub gen_time: Duration,
}

/// Π_BitDec (Alg. 14): XOR shares of the bits of `x_0 + x_1 mod 2^n`, MSB
/// first.
fn bit_dec(bp: &mut BoolParty, ch: &mut Channel, share: u64, n: usize) -> Vec<bool> {
    let mut y = vec![false; n];
    let mut q = false;
    for i in 0..n {
        let x = (share >> i) & 1 == 1;
        y[n - 1 - i] = x ^ q;
        let t = bp.and_cross(ch, x);
        let u = bp.and1(ch, x, q);
        q = bp.or1(ch, t, u);
    }
    y
}

/// Π_CCMP (Alg. 1): XOR shares of `1{x_0 < x_1}` for integers with
/// `|x_0 − x_1| = 1`, with one F_AND.
fn ccmp(bp: &mut BoolParty, ch: &mut Channel, x: u64) -> bool {
    let b = bp.party() == 1;
    let (h, l) = ((x >> 1) & 1 == 1, x & 1 == 1);
    let t = bp.and1(ch, h, h ^ l ^ b);
    t ^ (l && b)
}

/// One party's tree randomness (root) and protocol randomness, split so the
/// dealer can reproduce the tree.
fn party_rngs(seed: [u8; 32]) -> (ChaCha20Rng, ChaCha20Rng) {
    let tree = ChaCha20Rng::from_seed(seed);
    let mut proto = ChaCha20Rng::from_seed(seed);
    proto.set_stream(1);
    (tree, proto)
}

#[allow(clippy::too_many_arguments)]
fn gen_with<R: Ring, T: ArithTree>(
    mode: TreeMode,
    full_output: bool,
    bp: &mut BoolParty,
    cot: &mut CotPair,
    rng: &mut ChaCha20Rng,
    ch: &mut Channel,
    root: Block,
    n_size: u64,
    bits: usize,
    alpha_share: u64,
    beta_share: R,
) -> (ArithKey<R>, Option<Vec<R>>) {
    let b = ch.party();
    let n = depth_for(n_size);
    let m = R::mask(bits);

    // Line 1: BitDec.
    let alpha = bit_dec(bp, ch, alpha_share, n);

    // Lines 2–15.
    let mut tree = T::new(n_size, root, b == 1, mode);
    let mut cws = Vec::with_capacity(n);
    for &a in &alpha {
        let (sl, sr) = tree.expand_level();
        // σ without its lsb, which would equal τ of the off-path side.
        let sigma = mux_block(ch, cot, a ^ (b == 1), &[sl.with_lsb(false)], &[sr.with_lsb(false)], rng).expect("semi-honest MUX")[0];
        let tau = [sl.lsb() ^ a ^ (b == 1), sr.lsb() ^ a];
        let mut msg = sigma.to_bytes().to_vec();
        msg.push(tau[0] as u8 | (tau[1] as u8) << 1);
        ch.send(msg);
        let theirs = ch.recv();
        assert_eq!(theirs.len(), 17, "malformed correction-word share");
        let cw = CorrectionWord {
            sigma: sigma ^ Block::from_bytes(&theirs[..16]),
            tau: [tau[0] ^ (theirs[16] & 1 == 1), tau[1] ^ (theirs[16] & 2 == 2)],
        };
        tree.correct(cw);
        cws.push(cw);
    }

    // Lines 16–22.
    let (w, t_count) = tree.leaf_sums::<R>(bits);
    let w = w.and(m);
    let g = ccmp(bp, ch, t_count);
    let w0 = beta_share.add(signed(b == 0, w, bits)).and(m);
    let w1 = beta_share.neg().add(signed(b == 1, w, bits)).and(m);
    let wcw_share = mux(ch, cot, &[g], &[w0], &[w1], bits, rng).expect("semi-honest MUX")[0];
    let mut msg = Vec::with_capacity(R::BYTES);
    wcw_share.put(&mut msg);
    ch.send(msg);
    let theirs = ch.recv();
    assert_eq!(theirs.len(), R::BYTES, "malformed W_CW share");
    let w_cw = wcw_share.add(R::get(&theirs)).and(m);

    let key = ArithKey { party: b, n_size, bits, root, cws, w_cw };
    let full = tree.stored_leaves(n_size as usize).filter(|_| full_output).map(|(seeds, ts)| seeds.iter().zip(ts).map(|(s, t)| key.output(*s, *t)).collect());
    (key, full)
}

/// Runs this party's side of the generation.
///
/// * `alpha_share`: additive share of `α < N` modulo `2^n`, `n = ceil(log2 N)`.
/// * `beta_share`: additive share of `β` modulo `2^bits`, `1 ≤ bits ≤ R::BITS`
///   (`R = u64` for ℓ ≤ 64, `u128` for ℓ ≤ 128).
pub fn gen<R: Ring>(ch: &mut Channel, n_size: u64, bits: usize, alpha_share: u64, beta_share: R, seed: [u8; 32]) -> GenOutput<R> {
    gen_mode(ch, n_size, bits, alpha_share, beta_share, seed, TreeMode::Stored, true)
}

/// [`gen`] with the tree held as `mode` says. Both modes send the same
/// messages; [`TreeMode::Stream`] returns no full-domain output. With
/// `full_output` false the stored tree does not build it either, so
/// `gen_time` covers the key alone.
#[allow(clippy::too_many_arguments)]
pub fn gen_mode<R: Ring>(ch: &mut Channel, n_size: u64, bits: usize, alpha_share: u64, beta_share: R, seed: [u8; 32], mode: TreeMode, full_output: bool) -> GenOutput<R> {
    assert!((1..=R::BITS).contains(&bits), "ℓ must be 1..={}", R::BITS);
    let t_setup = Instant::now();
    let (mut rng_tree, mut rng) = party_rngs(seed);
    let root = Block::random(&mut rng_tree);
    let delta = Block::random(&mut rng);
    let mut cot = CotPair::setup(ch, &mut rng, delta, false).expect("semi-honest base OT");
    let mut bp = BoolParty::setup(ch, &mut rng);
    ch.sync();
    let setup_stats = ch.stats();
    let setup_time = t_setup.elapsed();
    let t_gen = Instant::now();
    let (key, full) = match mode {
        TreeMode::Stored => gen_with::<R, Tree>(mode, full_output, &mut bp, &mut cot, &mut rng, ch, root, n_size, bits, alpha_share, beta_share),
        TreeMode::Stream { .. } => gen_with::<R, TreeStream>(mode, full_output, &mut bp, &mut cot, &mut rng, ch, root, n_size, bits, alpha_share, beta_share),
    };
    GenOutput {
        key,
        full,
        gen_stats: ch.stats().since(&setup_stats),
        setup_stats,
        and_gates: bp.ands,
        cots: cot.produced,
        setup_time,
        gen_time: t_gen.elapsed(),
    }
}

/// Trusted-dealer generation for given root shares: the plaintext version of
/// [`gen`] and its bit-exact oracle.
pub fn deal<R: Ring>(roots: [Block; 2], n_size: u64, bits: usize, alpha: u64, beta: R) -> [ArithKey<R>; 2] {
    deal_mode(roots, n_size, bits, alpha, beta, TreeMode::Stored)
}

/// [`deal`] with the tree held as `mode` says.
pub fn deal_mode<R: Ring>(roots: [Block; 2], n_size: u64, bits: usize, alpha: u64, beta: R, mode: TreeMode) -> [ArithKey<R>; 2] {
    match mode {
        TreeMode::Stored => deal_with::<R, Tree>(roots, n_size, bits, alpha, beta, mode),
        TreeMode::Stream { .. } => deal_with::<R, TreeStream>(roots, n_size, bits, alpha, beta, mode),
    }
}

fn deal_with<R: Ring, T: ArithTree>(roots: [Block; 2], n_size: u64, bits: usize, alpha: u64, beta: R, mode: TreeMode) -> [ArithKey<R>; 2] {
    assert!(alpha < n_size);
    let n = depth_for(n_size);
    let m = R::mask(bits);
    let mut tr = [T::new(n_size, roots[0], false, mode), T::new(n_size, roots[1], true, mode)];
    let mut cws = Vec::with_capacity(n);
    for a in bits_msb_first(alpha, n) {
        let (l0, r0) = tr[0].expand_level();
        let (l1, r1) = tr[1].expand_level();
        let (dl, dr) = (l0 ^ l1, r0 ^ r1);
        let cw = CorrectionWord { sigma: if a { dl } else { dr }.with_lsb(false), tau: [dl.lsb() ^ a ^ true, dr.lsb() ^ a] };
        tr[0].correct(cw);
        tr[1].correct(cw);
        cws.push(cw);
    }
    let ((s0, t0), (s1, t1)) = (tr[0].leaf(alpha), tr[1].leaf(alpha));
    assert!(t0 ^ t1, "α-leaf control bits must differ");
    let base = beta.sub(conv(s0, bits)).add(conv(s1, bits));
    let w_cw = signed(t1, base, bits).and(m);
    let mk = |party: usize| ArithKey { party, n_size, bits, root: roots[party], cws: cws.clone(), w_cw };
    [mk(0), mk(1)]
}

/// Trusted-dealer generation from a seed.
pub fn gen_reference<R: Ring>(n_size: u64, bits: usize, alpha: u64, beta: R, seed: [u8; 32]) -> [ArithKey<R>; 2] {
    gen_reference_mode(n_size, bits, alpha, beta, seed, TreeMode::Stored)
}

/// [`gen_reference`] with the tree held as `mode` says.
pub fn gen_reference_mode<R: Ring>(n_size: u64, bits: usize, alpha: u64, beta: R, seed: [u8; 32], mode: TreeMode) -> [ArithKey<R>; 2] {
    let mut rng = ChaCha20Rng::from_seed(seed);
    let roots = [Block::random(&mut rng), Block::random(&mut rng)];
    deal_mode(roots, n_size, bits, alpha, beta, mode)
}
