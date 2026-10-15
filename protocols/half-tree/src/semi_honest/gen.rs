//! Distributed Half-Tree DPF generation, ΠDPF of GYW+23 (Fig. 10) with the
//! preprocessing of Fig. 11, for a binary-field payload.
//!
//! Setup (once per session): each party picks its share `Δ_b` of the global
//! offset with `lsb(Δ_b) = b`, so `lsb(Δ_0 ⊕ Δ_1) = 1` without the lsb exchange of
//! Fig. 11, and runs the base OTs of a COT instance keyed by `Δ_b` in each
//! direction. One coin toss fixes the hash key `S` and the seed from which the
//! per-run root re-randomiser `W` is derived. GYW+23 §5.2 allows exactly this:
//! "all invocations of F_Rand can be compressed via another independent PRF
//! key sampled after the one-time initialization of F_COT".
//!
//! Per run, with `α` XOR-shared MSB-first and `β` XOR-shared:
//!
//! 1. n COTs per direction on the α-share bits give
//!    `M_b[α_{i,b}] = K_{1−b}[α_{i,b}] ⊕ α_{i,b}·Δ_{1−b}`. With chosen-choice IKNP
//!    the masked-choice message `g_b` of Fig. 11 is folded into the extension.
//! 2. Root share `Δ_b ⊕ W`.
//! 3. Levels `1..n−1` (one round each):
//!    `⟨CW_i⟩_b = ⊕_j H(X^j_b) ⊕ Δ_b ⊕ α_{i,b}·Δ_b ⊕ K_b[α_{i,1−b}] ⊕ M_b[α_{i,b}]`,
//!    which reconstructs to `⊕_j H(X^j_0) ⊕ H(X^j_1) ⊕ ᾱ_i·Δ`.
//! 4. Level n (two rounds): `HCW = hb(Xsum_{ᾱ_n})` is selected obliviously with
//!    the level-n COT and the `(μ_b, d_b)` message; `LCW_σ` is linear.
//! 5. `CW_{n+1} = ⊕_j Convert(s^j_0) ⊕ Convert(s^j_1) ⊕ β` (one round).
//!
//! That is n + 3 rounds after setup, as in the paper.

use super::key::HtKey;
use crate::tree::{hb, Convert, FullEval, HtLocal, HtStream, HtTree};
use dpf_common::block::{bits_msb_first, depth_for, xor_blocks, Block};
use dpf_common::coin::coin_blocks;
use dpf_common::hash::{CcrHash, CtrPrg};
use dpf_common::net::{Channel, CommStats};
use dpf_common::ot::CotPair;
use dpf_common::stream::TreeMode;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use std::time::{Duration, Instant};

/// One party's long-lived state: COTs under its `Δ_b`, the hash key and the
/// W-stream. Many generations can run on one session.
pub struct Session {
    pub party: usize,
    pub cot: CotPair,
    pub hash: CcrHash,
    w_stream: CtrPrg,
    rng: ChaCha20Rng,
    pub setup_stats: CommStats,
    pub setup_time: Duration,
}

impl Session {
    pub fn setup(ch: &mut Channel, seed: [u8; 32]) -> Self {
        let t = Instant::now();
        let before = ch.stats();
        let party = ch.party();
        let mut rng = ChaCha20Rng::from_seed(seed);
        let mut delta = Block::random(&mut rng);
        delta.0 = (delta.0 & !1) | party as u128;
        let cot = CotPair::setup(ch, &mut rng, delta, false).expect("semi-honest base OT");
        let coins = coin_blocks(ch, 2, &mut rng).expect("semi-honest coin toss");
        // Synchronise so neither party's gen time includes the other's setup.
        ch.sync();
        Session {
            party,
            cot,
            hash: CcrHash::new(coins[0]),
            w_stream: CtrPrg::new(coins[1]),
            rng,
            setup_stats: ch.stats().since(&before),
            setup_time: t.elapsed(),
        }
    }

    /// `Δ_b`, this party's share of the global offset.
    pub fn delta(&self) -> Block {
        self.cot.delta()
    }

    /// One generation. `alpha_share` and `beta_share` are this party's XOR
    /// shares of `α < N` and `β` (`ceil(out_bits/128)` blocks; `out_bits ≤ 127`
    /// uses the PRG-free Convert).
    pub fn gen(&mut self, ch: &mut Channel, n_size: u64, out_bits: usize, alpha_share: u64, beta_share: &[Block]) -> GenOutput {
        self.gen_mode(ch, n_size, out_bits, alpha_share, beta_share, TreeMode::Stored)
    }

    /// [`gen`](Self::gen) with the tree held as `mode` says. Both modes send
    /// the same messages; [`TreeMode::Stream`] returns no full-domain output.
    pub fn gen_mode(&mut self, ch: &mut Channel, n_size: u64, out_bits: usize, alpha_share: u64, beta_share: &[Block], mode: TreeMode) -> GenOutput {
        match mode {
            TreeMode::Stored => self.gen_with::<HtLocal>(ch, n_size, out_bits, alpha_share, beta_share, mode),
            TreeMode::Stream { .. } => self.gen_with::<HtStream>(ch, n_size, out_bits, alpha_share, beta_share, mode),
        }
    }

    fn gen_with<T: HtTree>(&mut self, ch: &mut Channel, n_size: u64, out_bits: usize, alpha_share: u64, beta_share: &[Block], mode: TreeMode) -> GenOutput {
        let t = Instant::now();
        let before = ch.stats();
        let b = self.party;
        let conv = Convert::new(out_bits);
        assert_eq!(beta_share.len(), conv.bm, "beta share must have ceil(out_bits/128) blocks");
        let n = depth_for(n_size);
        let alpha = bits_msb_first(alpha_share, n);
        let delta = self.delta();

        // 1. COTs on the α shares, both directions.
        let cot_before = ch.stats();
        let (k, m) = self.cot.extend(ch, &alpha, n, &mut self.rng).expect("semi-honest COT");
        let cot_stats = ch.stats().since(&cot_before);

        // 2. Root.
        let w = Block(self.w_stream.next_words(1)[0]);
        let root = delta ^ w;
        let mut local = T::start(self.hash.clone(), n_size, conv, root, mode);

        // 3. Correlated levels.
        let mut cws = Vec::with_capacity(n - 1);
        for i in 0..n - 1 {
            let mine = local.correlated_sum() ^ delta ^ delta.and_bit(alpha[i]) ^ k[i] ^ m[i];
            ch.send_blocks(&[mine]);
            let cw = mine ^ ch.recv_blocks(1)[0];
            local.apply_correlated(cw);
            cws.push(cw);
        }

        // 4. Last level.
        let (sum0, sum1) = local.last_sums();
        let hp = |x: Block| hb(self.hash.h(x));
        let an = alpha[n - 1];
        let (kn, mn) = (k[n - 1], m[n - 1]);
        let d_own = hb(sum0 ^ sum1);
        let mu = Block::random(&mut self.rng);
        let d = hp(mu ^ kn) ^ hp(mu ^ kn ^ delta) ^ d_own;
        ch.send_blocks(&[mu, d]);
        let theirs = ch.recv_blocks(2);
        let (mu1, d1) = (theirs[0], hb(theirs[1]));
        let own_sel = if an { sum0 } else { sum1 }; // Xsum_{α_b ⊕ 1}
        let hcw_share = hb(own_sel) ^ hp(mu ^ kn) ^ hp(mu1 ^ mn) ^ d1.and_bit(an);
        let lcw_share = [sum0.lsb() ^ an ^ (b == 1), sum1.lsb() ^ an];
        let mut msg = hcw_share.to_bytes().to_vec();
        msg.push(lcw_share[0] as u8 | (lcw_share[1] as u8) << 1);
        ch.send(msg);
        let theirs = ch.recv();
        assert_eq!(theirs.len(), 17);
        let hcw = hcw_share ^ hb(Block::from_bytes(&theirs[..16]));
        let lcw = [lcw_share[0] ^ (theirs[16] & 1 == 1), lcw_share[1] ^ (theirs[16] & 2 == 2)];
        local.apply_last(hcw, lcw);

        // 5. Output correction word.
        let mine = xor_blocks(&local.finalize(), beta_share);
        ch.send_blocks(&mine);
        let cw_out = xor_blocks(&mine, &ch.recv_blocks(conv.bm));

        let full = local.output(&cw_out);
        let key = HtKey { party: b, n_size, conv, hash: self.hash.clone(), root, cws, hcw, lcw, cw_out };
        GenOutput {
            key,
            full,
            setup_stats: self.setup_stats,
            setup_time: self.setup_time,
            gen_stats: ch.stats().since(&before),
            cot_stats,
            cots: 2 * n,
            gen_time: t.elapsed(),
        }
    }
}

/// Everything one party gets out of a generation.
pub struct GenOutput {
    pub key: HtKey,
    /// Full-domain output, a by-product of generation. `None` with the
    /// streaming tree.
    pub full: Option<FullEval>,
    pub setup_stats: CommStats,
    pub setup_time: Duration,
    /// Traffic for this generation, COT extension included.
    pub gen_stats: CommStats,
    /// The part of `gen_stats` spent on COT extension.
    pub cot_stats: CommStats,
    /// COTs consumed (both directions).
    pub cots: usize,
    pub gen_time: Duration,
}

/// Session setup plus one generation, with Floram's `gen` signature.
pub fn gen(ch: &mut Channel, n_size: u64, out_bits: usize, alpha_share: u64, beta_share: &[Block], seed: [u8; 32]) -> GenOutput {
    gen_mode(ch, n_size, out_bits, alpha_share, beta_share, seed, TreeMode::Stored)
}

/// [`gen`] with the tree held as `mode` says.
pub fn gen_mode(ch: &mut Channel, n_size: u64, out_bits: usize, alpha_share: u64, beta_share: &[Block], seed: [u8; 32], mode: TreeMode) -> GenOutput {
    let mut s = Session::setup(ch, seed);
    s.gen_mode(ch, n_size, out_bits, alpha_share, beta_share, mode)
}

/// Trusted-dealer DPF.Gen (Fig. 8) for given root shares and hash key. Used as
/// the bit-exact oracle for [`Session::gen`]: the protocol's keys must equal
/// `deal` applied to the roots and `S` it produced.
pub fn deal(hash: &CcrHash, roots: [Block; 2], n_size: u64, out_bits: usize, alpha: u64, beta: &[Block]) -> ([HtKey; 2], [FullEval; 2]) {
    let (keys, [f0, f1]) = deal_with::<HtLocal>(hash, roots, n_size, out_bits, alpha, beta, TreeMode::Stored);
    (keys, [f0.expect("stored tree"), f1.expect("stored tree")])
}

/// The keys of [`deal`], with the tree held as `mode` says.
pub fn deal_keys(hash: &CcrHash, roots: [Block; 2], n_size: u64, out_bits: usize, alpha: u64, beta: &[Block], mode: TreeMode) -> [HtKey; 2] {
    match mode {
        TreeMode::Stored => deal_with::<HtLocal>(hash, roots, n_size, out_bits, alpha, beta, mode).0,
        TreeMode::Stream { .. } => deal_with::<HtStream>(hash, roots, n_size, out_bits, alpha, beta, mode).0,
    }
}

fn deal_with<T: HtTree>(hash: &CcrHash, roots: [Block; 2], n_size: u64, out_bits: usize, alpha: u64, beta: &[Block], mode: TreeMode) -> ([HtKey; 2], [Option<FullEval>; 2]) {
    assert!(alpha < n_size);
    let conv = Convert::new(out_bits);
    assert_eq!(beta.len(), conv.bm);
    let delta = roots[0] ^ roots[1];
    assert!(delta.lsb(), "root shares must differ in the lsb");
    let n = depth_for(n_size);
    let a = bits_msb_first(alpha, n);
    let mut l0 = T::start(hash.clone(), n_size, conv, roots[0], mode);
    let mut l1 = T::start(hash.clone(), n_size, conv, roots[1], mode);
    let mut cws = Vec::with_capacity(n - 1);
    for &ai in &a[..n - 1] {
        let cw = l0.correlated_sum() ^ l1.correlated_sum() ^ delta.and_bit(!ai);
        l0.apply_correlated(cw);
        l1.apply_correlated(cw);
        cws.push(cw);
    }
    let (p0, q0) = l0.last_sums();
    let (p1, q1) = l1.last_sums();
    let (sum0, sum1) = (p0 ^ p1, q0 ^ q1);
    let an = a[n - 1];
    let hcw = hb(if an { sum0 } else { sum1 });
    let lcw = [sum0.lsb() ^ an ^ true, sum1.lsb() ^ an];
    l0.apply_last(hcw, lcw);
    l1.apply_last(hcw, lcw);
    let cw_out = xor_blocks(&xor_blocks(&l0.finalize(), &l1.finalize()), beta);
    let f = [l0.output(&cw_out), l1.output(&cw_out)];
    let mk = |party: usize| HtKey {
        party,
        n_size,
        conv,
        hash: hash.clone(),
        root: roots[party],
        cws: cws.clone(),
        hcw,
        lcw,
        cw_out: cw_out.clone(),
    };
    ([mk(0), mk(1)], f)
}

/// Trusted-dealer generation from a seed: random `Δ` with lsb 1, random roots
/// and hash key.
pub fn gen_reference(n_size: u64, out_bits: usize, alpha: u64, beta: &[Block], seed: [u8; 32]) -> ([HtKey; 2], [FullEval; 2]) {
    let (hash, roots) = reference_setup(seed);
    deal(&hash, roots, n_size, out_bits, alpha, beta)
}

/// The keys of [`gen_reference`], with the tree held as `mode` says.
pub fn gen_reference_keys(n_size: u64, out_bits: usize, alpha: u64, beta: &[Block], seed: [u8; 32], mode: TreeMode) -> [HtKey; 2] {
    let (hash, roots) = reference_setup(seed);
    deal_keys(&hash, roots, n_size, out_bits, alpha, beta, mode)
}

fn reference_setup(seed: [u8; 32]) -> (CcrHash, [Block; 2]) {
    let mut rng = ChaCha20Rng::from_seed(seed);
    let delta = Block(rng.gen::<u128>() | 1);
    let r0 = Block::random(&mut rng);
    (CcrHash::new(Block::random(&mut rng)), [r0, r0 ^ delta])
}
