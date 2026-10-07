//! Actively secure distributed DPF with one-bit leakage, ΠDPF of Zhang et al.,
//! "Efficient Actively Secure DPF and RAM-based 2PC with One-Bit Leakage"
//! (S&P'24, Fig. 5).
//!
//! Inputs are BDOZ-authenticated bits `⟨α_i⟩` (MSB first) and SPDZ-authenticated
//! `⟨β_k⟩ ∈ GF(2^128)`. With `Δ = Δ_0 ⊕ Δ_1` (lsb 1) the shared tree keeps the
//! invariant that on-path nodes differ by Δ and off-path nodes are equal:
//!
//! 1. Root share `Δ_b ⊕ W` (W from the session's coin stream).
//! 2. For every level (one flight each):
//!    `CW_b = ⊕_j H(X^j_b) ⊕ Δ_b ⊕ α_{i,b}·Δ_b ⊕ K_b[α_{i,1−b}] ⊕ M_b[α_{i,b}]`,
//!    which reconstructs to `H-difference ⊕ ᾱ_i·Δ` and needs no 2PC.
//! 3. Leaf word: `CW^{(n)}_b = ⊕_j H_1(X^j_b) ⊕ (β_b ∥ M_b[β])` (one flight).
//! 4. Outputs `u = unit(α)` and `v = β·unit(α)` as SPDZ sharings (the MAC of
//!    `u(x)` is the leaf itself).
//! 5. Consistency: with random `⟨r⟩` and public χ,
//!    `a = Σ_j χ^j u_j + Σ χ^{N+…} v_{j,k} + r` is opened and recorded. If a
//!    party added an error to any correction word, the outputs' MACs no longer
//!    match and the deferred [`MacParty::check`] aborts. The adversary only
//!    learns whether it aborted, i.e. one bit.
//!
//! [`MalSession::gen`] leaves the MAC check to the caller so it can be batched
//! with the rest of a larger protocol; [`run_mal`] runs it at the end.

use super::key::{leaf_outputs, leaf_sums, MalFull, MalKey};
use crate::tree::HtLocal;
use dpf_common::block::{bits_msb_first, blocks_from_bytes, blocks_to_bytes, depth_for, Block};
use dpf_common::coin::Abort;
use dpf_common::gf128;
use dpf_common::hash::{CcrHash, CtrPrg};
use dpf_common::mac::binary::{AuthBit, AuthGf, MacParty};
use dpf_common::net::{Channel, CommStats};
use dpf_common::ot::FerretConfig;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::time::{Duration, Instant};

/// Deliberate deviation for the abort tests: XOR `err` into this party's share
/// of correction word `level` (`n` is the leaf word).
#[derive(Clone, Copy, Debug)]
pub struct Fault {
    pub level: usize,
    pub err: Block,
}

pub struct MalSession {
    pub mac: MacParty,
    pub hash: CcrHash,
    w_stream: CtrPrg,
    pub setup_stats: CommStats,
    pub setup_time: Duration,
}

/// One party's output of [`MalSession::gen`].
pub struct MalGenOutput {
    pub key: MalKey,
    pub full: MalFull,
}

impl MalSession {
    /// MAC keys with `lsb(Δ_b) = b`, KOS-checked COTs, the lsb proof, and one
    /// coin toss for the hash key and the W-stream.
    pub fn setup(ch: &mut Channel, seed: [u8; 32]) -> Result<Self, Abort> {
        Self::setup_with(ch, seed, None)
    }

    /// As [`setup`](Self::setup); with `Some(cfg)`, F_COT is then served by
    /// Ferret (as in the paper's implementation), bootstrapped from the
    /// KOS-checked IKNP COTs.
    pub fn setup_with(ch: &mut Channel, seed: [u8; 32], ferret: Option<FerretConfig>) -> Result<Self, Abort> {
        let t = Instant::now();
        let before = ch.stats();
        let mut mac = MacParty::setup(ch, seed)?;
        if let Some(cfg) = ferret {
            let mut rng = mac.rng().clone();
            mac.cot.enable_ferret(ch, cfg, &mut rng)?;
            *mac.rng() = rng;
        }
        let coins = mac.coins(ch, 2)?;
        ch.sync();
        Ok(MalSession {
            mac,
            hash: CcrHash::new(coins[0]),
            w_stream: CtrPrg::new(coins[1]),
            setup_stats: ch.stats().since(&before),
            setup_time: t.elapsed(),
        })
    }

    pub fn delta(&self) -> Block {
        self.mac.delta()
    }

    /// Authenticates XOR shares of `α < N` (as bits, MSB first) and of `β`.
    pub fn share_inputs(&mut self, ch: &mut Channel, n_size: u64, alpha_share: u64, beta_share: &[Block]) -> Result<(Vec<AuthBit>, Vec<AuthGf>), Abort> {
        let bits = bits_msb_first(alpha_share, depth_for(n_size));
        let a = self.mac.share_bits(ch, &bits)?;
        let b = self.mac.share_gf(ch, beta_share)?;
        Ok((a, b))
    }

    pub fn gen(&mut self, ch: &mut Channel, n_size: u64, alpha: &[AuthBit], beta: &[AuthGf]) -> Result<MalGenOutput, Abort> {
        self.gen_with_fault(ch, n_size, alpha, beta, None)
    }

    #[doc(hidden)]
    pub fn gen_with_fault(
        &mut self,
        ch: &mut Channel,
        n_size: u64,
        alpha: &[AuthBit],
        beta: &[AuthGf],
        fault: Option<Fault>,
    ) -> Result<MalGenOutput, Abort> {
        let n = depth_for(n_size);
        assert_eq!(alpha.len(), n, "need one authenticated bit per level");
        let bm = beta.len();
        assert!(bm >= 1);
        let delta = self.delta();
        let err = |lvl: usize| match fault {
            Some(f) if f.level == lvl => f.err,
            _ => Block::ZERO,
        };

        // 1–2. Root and correlated levels.
        let root = delta ^ Block(self.w_stream.next_words(1)[0]);
        let mut local = HtLocal::start_all_correlated(self.hash.clone(), n_size, root);
        let mut cws = Vec::with_capacity(n);
        for (i, a) in alpha.iter().enumerate() {
            let mine = local.correlated_sum() ^ delta ^ delta.and_bit(a.x) ^ a.k ^ a.m ^ err(i);
            ch.send_blocks(&[mine]);
            let cw = mine ^ ch.recv_blocks(1)[0];
            local.apply_correlated(cw);
            cws.push(cw);
        }

        // 3. Leaf word.
        let leaves = local.nodes();
        let (sv, sm) = leaf_sums(&self.hash, leaves, bm);
        let mut mine: Vec<Block> = sv.iter().zip(beta).map(|(s, b)| *s ^ b.x).collect();
        mine.extend(sm.iter().zip(beta).map(|(s, b)| *s ^ b.m));
        mine[0] ^= err(n);
        ch.send(blocks_to_bytes(&mine));
        let theirs = blocks_from_bytes(&ch.recv());
        if theirs.len() != 2 * bm {
            return Err(Abort("malformed leaf correction word"));
        }
        let cw: Vec<Block> = mine.iter().zip(&theirs).map(|(a, b)| *a ^ *b).collect();
        let (cw_v, cw_m) = (cw[..bm].to_vec(), cw[bm..].to_vec());

        // 4. Outputs.
        let full = leaf_outputs(&self.hash, leaves, &cw_v, &cw_m);

        // 5. Random linear combination, masked by ⟨r⟩, opened for the batch check.
        let r = self.mac.rand_gf(ch, 1)?[0];
        let chi = self.mac.coins(ch, 1)?[0];
        let mut c = gf128::ONE;
        let mut a = r;
        let mut acc = |s: &AuthGf, c: &mut Block| {
            a.x ^= gf128::mul(*c, s.x);
            a.m ^= gf128::mul(*c, s.m);
            *c = gf128::mul(*c, chi);
        };
        for s in &full.u {
            acc(s, &mut c);
        }
        for col in &full.v {
            for s in col {
                acc(s, &mut c);
            }
        }
        self.mac.open(ch, &[a]);

        let key = MalKey { party: ch.party(), n_size, hash: self.hash.clone(), root, cws, cw_v, cw_m };
        Ok(MalGenOutput { key, full })
    }
}

/// Everything one party gets from [`run_mal`].
pub struct MalRun {
    pub out: MalGenOutput,
    pub delta: Block,
    pub setup_stats: CommStats,
    pub setup_time: Duration,
    /// Input authentication + generation + final MAC check.
    pub gen_stats: CommStats,
    pub gen_time: Duration,
    /// COTs consumed by this generation (both directions, KOS padding included).
    pub cots: usize,
}

/// Setup, input authentication, generation and the MAC check for one party.
/// `ferret` selects F_COT: `None` = KOS-checked IKNP, `Some(cfg)` = Ferret.
pub fn run_mal(
    ch: &mut Channel,
    n_size: u64,
    alpha_share: u64,
    beta_share: &[Block],
    seed: [u8; 32],
    fault: Option<Fault>,
    ferret: Option<FerretConfig>,
) -> Result<MalRun, Abort> {
    let mut s = MalSession::setup_with(ch, seed, ferret)?;
    let t = Instant::now();
    let before = ch.stats();
    let cots_before = s.mac.cot.produced;
    let (a, b) = s.share_inputs(ch, n_size, alpha_share, beta_share)?;
    let out = s.gen_with_fault(ch, n_size, &a, &b, fault)?;
    s.mac.check(ch)?;
    Ok(MalRun {
        out,
        delta: s.delta(),
        setup_stats: s.setup_stats,
        setup_time: s.setup_time,
        gen_stats: ch.stats().since(&before),
        gen_time: t.elapsed(),
        cots: s.mac.cot.produced - cots_before,
    })
}

/// Trusted-dealer key generation for the eval benchmarks and tests. Returns the
/// keys and the MAC keys `[Δ_0, Δ_1]`.
pub fn gen_reference(n_size: u64, alpha: u64, beta: &[Block], seed: [u8; 32]) -> ([MalKey; 2], [Block; 2]) {
    use dpf_common::mac::binary::dealer;
    assert!(alpha < n_size);
    let mut rng = ChaCha20Rng::from_seed(seed);
    let deltas = dealer::deltas(&mut rng);
    let delta = deltas[0] ^ deltas[1];
    let w = Block::random(&mut rng);
    let roots = [deltas[0] ^ w, deltas[1] ^ w];
    let hash = CcrHash::new(Block::random(&mut rng));
    let n = depth_for(n_size);
    let mut l0 = HtLocal::start_all_correlated(hash.clone(), n_size, roots[0]);
    let mut l1 = HtLocal::start_all_correlated(hash.clone(), n_size, roots[1]);
    let mut cws = Vec::with_capacity(n);
    for ai in bits_msb_first(alpha, n) {
        let cw = l0.correlated_sum() ^ l1.correlated_sum() ^ delta.and_bit(!ai);
        l0.apply_correlated(cw);
        l1.apply_correlated(cw);
        cws.push(cw);
    }
    let bm = beta.len();
    let (v0, m0) = leaf_sums(&hash, l0.nodes(), bm);
    let (v1, m1) = leaf_sums(&hash, l1.nodes(), bm);
    let cw_v: Vec<Block> = (0..bm).map(|k| v0[k] ^ v1[k] ^ beta[k]).collect();
    let cw_m: Vec<Block> = (0..bm).map(|k| m0[k] ^ m1[k] ^ gf128::mul(beta[k], delta)).collect();
    let mk = |party: usize| MalKey {
        party,
        n_size,
        hash: hash.clone(),
        root: roots[party],
        cws: cws.clone(),
        cw_v: cw_v.clone(),
        cw_m: cw_m.clone(),
    };
    ([mk(0), mk(1)], deltas)
}
