//! Semi-honest dealer-free generation (Figures `Π_GenSH`, `Π_Top` and
//! `Π_Bottom` of the paper) with `F_PRF` = AES–MMO under one public key K: a
//! local top phase of ν ≥ 1 levels and, below it, on-path pairs sampled in the
//! middle of the cipher ([`mmo_pairs`]).
//!
//! **Setup** (`Π_setup`, once per [`Session`], for all its Gens): party b
//! samples its share `Δ_b` of the global `⟨Δ⟩` (`lsb(Δ_b) = b`, so `lsb(Δ) =
//! 1`) and uses it as its Ferret key `Γ_b := Δ_b`; base OTs and Ferret in both
//! directions; then `K ← 𝓕_reveal(𝓕_rand)`. The OT tower runs on party 0's COTs under `Γ_0 = Δ_0`; its
//! hashes, the daBits' and the triples' are tweaked apart from H_K, so Δ_b's
//! two uses are separate correlation-robustness queries.
//!
//! **Preprocessing** (input-independent, per Gen; [`precompute_pairs`]): `⟨α⟩`,
//! the public `W` with `lsb(W) = 0` (roots `k_b = Δ_b ⊕ W`), the middle states
//! of the pairs and the bits `⟨r_ℓ⟩`; the OT tower's random COTs
//! ([`COTS_PER_CALL`] per pair); `⟨α_ℓ·Δ⟩` for ℓ ≤ ν, from COTs under `Γ_b =
//! Δ_b` with `⟨α_ℓ⟩` as the choices; random COTs under `Γ_b = Δ_b` for Step A
//! of each level ν < ℓ ≤ n and for the glue; one AND triple per level ν..=n;
//! and the leaf's daBits and triple ([`crate::leaf`]).
//!
//! **Generation** runs its two layers in parallel:
//!
//! 1. `Π_top`, `ℓ = 1, …, ν`, on its own lane (ν rounds): party b expands its
//!    own tree from `k_b`; `Z_{ℓ,b} = ⊕_x H_K(st_b(x))` and `CW_ℓ = Z_{ℓ,0} ⊕
//!    Z_{ℓ,1} ⊕ ¬α_ℓ·Δ` is opened. Then the glue's `⟨st_{ν,0}⟩ = ⟨E⟩ ⊕
//!    ¬⟨t_{ν,0}⟩·⟨Δ⟩` (one COT; no product with a binary payload).
//! 2. Rounds 1–20: the `2(n − ν + 1)` calls of `𝓕_PRFPair`, in one batch.
//!    `⟨u^b_ℓ⟩` is `⟨X^b_ℓ⟩` with its low bit set to `⟨r_ℓ⟩ ⊕ b`.
//! 3. Round 21: open `C_ℓ = Δ ⊕ u^0_ℓ ⊕ u^1_ℓ`; the AND `g_ℓ = r_ℓ·lsb(X^0_ℓ ⊕
//!    X^1_ℓ)`; Step A, `(⟨α_ℓ·Δ⟩, ⟨P_ℓ⟩) = 𝓕_COT(⟨α_ℓ⟩, ⟨Δ⟩ ∥ ⟨u^0_{ℓ−1}⟩)`: per
//!    direction one correction bit of `⟨α_ℓ⟩` and one λ-bit message, which does
//!    not depend on the peer's correction, so both travel in this round.
//! 4. Round 22: open `CW_ℓ`, `b^τ_ℓ = lsb(X^τ_ℓ) ⊕ g_ℓ` and the glue's `M^0_ν`.
//! 5. Round 23: open `M^0_ℓ` for ℓ > ν.
//!
//! The leaf rides along on its own lane from round 21 ([`pair_leaf`]).
//! Rounds: `max(ν + 3, 23)`, and `max(ν + 2, 23)` for a binary payload, since
//! the glue's opening waits for `C_ν` and the top phase.
//!
//! The malicious variants run this Gen with the further pairs of a τ-block leaf
//! hash ([`PreSpec::leaf_pairs`], whose words `C^j`, `N^j` ride in rounds 21 and
//! 22) and may inject the deviations of [`Fault`].

use super::key::ShKey;
use crate::field::Field;
use crate::leaf::{fp_pre, fp_pre_cots, leaf_dabits, pair_leaf, FpPre};
use crate::{deal_pairs, default_nu, mal_calls, Bottom};
use dpf_common::aes_tower::{bits_of, block_of, mmo_pairs, Mmo, OtTower, Shared128, COTS_PER_CALL};
use dpf_common::block::{depth_for, pack_bits, unpack_bits, Block};
use dpf_common::bool2pc::rot_string_triples;
use dpf_common::hash::cot_hash;
use dpf_common::net::{Channel, CommStats, Lane};
use dpf_common::ot::{CotPair, FerretConfig, RandomCots};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use std::time::{Duration, Instant};

/// Everything one party gets out of [`gen`] (and [`super::bin::gen`]).
pub struct GenOutput<K> {
    pub key: K,
    /// This party's XOR share of the random index α (bit `n − 1 − i` is level
    /// i + 1), sampled in preprocessing.
    pub alpha_share: u64,
    /// This party's XOR shares of the pair inputs `[X^0_ℓ, X^1_ℓ]`, `ν ≤ ℓ ≤ n`.
    pub pairs: Vec<[Block; 2]>,
    /// This party's XOR shares of the bits `r_ν, …, r_n`.
    pub rs: Vec<bool>,
    /// Base OTs and the Ferret bootstrap.
    pub setup_stats: CommStats,
    pub pre_stats: CommStats,
    pub gen_stats: CommStats,
    pub setup_time: Duration,
    pub pre_time: Duration,
    pub gen_time: Duration,
    /// ANDs of the AES–MMO calls in 2PC.
    pub ands: usize,
    /// COTs consumed after setup (the OT tower's, 𝓕_COT's, the
    /// bit-times-block triples, the leaf's).
    pub cots: usize,
}

/// One random COT under `Γ_b = Δ_b` per direction: this party's sender key
/// `K` and its receiver side `(c, M)` with `M = K' ⊕ c·Δ_{1−b}`.
pub type DeltaCot = (Block, bool, Block);

/// `⟨x_i·Δ⟩` for shared bits `x_i` on random COTs under `Γ_b = Δ_b` (𝓕_COT of
/// the paper, as in Half-Tree): `x·Δ = x_0Δ_0 ⊕ x_1Δ_1 ⊕ x_1Δ_0 ⊕ x_0Δ_1`,
/// each cross term one COT. Each party sends `d = x_b ⊕ c` (one bit per COT,
/// one round on `lane`) and shifts its sender key by the peer's d, so that the
/// peer's receiver side is `K' ⊕ x_{1−b}·Δ_b`; the share is `x_b·Δ_b ⊕ K' ⊕
/// M`.
fn delta_products(ch: &mut Channel, lane: &mut Lane, xs: &[bool], cots: &[DeltaCot], delta: Block) -> Vec<Block> {
    assert_eq!(xs.len(), cots.len(), "𝓕_COT: COTs exhausted");
    let mine: Vec<bool> = xs.iter().zip(cots).map(|(&x, &(_, c, _))| x ^ c).collect();
    let theirs = ch.exchange_on(lane, pack_bits(&mine));
    assert_eq!(theirs.len(), mine.len().div_ceil(8), "malformed 𝓕_COT message");
    let d = unpack_bits(&theirs, xs.len());
    xs.iter().zip(cots).zip(d).map(|((&x, &(k, _, m)), d)| delta.and_bit(x) ^ k ^ delta.and_bit(d) ^ m).collect()
}

/// A public word of the malicious Gen that a test can falsify.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Word {
    /// `CW_{i+1}`, `i < n`.
    Cw(usize),
    /// The payload word `W_CW`.
    Payload,
    /// The MAC word `W^MAC_CW`.
    Mac,
    /// `M^0_{ν+j}`.
    M0(usize),
    /// `C_{ν+j}`.
    C(usize),
    /// `b^τ_{ν+j}`, τ ∈ {0, 1}; the low bit of the error is XORed in.
    BTau(usize, usize),
    /// `C^{j+2}` of the leaf hash.
    LeafC(usize),
    /// `N^{j+2}` of the leaf hash.
    LeafN(usize),
    /// This party's share of the glue residual ω (arithmetic payload).
    Omega,
}

/// A deliberate deviation of one party, for the malicious tests.
#[derive(Clone, Copy, Debug)]
pub enum Fault {
    /// XOR the error into this party's share of the word before it is opened
    /// (added, for `Payload`, `Mac` and `Omega` in a field, as `from_u128`).
    Word(Word, Block),
    /// The swap of the paper: flip this party's share of `t_{ν,0}` in the glue,
    /// both in the 𝓕_COT and in the local term `t_{ν,0}·C_ν`. With a Boolean
    /// payload the glue has neither; a party that sets this takes the other
    /// server's state as `st_{ν,0}`, adding `Δ_b` in place of `b·C_ν`.
    Swap,
    /// Flip this party's share of `α_{i+1}` into the one product it enters and
    /// in the terms local to its level: the keys are honest keys for `α* = α ⊕
    /// e_{i+1}`.
    Alpha(usize),
    /// Flip this party's share of the tag `σ = r_n` into the B2A of the leaf.
    Sigma,
}

impl Fault {
    /// The error on `word` (zero without this fault).
    pub(crate) fn at(fault: Option<Fault>, word: Word) -> Block {
        match fault {
            Some(Fault::Word(w, e)) if w == word => e,
            _ => Block::ZERO,
        }
    }
}

/// What a variant asks of the preprocessing of [`walk_pairs`].
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct PreSpec {
    /// A binary payload: no glue COT.
    pub binary: bool,
    /// More COTs per direction, for the leaf.
    pub cots: usize,
    /// Further pairs of the leaf hash, `τ − 1` (two calls each).
    pub leaf_pairs: usize,
    /// The α share a party feeds to generation has this level flipped.
    pub flip_alpha: Option<usize>,
}

/// The preprocessing of one generation of [`walk_pairs`].
pub struct PairPre {
    /// The glue level ν.
    pub nu: usize,
    /// `⟨α⟩`: this party's share, bit `n − 1 − i` for level i + 1.
    pub alpha_share: u64,
    /// `⟨Δ⟩`: this party's share `Δ_b`, `lsb(Δ_b) = b`.
    pub delta: Block,
    /// The public W, `lsb(W) = 0`, that re-randomises the roots per Gen.
    pub w: Block,
    /// `⟨α_ℓ·Δ⟩` for the n levels: those of ℓ ≤ ν from preprocessing, the
    /// others filled in by Step A of [`walk_pairs`].
    pub alpha_delta: Vec<Block>,
    /// Step A's random COTs under `Γ_b = Δ_b`, levels ν < ℓ ≤ n.
    pub step_a: Vec<DeltaCot>,
    /// The glue's random COT (`None` for a binary payload).
    pub glue_cot: Option<DeltaCot>,
    /// `⟨m⟩` of the two pairs of each level ν..=n, then of each leaf pair.
    pub mids: Vec<[Block; 2]>,
    /// `⟨r_ℓ⟩`, `ν ≤ ℓ ≤ n`.
    pub rs: Vec<bool>,
    /// One AND triple per level ν..=n, in the low bits of `(a, B, a·B)`.
    pub triples: Vec<(bool, Block, Block)>,
    /// The public key K.
    pub key: Mmo,
    /// The OT tower, on its random COTs.
    pub be: OtTower,
    /// The level whose α share this party flips ([`Fault::Alpha`]).
    pub flip_alpha: Option<usize>,
}

impl PairPre {
    /// This party's root `k_b = Δ_b ⊕ W`.
    pub fn root(&self) -> Block {
        self.delta ^ self.w
    }

    fn alpha_bits(&self) -> Vec<bool> {
        alpha_bits(self.alpha_share, self.alpha_delta.len(), self.flip_alpha)
    }
}

/// The bits of a share of α, level 1 first, with level `flip` flipped.
fn alpha_bits(share: u64, n: usize, flip: Option<usize>) -> Vec<bool> {
    (0..n).map(|i| ((share >> (n - 1 - i)) & 1 == 1) ^ (flip == Some(i))).collect()
}

/// The preprocessing of one Gen of depth n on session `s` (the module's
/// header), as `spec` asks.
pub(crate) fn precompute_pairs(ch: &mut Channel, s: &mut Setup, n: usize, nu: usize, spec: PreSpec) -> PairPre {
    assert!(n >= 1 && (1..=n).contains(&nu), "1 ≤ ν ≤ n");
    let PreSpec { binary, cots, leaf_pairs, flip_alpha } = spec;
    let b = ch.party();
    let Setup { cot, rng, global, .. } = s;
    let pool = cot.random_cots(ch, 0, mal_calls(n, nu, leaf_pairs + 1) * COTS_PER_CALL, rng).expect("semi-honest COT");
    let be = OtTower::new(b, pool, cot.delta());
    let levels = n - nu + 1;
    let triples = rot_string_triples(ch, cot, levels, rng);
    // Step A's and the glue's random COTs under Γ_b = Δ_b, silent on Ferret.
    let m = n - nu + !binary as usize;
    let (mut keys, mut macs, mut choices) = (vec![], vec![], vec![]);
    for sender in 0..2 {
        match cot.random_cots(ch, sender, m, rng).expect("semi-honest COT") {
            RandomCots::Sender(k) => keys = k,
            RandomCots::Receiver(c, mm) => (choices, macs) = (c, mm),
        }
    }
    let mut randoms: Vec<DeltaCot> = (0..m).map(|i| (keys[i], choices[i], macs[i])).collect();
    let glue_cot = if binary { None } else { randoms.pop() };
    let step_a = randoms;
    cot.precompute(ch, nu + cots, nu + cots, rng).expect("semi-honest COT");
    let alpha_share: u64 = rng.gen::<u64>() & dpf_common::arith::mask(n);
    let mids = (0..levels + leaf_pairs).map(|_| [Block::random(rng), Block::random(rng)]).collect();
    let rs = (0..levels).map(|_| rng.gen()).collect();
    // W ← 𝓕_reveal(𝓕_rand) with lsb(W) = 0, and the COTs under Γ_b = Δ_b with
    // the bits of α as choices, for the top levels, in one round.
    let mine = Block::random(rng);
    ch.send_blocks(&[mine]);
    let w = (mine ^ ch.recv_blocks(1)[0]).with_lsb(false);
    let top = alpha_bits(alpha_share, n, flip_alpha);
    let (keys, macs) = cot.extend(ch, &top[..nu], nu, rng).expect("semi-honest COT");
    let delta = global.delta;
    // ⟨α_ℓ·Δ⟩_b = α_{ℓ,b}·Δ_b ⊕ K ⊕ M, as in [`delta_products`] with no correction.
    let mut alpha_delta = vec![Block::ZERO; n];
    for i in 0..nu {
        alpha_delta[i] = delta.and_bit(top[i]) ^ keys[i] ^ macs[i];
    }
    PairPre { nu, alpha_share, delta, w, alpha_delta, step_a, glue_cot, mids, rs, triples, key: global.key.clone(), be, flip_alpha }
}

/// `Π_top` and the glue's product on `lane`: `CW_1, …, CW_ν`, this party's
/// share of `st_{ν,0}` (of E for a binary payload) and of `¬t_{ν,0}`, and, if
/// `keep`, its level-ν frontier `st_b({0,1}^ν)`.
fn top_pairs(pre: &mut PairPre, ch: &mut Channel, lane: &mut Lane, fault: Option<Fault>, keep: bool) -> (Vec<Block>, Block, bool, Vec<Block>) {
    let b = ch.party();
    let delta = pre.delta;
    let mut nodes = vec![pre.root()];
    let mut ls = Vec::new();
    let mut cws = Vec::with_capacity(pre.nu);
    for i in 0..pre.nu {
        ls.resize(nodes.len(), Block::ZERO);
        pre.key.h_many(&nodes, &mut ls);
        // ⟨CW_ℓ⟩ = Z_{ℓ,b} ⊕ ⟨¬α_ℓ·Δ⟩, ⟨¬α_ℓ·Δ⟩ = ⟨Δ⟩ ⊕ ⟨α_ℓ·Δ⟩.
        let share = ls.iter().fold(Block::ZERO, |acc, &l| acc ^ l) ^ delta ^ pre.alpha_delta[i] ^ Fault::at(fault, Word::Cw(i));
        let cw = share ^ Block::from_bytes(&ch.exchange_on(lane, share.to_bytes().to_vec()));
        let mut next = Vec::with_capacity(2 * nodes.len());
        for (&st, &l) in nodes.iter().zip(&ls) {
            let lv = l ^ cw.and_bit(st.lsb());
            next.push(lv);
            next.push(st ^ lv);
        }
        nodes = next;
        cws.push(cw);
    }
    // E_b and A_b over level ν; ¬t_{ν,0} = a_1 ⊕ e_1 (Lemma "Glue").
    let (e_b, a_b) = nodes.iter().filter(|s| s.lsb()).fold((Block::ZERO, 0u64), |(e, c), &s| (e ^ s, c + 1));
    let v = if b == 0 { a_b % 4 } else { (4 - a_b % 4) % 4 };
    let not_t = ((v >> 1) & 1 == 1) ^ matches!(fault, Some(Fault::Swap));
    let st = match pre.glue_cot.take() {
        Some(cot) => e_b ^ delta_products(ch, lane, &[not_t], &[cot], delta)[0],
        None => e_b,
    };
    (cws, st, not_t, if keep { nodes } else { vec![] })
}

/// One simultaneous exchange on the main line.
fn exchange(ch: &mut Channel, msg: Vec<u8>) -> Vec<u8> {
    let n = msg.len();
    let mut lane = ch.lane();
    let theirs = ch.exchange_on(&mut lane, msg);
    ch.join(lane);
    assert_eq!(theirs.len(), n, "malformed message");
    theirs
}

fn put_blocks(msg: &mut Vec<u8>, xs: &[Block]) {
    xs.iter().for_each(|x| msg.extend_from_slice(&x.to_bytes()));
}

fn get_blocks(b: &[u8]) -> Vec<Block> {
    b.chunks(16).map(Block::from_bytes).collect()
}

/// What [`walk_pairs`] leaves: the n level words, the bottom layer's public
/// words, this party's shares of the leaf hashes `H_K(X^b_n)` and of the pair
/// inputs (the levels' first, then the leaf pairs'), the public words `[C^j,
/// N^j]` of the leaf pairs with this party's shares of their hashes `[h^{(0)}_j,
/// h^{(1)}_j]`, the lane for the leaf, at the end of the pairs; and, for the
/// glue residual, this party's share of `st_{ν,0}`, its level-ν frontier and a
/// lane at the end of the glue.
pub struct PairWalk {
    pub cws: Vec<Block>,
    pub bottom: Bottom,
    pub hs: [Block; 2],
    pub xs: Vec<[Block; 2]>,
    pub leaf_words: Vec<[Block; 2]>,
    pub leaf_hs: Vec<[Block; 2]>,
    pub leaf_lane: Lane,
    pub glue: Block,
    pub frontier: Vec<Block>,
    pub glue_lane: Lane,
}

/// Figures `Π_GenSH`, `Π_Top` and `Π_Bottom` up to the leaf, in the schedule of
/// the module's header, with the deviation `fault` of this party. `keep_frontier`
/// keeps the level-ν frontier for the glue residual.
pub(crate) fn walk_pairs(pre: &mut PairPre, ch: &mut Channel, fault: Option<Fault>, keep_frontier: bool) -> PairWalk {
    let b = ch.party();
    let (n, nu, delta) = (pre.alpha_delta.len(), pre.nu, pre.delta);
    let (levels, k) = (n - nu + 1, n - nu);
    let binary = pre.glue_cot.is_none();
    let a = pre.alpha_bits();
    let p0 = b == 0;
    let err = |w: Word| Fault::at(fault, w);

    let mut top_lane = ch.lane();
    let (mut cws, st_nu, not_t, frontier) = top_pairs(pre, ch, &mut top_lane, fault, keep_frontier);
    let glue_lane = top_lane;

    // Rounds 1–20: the pairs.
    let mids: Vec<Shared128<bool>> = pre.mids.iter().flat_map(|m| m.iter().map(|&x| bits_of(x))).collect();
    let out = mmo_pairs(&mut pre.be, ch, &pre.key, &mids);
    let leaf_lane = ch.lane();
    let xs: Vec<[Block; 2]> = out.chunks(2).map(|p| [block_of(&p[0].0), block_of(&p[1].0)]).collect();
    let ls: Vec<[Block; 2]> = out.chunks(2).map(|p| [block_of(&p[0].1), block_of(&p[1].1)]).collect();
    let (leaf_xs, leaf_hs) = (xs[levels..].to_vec(), ls[levels..].to_vec());
    let us: Vec<[Block; 2]> = (0..levels).map(|j| [xs[j][0].with_lsb(pre.rs[j]), xs[j][1].with_lsb(pre.rs[j] ^ p0)]).collect();

    // Round 21: C_ℓ and C^j, the masks of the ANDs, Step A's messages.
    let mut c_mine: Vec<Block> = us.iter().enumerate().map(|(j, u)| delta ^ u[0] ^ u[1] ^ err(Word::C(j))).collect();
    c_mine.extend(leaf_xs.iter().enumerate().map(|(j, x)| delta ^ x[0] ^ x[1] ^ err(Word::LeafC(j))));
    let t: Vec<(bool, Block, Block)> = pre.triples.drain(..).collect();
    let ef_mine: Vec<bool> = (0..levels).flat_map(|j| [pre.rs[j] ^ t[j].0, xs[j][0].lsb() ^ xs[j][1].lsb() ^ t[j].1.lsb()]).collect();
    let h = |x: Block, j: usize| cot_hash().h(x, (9 << 60) | j as u64);
    // Step A: ε = α_b ⊕ c and D = H(K) ⊕ H(K ⊕ Δ_b) ⊕ u_b.
    let eps_mine: Vec<bool> = (0..k).map(|j| a[nu + j] ^ pre.step_a[j].1).collect();
    let d_mine: Vec<Block> = (0..k).map(|j| h(pre.step_a[j].0, j) ^ h(pre.step_a[j].0 ^ delta, j) ^ us[j][0]).collect();
    let bits_mine: Vec<bool> = ef_mine.iter().chain(&eps_mine).copied().collect();
    let mut msg = pack_bits(&bits_mine);
    let nb = msg.len();
    put_blocks(&mut msg, &c_mine);
    put_blocks(&mut msg, &d_mine);
    let theirs = exchange(ch, msg);
    let bits_peer = unpack_bits(&theirs[..nb], bits_mine.len());
    let ef: Vec<bool> = bits_peer.iter().zip(&ef_mine).map(|(&x, &y)| x ^ y).collect();
    let eps_peer = &bits_peer[2 * levels..];
    let nc = c_mine.len();
    let mut c: Vec<Block> = get_blocks(&theirs[nb..nb + 16 * nc]).iter().zip(&c_mine).map(|(&x, &y)| x ^ y).collect();
    let leaf_c = c.split_off(levels);
    let d_peer = get_blocks(&theirs[nb + 16 * nc..]);
    // ⟨g_ℓ⟩ by Beaver; with K' = K ⊕ ε_{1−b}·Δ_b, ⟨α_ℓ·Δ⟩_b = α_b·Δ_b ⊕ K' ⊕ M
    // and ⟨P_ℓ⟩_b = α_b·u_b ⊕ H(K') ⊕ H(M) ⊕ α_b·D_{1−b}.
    let gs: Vec<bool> = (0..levels)
        .map(|j| {
            let (e, f) = (ef[2 * j], ef[2 * j + 1]);
            t[j].2.lsb() ^ (e && t[j].1.lsb()) ^ (f && t[j].0) ^ (e && f && p0)
        })
        .collect();
    let mut ps = Vec::with_capacity(k);
    for j in 0..k {
        let (key, _, mac) = pre.step_a[j];
        let (al, shifted) = (a[nu + j], key ^ delta.and_bit(eps_peer[j]));
        pre.alpha_delta[nu + j] = delta.and_bit(al) ^ shifted ^ mac;
        ps.push(us[j][0].and_bit(al) ^ h(shifted, j) ^ h(mac, j) ^ d_peer[j].and_bit(al));
    }

    // Round 22, once the glue's product is in: CW_ℓ, b^τ_ℓ, M^0_ν, N^j.
    ch.join(top_lane);
    let t_share = not_t ^ p0;
    let glue_term = match (binary, matches!(fault, Some(Fault::Swap))) {
        (true, false) => c[0].and_bit(p0),
        (true, true) => delta,
        (false, _) => c[0].and_bit(t_share),
    };
    let m_nu_mine = st_nu ^ us[0][0] ^ glue_term ^ err(Word::M0(0));
    let cw_mine: Vec<Block> = (0..k).map(|j| ls[j][0] ^ ls[j][1] ^ delta ^ pre.alpha_delta[nu + j] ^ c[j].and_bit(a[nu + j] ^ p0) ^ err(Word::Cw(nu + j))).collect();
    let (un0, r_n, cn) = (us[levels - 1][0], pre.rs[levels - 1], c[levels - 1]);
    let n_mine: Vec<Block> = leaf_xs.iter().zip(&leaf_c).enumerate().map(|(j, (x, &cj))| un0 ^ x[0] ^ (cn ^ cj).and_bit(r_n) ^ err(Word::LeafN(j))).collect();
    let bt_mine: Vec<bool> = (0..levels).flat_map(|j| (0..2).map(move |tau| (j, tau))).map(|(j, tau)| xs[j][tau].lsb() ^ gs[j] ^ err(Word::BTau(j, tau)).lsb()).collect();
    let mut msg = Vec::with_capacity(16 * (k + 1 + n_mine.len()) + levels);
    put_blocks(&mut msg, &[m_nu_mine]);
    put_blocks(&mut msg, &cw_mine);
    put_blocks(&mut msg, &n_mine);
    msg.extend(pack_bits(&bt_mine));
    let theirs = exchange(ch, msg);
    let m_nu = m_nu_mine ^ Block::from_bytes(&theirs[..16]);
    let low: Vec<Block> = get_blocks(&theirs[16..16 * (k + 1)]).iter().zip(&cw_mine).map(|(&x, &y)| x ^ y).collect();
    let bw = 16 * (k + 1 + n_mine.len());
    let ns: Vec<Block> = get_blocks(&theirs[16 * (k + 1)..bw]).iter().zip(&n_mine).map(|(&x, &y)| x ^ y).collect();
    let bt: Vec<bool> = unpack_bits(&theirs[bw..], 2 * levels).iter().zip(&bt_mine).map(|(&x, &y)| x ^ y).collect();

    // Round 23: M^0_ℓ.
    let mut m0 = vec![m_nu];
    if k > 0 {
        let mine: Vec<Block> = (0..k)
            .map(|j| {
                let kl = ls[j][0] ^ ps[j] ^ low[j].and_bit(pre.rs[j]);
                kl ^ us[j + 1][0] ^ (c[j] ^ c[j + 1]).and_bit(kl.lsb()) ^ err(Word::M0(j + 1))
            })
            .collect();
        let mut msg = Vec::with_capacity(16 * k);
        put_blocks(&mut msg, &mine);
        let theirs = exchange(ch, msg);
        m0.extend(get_blocks(&theirs).iter().zip(&mine).map(|(&x, &y)| x ^ y));
    }
    cws.extend(low);
    let b_pairs = bt.chunks(2).map(|p| [p[0], p[1]]).collect();
    let leaf_words = leaf_c.iter().zip(&ns).map(|(&c, &n)| [c, n]).collect();
    PairWalk { cws, bottom: Bottom { nu, m0, c, b: b_pairs }, hs: ls[levels - 1], xs, leaf_words, leaf_hs, leaf_lane, glue: st_nu, frontier, glue_lane }
}

fn gen_with<F: Field>(mut pre: PairPre, mut fpre: FpPre<F, F>, ch: &mut Channel, n_size: u64, beta: F) -> (ShKey<F>, usize, Vec<[Block; 2]>) {
    let b = ch.party();
    let PairWalk { cws, bottom, hs, xs, mut leaf_lane, .. } = walk_pairs(&mut pre, ch, None, false);
    let w_cw = pair_leaf(ch, &mut leaf_lane, hs, *pre.rs.last().unwrap(), &mut fpre, beta);
    ch.join(leaf_lane);
    let root = pre.root();
    (ShKey { party: b, n_size, prf: pre.key, root, cws, bottom, w_cw }, pre.be.ands, xs)
}

/// A semi-honest session: [`Session::setup`] once (the global ⟨Δ⟩, used as
/// the Ferret keys `Γ_b = Δ_b`, and the public K), then any number of Gens,
/// each with its own preprocessing and public W.
pub struct Session {
    pub(crate) s: Setup,
}

impl Session {
    /// Base OTs, Ferret (`ferret`: `Some(FerretConfig::B13)` for benchmarks,
    /// `None` keeps IKNP, for tests), `⟨Δ⟩` and K.
    pub fn setup(ch: &mut Channel, seed: [u8; 32], ferret: Option<FerretConfig>) -> Self {
        Session { s: setup(ch, seed, ferret) }
    }

    /// Preprocessing and generation of a key for a random index α (its share
    /// is in the output) and the public payload β, with glue level `nu ≥ 1`
    /// ([`default_nu`] if `None`).
    pub fn gen<F: Field>(&mut self, ch: &mut Channel, n_size: u64, nu: Option<usize>, beta: F) -> GenOutput<ShKey<F>> {
        let n = depth_for(n_size);
        let dabits = leaf_dabits::<F>(&[1]);
        drive(
            ch,
            &mut self.s,
            n,
            nu.unwrap_or(default_nu(n)),
            PreSpec { cots: fp_pre_cots::<F, F>(dabits, 1), ..Default::default() },
            |cot, rng, ch| fp_pre::<F, F, _>(ch, cot, dabits, 1, &[], rng),
            |pre, fpre, ch| gen_with(pre, fpre, ch, n_size, beta),
        )
    }
}

/// [`Session::setup`] and one [`Session::gen`].
pub fn gen<F: Field>(ch: &mut Channel, n_size: u64, nu: Option<usize>, beta: F, seed: [u8; 32], ferret: Option<FerretConfig>) -> GenOutput<ShKey<F>> {
    Session::setup(ch, seed, ferret).gen(ch, n_size, nu, beta)
}

/// The session secrets: this party's share `Δ_b` of the global ⟨Δ⟩ (also its
/// Ferret key) and the public key K.
pub(crate) struct Global {
    pub delta: Block,
    pub key: Mmo,
}

/// One party's session state after setup.
pub(crate) struct Setup {
    pub cot: CotPair,
    pub rng: ChaCha20Rng,
    pub global: Global,
    pub stats: CommStats,
    pub time: Duration,
}

/// Π_setup: base OTs and Ferret, party b's COTs under its Ferret key `Γ_b :=
/// Δ_b` (`lsb(Δ_b) = b`), then `K` by `𝓕_reveal(𝓕_rand)`.
pub(crate) fn setup(ch: &mut Channel, seed: [u8; 32], ferret: Option<FerretConfig>) -> Setup {
    let t_setup = Instant::now();
    let b = ch.party();
    let mut rng = ChaCha20Rng::from_seed(seed);
    let delta = Block::random(&mut rng).with_lsb(b == 1);
    let mut cot = CotPair::setup(ch, &mut rng, delta, false).expect("semi-honest base OT");
    if let Some(cfg) = ferret {
        cot.enable_ferret(ch, cfg, &mut rng).expect("semi-honest Ferret");
    }
    let mine = Block::random(&mut rng);
    ch.send_blocks(&[mine]);
    let key = Mmo::new((mine ^ ch.recv_blocks(1)[0]).to_bytes());
    ch.sync();
    Setup { cot, rng, global: Global { delta, key }, stats: ch.stats(), time: t_setup.elapsed() }
}

/// Preprocessing on session `s` ([`precompute_pairs`] as `spec` asks, then
/// `extra`), then `body`, the generation proper, each
/// phase timed and counted on its own; the setup figures are the session's.
#[allow(clippy::too_many_arguments)]
pub(crate) fn drive<K, P>(
    ch: &mut Channel,
    s: &mut Setup,
    n: usize,
    nu: usize,
    spec: PreSpec,
    extra: impl FnOnce(&mut CotPair, &mut ChaCha20Rng, &mut Channel) -> P,
    body: impl FnOnce(PairPre, P, &mut Channel) -> (K, usize, Vec<[Block; 2]>),
) -> GenOutput<K> {
    let cots_before = s.cot.produced;
    let start = ch.stats();
    let t_pre = Instant::now();
    let pre = precompute_pairs(ch, s, n, nu, spec);
    let (alpha_share, rs) = (pre.alpha_share, pre.rs.clone());
    let more = extra(&mut s.cot, &mut s.rng, ch);
    let pre_stats = ch.stats().since(&start);
    let pre_time = t_pre.elapsed();
    // Timing only: neither party's gen time includes waiting for the other's
    // preprocessing. Counted in no phase.
    ch.sync();
    let gen_start = ch.stats();
    let t_gen = Instant::now();
    let (key, ands, pairs) = body(pre, more, ch);
    GenOutput {
        key,
        alpha_share,
        pairs,
        rs,
        gen_stats: ch.stats().since(&gen_start),
        setup_stats: s.stats,
        pre_stats,
        setup_time: s.time,
        pre_time,
        gen_time: t_gen.elapsed(),
        ands,
        cots: s.cot.produced - cots_before,
    }
}

/// Trusted-dealer generation for given roots (`lsb(root_b) = b`, the root
/// share `Δ_b`), AES key K, glue level ν ≥ 1, inputs `pairs = [[X^0_ℓ, X^1_ℓ]]`
/// and bits `rs` of levels ν..=n: the cleartext Gen, and the bit-exact oracle of
/// [`gen`]. `α < 2^n` (n = [`depth_for`]`(n_size)`).
#[allow(clippy::too_many_arguments)]
pub fn deal<F: Field>(roots: [Block; 2], key: [u8; 16], n_size: u64, nu: usize, alpha: u64, beta: F, pairs: &[[Block; 2]], rs: &[bool]) -> [ShKey<F>; 2] {
    let prf = Mmo::new(key);
    let (cws, bottom, h) = deal_pairs(&prf, roots, depth_for(n_size), nu, alpha, pairs, rs, false);
    let v = F::from_block(h[0]).sub(F::from_block(h[1])).sub(beta);
    let w_cw = if *rs.last().unwrap() { v.neg() } else { v };
    let mk = |party: usize| ShKey { party, n_size, prf: prf.clone(), root: roots[party], cws: cws.clone(), bottom: bottom.clone(), w_cw };
    [mk(0), mk(1)]
}

/// Trusted-dealer generation from a seed, glue level [`default_nu`].
pub fn gen_reference<F: Field>(n_size: u64, alpha: u64, beta: F, seed: [u8; 32]) -> [ShKey<F>; 2] {
    assert!(alpha < n_size);
    let mut rng = ChaCha20Rng::from_seed(seed);
    let (roots, key, nu, pairs, rs) = reference_params(n_size, &mut rng);
    deal(roots, key, n_size, nu, alpha, beta, &pairs, &rs)
}

/// Random roots, K, [`default_nu`], pair inputs and bits for a dealer.
#[allow(clippy::type_complexity)]
pub(crate) fn reference_params(n_size: u64, rng: &mut ChaCha20Rng) -> ([Block; 2], [u8; 16], usize, Vec<[Block; 2]>, Vec<bool>) {
    let n = depth_for(n_size);
    let nu = default_nu(n);
    let roots = [Block::random(rng).with_lsb(false), Block::random(rng).with_lsb(true)];
    let key = Block::random(rng).to_bytes();
    let pairs = (nu..=n).map(|_| [Block::random(rng), Block::random(rng)]).collect();
    let rs = (nu..=n).map(|_| rng.gen()).collect();
    (roots, key, nu, pairs, rs)
}
