//! Semi-honest dealer-free generation (Figure "DPF.Gen" of the paper) with
//! `F_PRF` = AES–MMO in 2PC on the OT tower ([`OtTower`]) under one public
//! key K, a local top phase of ν ≥ 1 levels, and level-independent lower
//! levels. The malicious variants run the same Gen ([`walk`]) with their
//! additions.
//!
//! **Setup** (`Π_setup`, once per [`Session`], for all its Gens): party b
//! samples its share `Δ_b` of the global `⟨Δ⟩` (`lsb(Δ_b) = b`, so `lsb(Δ) =
//! 1`) and uses it as its Ferret key `Γ_b := Δ_b`; base OTs and Ferret in both
//! directions; then `K ← 𝓕_reveal(𝓕_rand)` (and the malicious variants'
//! `K^mac_j`). The OT tower runs on party 0's COTs under `Γ_0 = Δ_0`; its
//! hashes, the daBits' and the triples' are tweaked apart from H_K, so Δ_b's
//! two uses are separate correlation-robustness queries.
//!
//! **Preprocessing** (input-independent, per Gen; [`precompute`]): the
//! paper's `⟨α⟩`, `⟨u_ℓ⟩` for `ν ≤ ℓ ≤ n` and the public `W` with `lsb(W) =
//! 0` (roots `k_b = Δ_b ⊕ W`); and the correlations its functionalities
//! consume: the OT tower's random COTs ([`COTS_PER_CALL`] per AES–MMO call),
//! the bit-times-block triples of Step C ([`rot_string_triples`]), random COTs under `Γ_b = Δ_b` for the products with `⟨Δ⟩` (𝓕_COT),
//! and the leaf's daBits ([`crate::leaf`]).
//!
//! **Generation**, after preprocessing:
//!
//! 0. 𝓕_COT: `⟨α_ℓ·Δ⟩` for every level and, for the tag-indexed leaf, `⟨Y⟩ =
//!    ⟨u_n⟩ ⊕ ⟨t_{n,0}·Δ⟩` with `t_{n,0} = lsb(u_n)`: each random COT is
//!    derandomised by one bit per direction, all in one round.
//! 1. `Π_top`, `ℓ = 1, …, ν`: party b expands its own tree from its root
//!    `k_b`; `Z_{ℓ,b} = ⊕_x H_K(st_b(x))` over level ℓ − 1, and `CW_ℓ =
//!    Z_{ℓ,0} ⊕ Z_{ℓ,1} ⊕ ¬α_ℓ·Δ` is opened (one round per level), 2^ν − 1
//!    local calls. Glue: `E_b = ⊕_x t_b(x)·st_b(x)`, `A_b = Σ_x t_b(x) mod 4`
//!    over level ν; `⟨t_{ν,0}⟩ = (¬a_1, e_1)` locally for `a = A_0 mod 4`,
//!    `e = −A_1 mod 4` (Lemma "Glue": `a_0·e_0 = 0`, since `a + e` is odd),
//!    `⟨st_{ν,0}⟩ = ⟨E⟩ ⊕ ¬⟨t_{ν,0}⟩·⟨Δ⟩` (one COT),
//!    and `M_ν = st_{ν,0} ⊕ u_ν` is opened.
//! 2. `Π_bottom`, `ν < ℓ ≤ n`, and the leaf, all in one batch of AES–MMO
//!    calls (40 rounds): Step A `⟨L_{ℓ,c}⟩ = H_K(⟨u_{ℓ−1}⟩ ⊕ c·⟨Δ⟩)` and the
//!    leaf masks; Step B opens `CW_ℓ = L_{ℓ,0} ⊕ L_{ℓ,1} ⊕ ¬α_ℓ·Δ`, then `M_ℓ =
//!    L_{ℓ,0} ⊕ P_ℓ ⊕ lsb(u_{ℓ−1})·CW_ℓ ⊕ u_ℓ` is opened; concurrently the
//!    leaf opens its B2A bits and `W_CW` ([`tag_leaf`]).
//! 3. Step C, `⟨P_ℓ⟩ = ⟨α_ℓ·u_{ℓ−1}⟩` by Beaver, one round, concurrent.
//!
//! Rounds: `max(ν + 3, 43)`. The output is the key, `⟨α⟩` and the shares of
//! `u_ν, …, u_n`.

use super::key::ShKey;
use crate::field::Field;
use crate::leaf::{fp_pre, fp_pre_cots, leaf_dabits, tag_leaf, FpPre};
use crate::{deal_walk_nu, default_nu, leaf_seed, sh_calls};
use dpf_common::aes_tower::{bits_of, block_of, mmo_shared, Mmo, OtTower, SharedKey, COTS_PER_CALL};
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
    /// This party's XOR shares of the on-path states `u_ν, …, u_n` of party 0.
    pub onpath_share: Vec<Block>,
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

/// What a variant's Gen asks of [`precompute`] and [`walk`].
#[derive(Clone, Copy, Debug)]
pub struct Shape {
    /// The glue level ν, `1 ≤ ν ≤ n`.
    pub nu: usize,
    /// The leaf is indexed by tag: Gen computes `⟨Y⟩ = ⟨u_n⟩ ⊕ ⟨t_{n,0}·Δ⟩`
    /// (one more 𝓕_COT, before the AES–MMO calls). Not needed with a binary
    /// payload, where the order of the two leaf states does not matter.
    pub y: bool,
    /// Addition (B) of the malicious Gen: below ν, `⟨α_ℓ·Δ⟩` and `⟨P_ℓ⟩` come
    /// from one bit-times-2-block product instead of 𝓕_COT and Step C.
    pub one_product: bool,
}

impl Shape {
    /// The semi-honest Gen with glue level ν and a tag-indexed leaf (`y`).
    pub fn sh(nu: usize, y: bool) -> Self {
        Shape { nu, y, one_product: false }
    }

    /// Levels whose `⟨α_ℓ·Δ⟩` comes from 𝓕_COT: all n, or the top ν with (B).
    pub fn cot_levels(&self, n: usize) -> usize {
        if self.one_product {
            self.nu
        } else {
            n
        }
    }
}

/// A bit-times-2-block Beaver triple's shares `(a, [B_1, B_2], [a·B_1, a·B_2])`.
pub type WideTriple = (bool, [Block; 2], [Block; 2]);

/// One random COT under `Γ_b = Δ_b` per direction: this party's sender key
/// `K` and its receiver side `(c, M)` with `M = K' ⊕ c·Δ_{1−b}`.
pub type DeltaCot = (Block, bool, Block);

/// The preprocessing of one generation.
pub struct Pre {
    pub shape: Shape,
    /// `⟨α⟩`: this party's share, bit `n − 1 − i` for level i + 1.
    pub alpha_share: u64,
    /// `⟨Δ⟩`: this party's share `Δ_b`, `lsb(Δ_b) = b`.
    pub delta: Block,
    /// The public W, `lsb(W) = 0`, that re-randomises the roots per Gen.
    pub w: Block,
    /// `⟨α_ℓ·Δ⟩` for the n levels, filled in by [`walk`].
    pub alpha_delta: Vec<Block>,
    /// `⟨u_ν⟩, …, ⟨u_n⟩`.
    pub us: Vec<Block>,
    /// `⟨Y⟩`, `lsb(Y) = 0`, filled in by [`walk`] if `shape.y`.
    pub y: Block,
    /// `⟨t_{n,0}⟩ = lsb(⟨u_n⟩)`.
    pub t_leaf: bool,
    /// The public AES keys: K, then the session's `K^mac_j`.
    pub keys: Vec<Mmo>,
    /// The OT tower, on its random COTs.
    pub be: OtTower,
    /// `(a, B, a·B)`: Step C's n − ν (none with (B)), then the caller's extra
    /// ones, which [`walk`] leaves here.
    pub string_triples: Vec<(bool, Block, Block)>,
    /// (B)'s n − ν bit-times-2-block triples.
    pub wide_triples: Vec<WideTriple>,
    /// 𝓕_COT's random COTs: the [`Shape::cot_levels`] bits of α, then
    /// `t_{n,0}` if `shape.y`, then the glue's `¬t_{ν,0}`.
    pub delta_cots: Vec<DeltaCot>,
}

/// Bit-times-block triples [`walk`] consumes: Step C's (none with (B)).
pub fn walk_strings(n: usize, shape: Shape) -> usize {
    if shape.one_product {
        0
    } else {
        n - shape.nu
    }
}

/// 𝓕_COT's random COTs per Gen: [`Pre::delta_cots`].
pub fn delta_cots(n: usize, shape: Shape) -> usize {
    shape.cot_levels(n) + shape.y as usize + 1
}

impl Pre {
    /// This party's root `k_b = Δ_b ⊕ W`.
    pub fn root(&self) -> Block {
        self.delta ^ self.w
    }

    /// The bits of α, level 1 first.
    fn alpha_bits(&self) -> Vec<bool> {
        let n = self.alpha_delta.len();
        (0..n).map(|i| (self.alpha_share >> (n - 1 - i)) & 1 == 1).collect()
    }

    /// This party's share of `u_n`.
    pub fn un(&self) -> Block {
        *self.us.last().unwrap()
    }
}

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

/// `m` bit-times-2-block triples from random OTs: as [`rot_string_triples`],
/// with each COT hashed into a 256-bit pair.
fn rot_wide_triples<R: rand::RngCore + rand::CryptoRng>(ch: &mut Channel, cot: &mut CotPair, m: usize, rng: &mut R) -> Vec<WideTriple> {
    let gamma = cot.delta();
    let h = |x: Block, i: usize| [0, 1].map(|j| cot_hash().h(x, (7 << 60) | (2 * i + j) as u64));
    let x2 = |a: [Block; 2], b: [Block; 2]| [a[0] ^ b[0], a[1] ^ b[1]];
    let (mut a, mut bb, mut c) = (vec![false; m], vec![[Block::ZERO; 2]; m], vec![[Block::ZERO; 2]; m]);
    for s in 0..2 {
        match cot.random_cots(ch, s, m, rng).expect("semi-honest COT") {
            RandomCots::Sender(k) => {
                for i in 0..m {
                    let (y0, y1) = (h(k[i], i), h(k[i] ^ gamma, i));
                    bb[i] = x2(y0, y1);
                    c[i] = x2(c[i], y0);
                }
            }
            RandomCots::Receiver(r, macs) => {
                for i in 0..m {
                    a[i] = r[i];
                    c[i] = x2(c[i], h(macs[i], i));
                }
            }
        }
    }
    (0..m).map(|i| (a[i], bb[i], [c[i][0] ^ bb[i][0].and_bit(a[i]), c[i][1] ^ bb[i][1].and_bit(a[i])])).collect()
}

/// The preprocessing of one Gen of depth n on session `s`: the OT tower's
/// COTs for `calls` AES–MMO calls, [`walk_strings`] + `extra_strings`
/// bit-times-block triples, (B)'s wide triples, 𝓕_COT's random COTs
/// ([`delta_cots`]), and `cots` more COTs per direction (the leaf's).
pub(crate) fn precompute(ch: &mut Channel, s: &mut Setup, n: usize, shape: Shape, calls: usize, extra_strings: usize, cots: usize) -> Pre {
    let nu = shape.nu;
    assert!(n >= 1 && (1..=n).contains(&nu), "1 ≤ ν ≤ n");
    let b = ch.party();
    let Setup { cot, rng, global, .. } = s;
    let pool = cot.random_cots(ch, 0, calls * COTS_PER_CALL, rng).expect("semi-honest COT");
    let be = OtTower::new(b, pool, cot.delta());
    let string_triples = rot_string_triples(ch, cot, walk_strings(n, shape) + extra_strings, rng);
    let wide_triples = if shape.one_product { rot_wide_triples(ch, cot, n - nu, rng) } else { vec![] };
    let k = delta_cots(n, shape);
    cot.precompute(ch, k + cots, k + cots, rng).expect("semi-honest COT");
    let alpha_share: u64 = rng.gen::<u64>() & dpf_common::arith::mask(n);
    let us: Vec<Block> = (nu..=n).map(|_| Block::random(rng)).collect();
    let t_leaf = us[n - nu].lsb();
    // W ← 𝓕_reveal(𝓕_rand) with lsb(W) = 0, and 𝓕_COT's random COTs (random
    // choices c) under Γ_b = Δ_b, in one round.
    let mine = Block::random(rng);
    ch.send_blocks(&[mine]);
    let w = (mine ^ ch.recv_blocks(1)[0]).with_lsb(false);
    let choices: Vec<bool> = (0..k).map(|_| rng.gen()).collect();
    let (keys_s, macs) = cot.extend(ch, &choices, k, rng).expect("semi-honest COT");
    let delta_cots = (0..k).map(|i| (keys_s[i], choices[i], macs[i])).collect();
    let keys = std::iter::once(global.key.clone()).chain(global.mac_keys.iter().cloned()).collect();
    Pre {
        shape,
        alpha_share,
        delta: global.delta,
        w,
        alpha_delta: vec![Block::ZERO; n],
        us,
        y: Block::ZERO,
        t_leaf,
        keys,
        be,
        string_triples,
        wide_triples,
        delta_cots,
    }
}

/// `⟨x_i·Y_i⟩` for shared bits `x_i` and blocks `Y_i`, by Beaver on the
/// bit-times-block triples `(a, B, a·B)`: one round on `lane`, opening `x ⊕ a`
/// and `Y ⊕ B`.
pub(crate) fn bit_times_block(ch: &mut Channel, lane: &mut Lane, xy: &[(bool, Block)], triples: &mut std::vec::Drain<(bool, Block, Block)>) -> Vec<Block> {
    let b = ch.party();
    let t: Vec<(bool, Block, Block)> = triples.take(xy.len()).collect();
    assert_eq!(t.len(), xy.len(), "bit-times-block triples exhausted");
    let mut msg = Vec::with_capacity(17 * xy.len());
    for (&(x, y), &(a, bb, _)) in xy.iter().zip(&t) {
        msg.extend_from_slice(&(y ^ bb).to_bytes());
        msg.push((x ^ a) as u8);
    }
    let theirs = ch.exchange_on(lane, msg.clone());
    assert_eq!(theirs.len(), msg.len(), "malformed product message");
    (0..xy.len())
        .map(|i| {
            let (a, bb, c) = t[i];
            let f = Block::from_bytes(&msg[17 * i..17 * i + 16]) ^ Block::from_bytes(&theirs[17 * i..17 * i + 16]);
            let e = (msg[17 * i + 16] ^ theirs[17 * i + 16]) & 1 == 1;
            // x·Y = e·f ⊕ e·B ⊕ a·f ⊕ a·B.
            f.and_bit(e && b == 0) ^ bb.and_bit(e) ^ f.and_bit(a) ^ c
        })
        .collect()
}

/// [`bit_times_block`] for one bit times two blocks, on the wide triples.
fn bit_times_wide(ch: &mut Channel, lane: &mut Lane, xy: &[(bool, [Block; 2])], t: &[WideTriple]) -> Vec<[Block; 2]> {
    let b = ch.party();
    assert_eq!(t.len(), xy.len(), "wide triples exhausted");
    let mut msg = Vec::with_capacity(33 * xy.len());
    for (&(x, y), &(a, bb, _)) in xy.iter().zip(t) {
        msg.extend_from_slice(&(y[0] ^ bb[0]).to_bytes());
        msg.extend_from_slice(&(y[1] ^ bb[1]).to_bytes());
        msg.push((x ^ a) as u8);
    }
    let theirs = ch.exchange_on(lane, msg.clone());
    assert_eq!(theirs.len(), msg.len(), "malformed product message");
    (0..xy.len())
        .map(|i| {
            let (a, bb, c) = t[i];
            let o = 33 * i;
            let e = (msg[o + 32] ^ theirs[o + 32]) & 1 == 1;
            [0, 1].map(|j| {
                let f = Block::from_bytes(&msg[o + 16 * j..o + 16 * j + 16]) ^ Block::from_bytes(&theirs[o + 16 * j..o + 16 * j + 16]);
                f.and_bit(e && b == 0) ^ bb[j].and_bit(e) ^ f.and_bit(a) ^ c[j]
            })
        })
        .collect()
}

/// What [`walk`] leaves: the n level words, the words `M_ν, …, M_n`, this
/// party's shares of the outputs of the leaf jobs with the lane they may be
/// opened on (after the AES–MMO calls), and the top phase's lane (not yet
/// joined) with this party's share of the glue output `st_{ν,0}` and its
/// level-ν frontier `st_b({0,1}^ν)` (if asked for).
pub(crate) struct Walk {
    pub cws: Vec<Block>,
    pub ms: Vec<Block>,
    pub leaf: Vec<Block>,
    pub leaf_lane: Lane,
    pub top_lane: Lane,
    pub glue: Block,
    pub frontier: Vec<Block>,
}

/// Deliberate deviations in [`walk`], for the malicious tests.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Deviation {
    /// ε is XORed into this party's share of `CW_{i+1}` (`i < n`) or of `M_ν`
    /// (`i = n`) before it is opened.
    pub word: Option<(usize, Block)>,
    /// This party flips its share of `¬t_{ν,0}` into the glue's 𝓕_COT (the
    /// swap of the paper).
    pub flip_switch: bool,
    /// This party flips its share of `α_ℓ` (level ℓ = i + 1) into the one
    /// product it enters (𝓕_COT, or (B) below ν).
    pub flip_alpha: Option<usize>,
}

impl Deviation {
    fn at(&self, i: usize) -> Block {
        match self.word {
            Some((l, e)) if l == i => e,
            _ => Block::ZERO,
        }
    }
}

/// The top phase and the glue (Figure "DPF.Gen", Π_top and lines 6–11) on
/// `lane`: returns `CW_1, …, CW_ν`, `M_ν`, this party's share of `st_{ν,0}`
/// and, if `keep`, its level-ν frontier.
fn top(pre: &mut Pre, ch: &mut Channel, lane: &mut Lane, dev: Deviation, keep: bool) -> (Vec<Block>, Block, Block, Vec<Block>) {
    let b = ch.party();
    let (n, delta) = (pre.alpha_delta.len(), pre.delta);
    let mut nodes = vec![pre.root()];
    let mut ls = Vec::new();
    let mut cws = Vec::with_capacity(pre.shape.nu);
    for i in 0..pre.shape.nu {
        ls.resize(nodes.len(), Block::ZERO);
        pre.keys[0].h_many(&nodes, &mut ls);
        // ⟨CW_ℓ⟩ = Z_{ℓ,b} ⊕ ⟨¬α_ℓ·Δ⟩, ⟨¬α_ℓ·Δ⟩ = ⟨Δ⟩ ⊕ ⟨α_ℓ·Δ⟩.
        let z = ls.iter().fold(Block::ZERO, |acc, &l| acc ^ l);
        let share = z ^ delta ^ pre.alpha_delta[i] ^ dev.at(i);
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
    // Glue: E_b and A_b over level ν.
    let (e_b, a_b) = nodes.iter().filter(|s| s.lsb()).fold((Block::ZERO, 0u64), |(e, c), &s| (e ^ s, c + 1));
    // Party 0 holds a = A_0 mod 4, party 1 e = −A_1 mod 4. a + e ≡ A_0 − A_1 = ±1
    // is odd, so a_0·e_0 = 0 and ¬t_{ν,0} = a_1 ⊕ e_1: each party's share is its
    // high bit (Lemma "Glue"). Then ⟨st_{ν,0}⟩ = ⟨E⟩ ⊕ 𝓕_COT(¬⟨t_{ν,0}⟩, ⟨Δ⟩).
    let v = if b == 0 { a_b % 4 } else { (4 - a_b % 4) % 4 };
    let not_t = ((v >> 1) & 1 == 1) ^ dev.flip_switch;
    let cot = pre.delta_cots.pop().expect("the glue's COT");
    let st = e_b ^ delta_products(ch, lane, &[not_t], &[cot], delta)[0];
    let share = st ^ pre.us[0] ^ dev.at(n);
    let m_nu = share ^ Block::from_bytes(&ch.exchange_on(lane, share.to_bytes().to_vec()));
    (cws, m_nu, st, if keep { nodes } else { vec![] })
}

/// Generation up to the leaf: 𝓕_COT, then the top phase and the glue on one
/// lane, Step C (or (B)) on another, the AES–MMO calls of the lower levels and
/// the leaf jobs (key index, this party's share of the input; `leaf_jobs` is
/// called once `⟨Y⟩` is known) on the main line, then Step B and the openings
/// of `M_ℓ`. Consumes the first [`walk_strings`] triples of `pre` and leaves
/// the rest. `keep_frontier` keeps the level-ν frontier for the glue residual.
pub(crate) fn walk(pre: &mut Pre, ch: &mut Channel, leaf_jobs: impl FnOnce(&Pre) -> Vec<(usize, Block)>, dev: Deviation, keep_frontier: bool) -> Walk {
    let (n, shape, delta) = (pre.alpha_delta.len(), pre.shape, pre.delta);
    let nu = shape.nu;
    let mut a = pre.alpha_bits();
    if let Some(l) = dev.flip_alpha {
        a[l] = !a[l];
    }
    // 0. 𝓕_COT: ⟨α_ℓ·Δ⟩ for its levels and ⟨t_{n,0}·Δ⟩, one round.
    let cl = shape.cot_levels(n);
    let mut xs = a[..cl].to_vec();
    if shape.y {
        xs.push(pre.t_leaf);
    }
    let cots: Vec<DeltaCot> = pre.delta_cots.drain(..xs.len()).collect();
    let mut lane = ch.lane();
    let mut prods = delta_products(ch, &mut lane, &xs, &cots, delta);
    if shape.y {
        // ⟨Y⟩ = ⟨u_n⟩ ⊕ ⟨t_{n,0}·Δ⟩; the leaf's AES–MMO calls wait for it.
        pre.y = pre.un() ^ prods.pop().unwrap();
        ch.join(lane);
    }
    pre.alpha_delta[..cl].copy_from_slice(&prods);
    let cot_lane = lane;

    let rest = pre.string_triples.split_off(walk_strings(n, shape));
    let mut mine = std::mem::replace(&mut pre.string_triples, rest);
    let mut triples = mine.drain(..);
    let k = n - nu;
    let step_c: Vec<(bool, Block, Block)> = if shape.one_product { vec![] } else { triples.by_ref().take(k).collect() };
    drop(triples);
    let (mut cws, m_nu, glue, frontier) = top(pre, ch, &mut lane, dev, keep_frontier);
    let mut ms = vec![m_nu];
    // Step C, ⟨P_ℓ⟩ = ⟨α_ℓ·u_{ℓ−1}⟩, or (B), (⟨α_ℓ·Δ⟩, ⟨P_ℓ⟩) from one product.
    let mut c_lane = ch.lane();
    let prods: Vec<Block> = if k == 0 {
        vec![]
    } else if shape.one_product {
        let xy: Vec<(bool, [Block; 2])> = (0..k).map(|j| (a[nu + j], [delta, pre.us[j]])).collect();
        let t: Vec<WideTriple> = pre.wide_triples.drain(..).collect();
        let out = bit_times_wide(ch, &mut c_lane, &xy, &t);
        for (j, o) in out.iter().enumerate() {
            pre.alpha_delta[nu + j] = o[0];
        }
        out.iter().map(|o| o[1]).collect()
    } else {
        let xy: Vec<(bool, Block)> = (0..k).map(|j| (a[nu + j], pre.us[j])).collect();
        let mut sc = step_c;
        let p = bit_times_block(ch, &mut c_lane, &xy, &mut sc.drain(..));
        p
    };
    // Step A (level ℓ = ν + j + 1 hashes u_{ℓ−1}) and the leaf jobs, in one batch.
    let mut jobs: Vec<(usize, _)> = (0..k).flat_map(|j| [(0, bits_of(pre.us[j])), (0, bits_of(pre.us[j] ^ delta))]).collect();
    jobs.extend(leaf_jobs(pre).into_iter().map(|(kj, x)| (kj, bits_of(x))));
    let mut keys: Vec<SharedKey<bool>> = pre.keys.iter().map(|m| SharedKey::public(&pre.be, m)).collect();
    let out: Vec<Block> = mmo_shared(&mut pre.be, ch, &mut keys, &jobs).iter().map(block_of).collect();
    let leaf_lane = ch.lane();
    if k > 0 {
        ch.join(cot_lane);
        ch.join(c_lane);
        // Step B: ⟨CW_ℓ⟩ = ⟨L_{ℓ,0}⟩ ⊕ ⟨L_{ℓ,1}⟩ ⊕ ⟨Δ⟩ ⊕ ⟨α_ℓ·Δ⟩.
        let shares: Vec<Block> = (0..k).map(|j| out[2 * j] ^ out[2 * j + 1] ^ delta ^ pre.alpha_delta[nu + j] ^ dev.at(nu + j)).collect();
        ch.send_blocks(&shares);
        let low: Vec<Block> = shares.iter().zip(ch.recv_blocks(k)).map(|(&x, y)| x ^ y).collect();
        // ⟨M_ℓ⟩ = ⟨L_{ℓ,0}⟩ ⊕ ⟨P_ℓ⟩ ⊕ lsb(⟨u_{ℓ−1}⟩)·CW_ℓ ⊕ ⟨u_ℓ⟩.
        let shares: Vec<Block> = (0..k).map(|j| out[2 * j] ^ prods[j] ^ low[j].and_bit(pre.us[j].lsb()) ^ pre.us[j + 1]).collect();
        ch.send_blocks(&shares);
        ms.extend(shares.iter().zip(ch.recv_blocks(k)).map(|(&x, y)| x ^ y));
        cws.extend(low);
    }
    Walk { cws, ms, leaf: out[2 * k..].to_vec(), leaf_lane, top_lane: lane, glue, frontier }
}

/// This party's leaf jobs of the semi-honest Gen: `H_K(s^(c) ∥ 0)` for the
/// on-path leaf states `Y`, `Y ⊕ Δ` with tags 0 and 1.
pub(crate) fn tag_leaf_jobs(pre: &Pre) -> Vec<(usize, Block)> {
    vec![(0, leaf_seed(pre.y)), (0, leaf_seed(pre.y ^ pre.delta))]
}

fn gen_with<F: Field>(mut pre: Pre, fpre: FpPre<F, F>, ch: &mut Channel, n_size: u64, beta: F) -> (ShKey<F>, usize) {
    let b = ch.party();
    let Walk { cws, ms, leaf, mut leaf_lane, top_lane, .. } = walk(&mut pre, ch, tag_leaf_jobs, Deviation::default(), false);
    let w_cw = tag_leaf(ch, &mut leaf_lane, [leaf[0], leaf[1]], pre.t_leaf, &fpre.dabits, beta);
    ch.join(leaf_lane);
    ch.join(top_lane);
    let prf = pre.keys.swap_remove(0);
    (ShKey { party: b, n_size, prf, root: pre.root(), nu: pre.shape.nu, cws, ms, w_cw }, pre.be.ands)
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
        Session { s: setup(ch, seed, ferret, 0) }
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
            Shape::sh(nu.unwrap_or(default_nu(n)), true),
            fp_pre_cots::<F, F>(dabits, 0),
            |cot, rng, ch| fp_pre::<F, F, _>(ch, cot, dabits, 0, &[], rng),
            |pre, fpre, ch| gen_with(pre, fpre, ch, n_size, beta),
        )
    }
}

/// [`Session::setup`] and one [`Session::gen`].
pub fn gen<F: Field>(ch: &mut Channel, n_size: u64, nu: Option<usize>, beta: F, seed: [u8; 32], ferret: Option<FerretConfig>) -> GenOutput<ShKey<F>> {
    Session::setup(ch, seed, ferret).gen(ch, n_size, nu, beta)
}

/// The session secrets: this party's share `Δ_b` of the global ⟨Δ⟩ (also its
/// Ferret key), the public key K and the malicious variants' `K^mac_j`.
pub(crate) struct Global {
    pub delta: Block,
    pub key: Mmo,
    pub mac_keys: Vec<Mmo>,
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
/// Δ_b` (`lsb(Δ_b) = b`), then `K` and `mac_keys` more public keys `K^mac_j`
/// by `𝓕_reveal(𝓕_rand)`.
pub(crate) fn setup(ch: &mut Channel, seed: [u8; 32], ferret: Option<FerretConfig>, mac_keys: usize) -> Setup {
    let t_setup = Instant::now();
    let b = ch.party();
    let mut rng = ChaCha20Rng::from_seed(seed);
    let delta = Block::random(&mut rng).with_lsb(b == 1);
    let mut cot = CotPair::setup(ch, &mut rng, delta, false).expect("semi-honest base OT");
    if let Some(cfg) = ferret {
        cot.enable_ferret(ch, cfg, &mut rng).expect("semi-honest Ferret");
    }
    let mine: Vec<Block> = (0..1 + mac_keys).map(|_| Block::random(&mut rng)).collect();
    ch.send_blocks(&mine);
    let mut keys: Vec<Mmo> = mine.iter().zip(ch.recv_blocks(1 + mac_keys)).map(|(&a, b)| Mmo::new((a ^ b).to_bytes())).collect();
    let key = keys.remove(0);
    ch.sync();
    Setup { cot, rng, global: Global { delta, key, mac_keys: keys }, stats: ch.stats(), time: t_setup.elapsed() }
}

/// Preprocessing on session `s` ([`precompute`] for [`sh_calls`] AES–MMO
/// calls and `cots` more COTs per direction, then `extra`), then `body`, the
/// generation proper, each phase timed and counted on its own; the setup
/// figures are the session's.
#[allow(clippy::too_many_arguments)]
pub(crate) fn drive<K, P>(
    ch: &mut Channel,
    s: &mut Setup,
    n: usize,
    shape: Shape,
    cots: usize,
    extra: impl FnOnce(&mut CotPair, &mut ChaCha20Rng, &mut Channel) -> P,
    body: impl FnOnce(Pre, P, &mut Channel) -> (K, usize),
) -> GenOutput<K> {
    let cots_before = s.cot.produced;
    let start = ch.stats();
    let t_pre = Instant::now();
    let pre = precompute(ch, s, n, shape, sh_calls(n, shape.nu), 0, cots);
    let (alpha_share, onpath_share) = (pre.alpha_share, pre.us.clone());
    let more = extra(&mut s.cot, &mut s.rng, ch);
    let pre_stats = ch.stats().since(&start);
    let pre_time = t_pre.elapsed();
    // Timing only: neither party's gen time includes waiting for the other's
    // preprocessing. Counted in no phase.
    ch.sync();
    let gen_start = ch.stats();
    let t_gen = Instant::now();
    let (key, ands) = body(pre, more, ch);
    GenOutput {
        key,
        alpha_share,
        onpath_share,
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
/// share `Δ_b`), AES key K, glue level ν ≥ 1 and on-path states `us = [u_ν, …,
/// u_n]` of party 0: the cleartext Gen, and the bit-exact oracle of [`gen`].
/// `α < 2^n` (n = [`depth_for`]`(n_size)`).
pub fn deal<F: Field>(roots: [Block; 2], key: [u8; 16], n_size: u64, nu: usize, alpha: u64, beta: F, us: &[Block]) -> [ShKey<F>; 2] {
    let prf = Mmo::new(key);
    let (cws, ms, st) = deal_walk_nu(&prf, roots, depth_for(n_size), nu, alpha, us);
    let w = |s: Block| F::from_block(prf.h(leaf_seed(s)));
    let v = w(st[0]).sub(w(st[1])).sub(beta);
    let w_cw = if st[0].lsb() { v.neg() } else { v };
    let mk = |party: usize| ShKey { party, n_size, prf: prf.clone(), root: roots[party], nu, cws: cws.clone(), ms: ms.clone(), w_cw };
    [mk(0), mk(1)]
}

/// Trusted-dealer generation from a seed, glue level [`default_nu`].
pub fn gen_reference<F: Field>(n_size: u64, alpha: u64, beta: F, seed: [u8; 32]) -> [ShKey<F>; 2] {
    assert!(alpha < n_size);
    let mut rng = ChaCha20Rng::from_seed(seed);
    let (roots, key, nu, us) = reference_params(n_size, &mut rng);
    deal(roots, key, n_size, nu, alpha, beta, &us)
}

/// Random roots, K, [`default_nu`] and on-path states for a dealer.
pub(crate) fn reference_params(n_size: u64, rng: &mut ChaCha20Rng) -> ([Block; 2], [u8; 16], usize, Vec<Block>) {
    let n = depth_for(n_size);
    let nu = default_nu(n);
    let roots = [Block::random(rng).with_lsb(false), Block::random(rng).with_lsb(true)];
    let key = Block::random(rng).to_bytes();
    let us = (nu..=n).map(|_| Block::random(rng)).collect();
    (roots, key, nu, us)
}
