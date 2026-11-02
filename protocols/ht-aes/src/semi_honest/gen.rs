//! Semi-honest dealer-free generation (Figure "DPF.Gen" of the paper) with
//! `F_PRF` = AES–MMO in 2PC on the OT tower ([`OtTower`]) under one public
//! key K, a local top phase of ν levels, and level-independent lower levels.
//!
//! **Setup** (once per session): base OTs and Ferret in both directions,
//! party b's COTs under its Ferret key `Γ_b`. Γ is internal to OT extension:
//! the OT tower runs on party 0's COTs under `Γ_0`, and every other
//! correlation is derived from random COTs; Γ is never the DPF's Δ.
//!
//! **Preprocessing** (input-independent, per Gen; [`precompute`]):
//!
//! * the paper's: `⟨α⟩`; `⟨Δ⟩` with `lsb(Δ) = 1` (party b samples `Δ_b` with
//!   `lsb(Δ_b) = b`); `⟨U_ℓ⟩` for `ν ≤ ℓ < n`; `⟨Y⟩` with `lsb(Y) = 0`;
//!   `⟨t_{n,0}⟩`; `K ← 𝓕_reveal(𝓕_rand)`; `⟨α_ℓ·Δ⟩` for every level and
//!   `⟨U_n⟩ = ⟨Y⟩ ⊕ ⟨t_{n,0}·Δ⟩`, by 𝓕_COT ([`alpha_delta`]: in each
//!   direction a COT with the chosen offset `Δ_b`, from Ferret random COTs);
//! * the correlations its functionalities consume: the OT tower's random
//!   COTs ([`COTS_PER_CALL`] per AES–MMO call), `n − ν + 2` bit-times-block
//!   triples ([`rot_string_triples`]: Step C and the switch's AND and
//!   product), and the leaf's daBits ([`crate::leaf`]).
//!
//! **Generation**, three concurrent branches after preprocessing (the top
//! phase and Step C on their own [`Lane`]s, so they share their rounds with
//! the AES–MMO calls):
//!
//! 1. Top phase, `ℓ = 1, …, ν`: party b expands its own tree from its root
//!    `Δ_b`; `Z_{ℓ,b} = ⊕_x H_K(st_b(x))` over level ℓ − 1, and `CW_ℓ = Z_{ℓ,0}
//!    ⊕ Z_{ℓ,1} ⊕ ᾱ_ℓ·Δ` is opened (one round per level), 2^ν − 1 local
//!    calls. Switch: `E_b = ⊕_x t_b(x)·st_b(x)`, `A_b = Σ_x t_b(x) mod 4` over
//!    level ν; `⟨t_{ν,0}⟩ = 1 ⊕ a_1 ⊕ e_1 ⊕ a_0e_0` for `a = A_0`, `e = −A_1
//!    mod 4` (one AND), `⟨st_{ν,0}⟩ = ⟨E⟩ ⊕ (1 ⊕ ⟨t_{ν,0}⟩)·⟨Δ⟩` (one
//!    product), and `M_ν = st_{ν,0} ⊕ U_ν` is opened: ν + 3 rounds.
//! 2. Lower levels `ν < ℓ ≤ n` and the leaf, all in one batch of AES–MMO
//!    calls (40 rounds): Step A `⟨L_{ℓ,c}⟩ = H_K(⟨U_{ℓ−1}⟩ ⊕ c·⟨Δ⟩)` and
//!    the leaf masks `⟨h^(c)⟩ = H_K(⟨s^(c)⟩ ∥ 0)` of `Y`, `Y ⊕ Δ`; Step B
//!    opens `CW_ℓ = L_{ℓ,0} ⊕ L_{ℓ,1} ⊕ ᾱ_ℓ·Δ`, then `M_ℓ = L_{ℓ,0} ⊕ P_ℓ ⊕
//!    lsb(U_{ℓ−1})·CW_ℓ ⊕ U_ℓ` is opened; concurrently the leaf opens its
//!    B2A bits and `W_CW` ([`tag_leaf`]).
//! 3. Step C, `⟨P_ℓ⟩ = ⟨α_ℓ·U_{ℓ−1}⟩` by Beaver, one round.
//!
//! Rounds: `max(ν + 3, 42)`. The output is the key, `⟨α⟩` and the shares of
//! `U_ν, …, U_n`.

use super::key::ShKey;
use crate::field::Field;
use crate::leaf::{fp_pre, fp_pre_cots, leaf_dabits, tag_leaf, FpPre};
use crate::{deal_walk_nu, default_nu, leaf_seed, sh_calls};
use dpf_common::aes_tower::{bits_of, block_of, mmo_shared, Mmo, OtTower, SharedKey, COTS_PER_CALL};
use dpf_common::block::{depth_for, Block};
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
    /// This party's XOR shares of the on-path states `U_ν, …, U_n` of party 0.
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
    /// COTs consumed after setup (the OT tower's, ⟨α_ℓ·Δ⟩ and ⟨t_{n,0}·Δ⟩,
    /// the bit-times-block triples, the leaf's).
    pub cots: usize,
}

/// The preprocessing of one generation.
pub struct Pre {
    /// The switch level ν.
    pub nu: usize,
    /// `⟨α⟩`: this party's share, bit `n − 1 − i` for level i + 1.
    pub alpha_share: u64,
    /// `⟨Δ⟩`: this party's share `Δ_b`, `lsb(Δ_b) = b`.
    pub delta: Block,
    /// `⟨α_ℓ·Δ⟩` for the n levels.
    pub alpha_delta: Vec<Block>,
    /// `⟨U_ν⟩, …, ⟨U_n⟩`, with `⟨U_n⟩ = ⟨Y⟩ ⊕ ⟨t_{n,0}·Δ⟩`.
    pub us: Vec<Block>,
    /// `⟨Y⟩`, `lsb(Y) = 0`: the on-path leaf state with tag 0 is Y.
    pub y: Block,
    /// `⟨t_{n,0}⟩`.
    pub t_leaf: bool,
    /// The public AES keys, `𝓕_reveal(𝓕_rand)` in preprocessing: the level
    /// keys first (one K for all levels, or `K_1, …, K_n`), then the extra
    /// ones (the malicious variants' `K_pay`, `K_mac`).
    pub keys: Vec<Mmo>,
    /// One key per level (`K_ℓ` expands level ℓ − 1 into level ℓ).
    pub per_level: bool,
    /// The OT tower, on its random COTs.
    pub be: OtTower,
    /// `(a, B, a·B)`: Step C's n − ν, the switch's two (if ν > 0), then the
    /// caller's extra ones, which [`walk`] leaves here.
    pub string_triples: Vec<(bool, Block, Block)>,
}

/// Bit-times-block triples [`walk`] consumes: Step C's and the switch's.
pub fn walk_strings(n: usize, nu: usize) -> usize {
    n - nu + if nu > 0 { 2 } else { 0 }
}

impl Pre {
    /// Index into [`keys`](Self::keys) of the key of level ℓ ≥ 1.
    pub fn level_key(&self, l: usize) -> usize {
        if self.per_level {
            l - 1
        } else {
            0
        }
    }

    /// Index of extra key j.
    pub fn extra_key(&self, j: usize) -> usize {
        if self.per_level {
            self.alpha_delta.len() + j
        } else {
            1 + j
        }
    }

    /// The keys of levels 1..=n, cloned (n of them, or one for all levels).
    pub fn level_keys(&self) -> Vec<Mmo> {
        let k = if self.per_level { self.alpha_delta.len() } else { 1 };
        self.keys[..k].to_vec()
    }

    /// The bits of α, level 1 first.
    fn alpha_bits(&self) -> Vec<bool> {
        let n = self.alpha_delta.len();
        (0..n).map(|i| (self.alpha_share >> (n - 1 - i)) & 1 == 1).collect()
    }
}

/// `⟨α_ℓ·Δ⟩` for this party's bits `a` and share `Δ_b` (𝓕_COT of the paper):
/// in each direction s, a COT with the chosen offset `Δ_s` from a Ferret
/// random COT `(q, q ⊕ cΓ_s)`, hashed into a random OT `(m_0, m_1)`, `(c,
/// m_c)`. The sender sends `u = m_0 ⊕ m_1 ⊕ Δ_s` and keeps `m_d`, the
/// receiver sends `d = a ⊕ c` and keeps `m_c ⊕ a·u`, so the two differ by
/// `a·Δ_s`. Both directions in one round; the share is `a_b·Δ_b` plus both.
pub(crate) fn alpha_delta<R: rand::RngCore + rand::CryptoRng>(
    ch: &mut Channel,
    cot: &mut CotPair,
    a: &[bool],
    delta: Block,
    rng: &mut R,
) -> Vec<Block> {
    let n = a.len();
    let me = ch.party();
    let gamma = cot.delta();
    let h = |x: Block, i: usize| cot_hash().h(x, (6 << 60) | i as u64);
    let (mut sent, mut recv): (Vec<(Block, Block)>, Vec<(bool, Block)>) = (Vec::new(), Vec::new());
    for s in 0..2 {
        match cot.random_cots(ch, s, n, rng).expect("semi-honest COT") {
            RandomCots::Sender(q) => sent = q.iter().enumerate().map(|(i, &q)| (h(q, i), h(q ^ gamma, i))).collect(),
            RandomCots::Receiver(c, m) => recv = c.iter().zip(&m).enumerate().map(|(i, (&c, &m))| (c, h(m, i))).collect(),
        }
    }
    debug_assert!(sent.len() == n && recv.len() == n && me < 2);
    let mut msg = Vec::with_capacity(17 * n);
    for (&(m0, m1), (&ai, &(c, _))) in sent.iter().zip(a.iter().zip(&recv)) {
        msg.extend_from_slice(&(m0 ^ m1 ^ delta).to_bytes());
        msg.push((ai ^ c) as u8);
    }
    ch.send(msg);
    let theirs = ch.recv();
    assert_eq!(theirs.len(), 17 * n, "malformed 𝓕_COT message");
    (0..n)
        .map(|i| {
            let (u, d) = (Block::from_bytes(&theirs[17 * i..17 * i + 16]), theirs[17 * i + 16] & 1 == 1);
            let (m0, m1) = sent[i];
            let mine = if d { m1 } else { m0 };
            let (_, mc) = recv[i];
            delta.and_bit(a[i]) ^ mine ^ mc ^ u.and_bit(a[i])
        })
        .collect()
}

/// The preprocessing of one Gen of depth n with switch level ν: the OT
/// tower's COTs for `calls` AES–MMO calls, one public key for all levels or
/// one per level (`per_level`) and `extra_keys` more, [`walk_strings`] +
/// `extra_strings` bit-times-block triples, and `cots` more COTs per
/// direction (the leaf's).
#[allow(clippy::too_many_arguments)]
pub(crate) fn precompute(
    ch: &mut Channel,
    cot: &mut CotPair,
    n: usize,
    nu: usize,
    calls: usize,
    per_level: bool,
    extra_keys: usize,
    extra_strings: usize,
    cots: usize,
    rng: &mut ChaCha20Rng,
) -> Pre {
    assert!(n >= 1 && nu <= n, "0 ≤ ν ≤ n");
    let b = ch.party();
    let pool = cot.random_cots(ch, 0, calls * COTS_PER_CALL, rng).expect("semi-honest COT");
    let be = OtTower::new(b, pool, cot.delta());
    let string_triples = rot_string_triples(ch, cot, walk_strings(n, nu) + extra_strings, rng);
    cot.precompute(ch, n + 1 + cots, n + 1 + cots, rng).expect("semi-honest COT");
    let alpha_share: u64 = rng.gen::<u64>() & dpf_common::arith::mask(n);
    let delta = Block::random(rng).with_lsb(b == 1);
    let mut us: Vec<Block> = (nu..n).map(|_| Block::random(rng)).collect();
    let y = Block::random(rng).with_lsb(false);
    let t_leaf: bool = rng.gen();
    // The keys ← 𝓕_reveal(𝓕_rand), then ⟨α_ℓ·Δ⟩ and ⟨t_{n,0}·Δ⟩ by 𝓕_COT.
    let nk = if per_level { n } else { 1 } + extra_keys;
    let k_shares: Vec<Block> = (0..nk).map(|_| Block::random(rng)).collect();
    ch.send_blocks(&k_shares);
    let keys = k_shares.iter().zip(ch.recv_blocks(nk)).map(|(&a, b)| Mmo::new((a ^ b).to_bytes())).collect();
    let bits: Vec<bool> = (0..n).map(|i| (alpha_share >> (n - 1 - i)) & 1 == 1).chain([t_leaf]).collect();
    let mut alpha_delta = alpha_delta(ch, cot, &bits, delta, rng);
    us.push(y ^ alpha_delta.pop().unwrap());
    Pre { nu, alpha_share, delta, alpha_delta, us, y, t_leaf, keys, per_level, be, string_triples }
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

/// What [`walk`] leaves: the n level words, the words `M_ν, …, M_n`, and
/// this party's shares of the outputs of the leaf jobs with the lane they
/// may be opened on (after the AES–MMO calls).
pub(crate) struct Walk {
    pub cws: Vec<Block>,
    pub ms: Vec<Block>,
    pub leaf: Vec<Block>,
    pub leaf_lane: Lane,
}

/// A deliberate deviation in [`walk`], for the malicious abort tests: ε is
/// XORed into this party's share of `CW_{i+1}` (`i < n`) or of `M_ν` (`i = n`)
/// before it is opened.
pub(crate) type WalkErr = Option<(usize, Block)>;

fn err_at(err: WalkErr, i: usize) -> Block {
    match err {
        Some((l, e)) if l == i => e,
        _ => Block::ZERO,
    }
}

/// The top phase and the switch (Figure "DPF.Gen", lines 6–13) on `lane`:
/// returns `CW_1, …, CW_ν` and `M_ν`. For ν = 0 there is no switch:
/// `⟨st_{0,0}⟩ = (Δ_0, 0)`.
fn top(pre: &Pre, ch: &mut Channel, lane: &mut Lane, triples: &mut std::vec::Drain<(bool, Block, Block)>, err: WalkErr) -> (Vec<Block>, Block) {
    let b = ch.party();
    let (n, delta) = (pre.alpha_delta.len(), pre.delta);
    if pre.nu == 0 {
        let share = if b == 0 { delta } else { Block::ZERO } ^ pre.us[0] ^ err_at(err, n);
        let m0 = share ^ Block::from_bytes(&ch.exchange_on(lane, share.to_bytes().to_vec()));
        return (vec![], m0);
    }
    let mut nodes = vec![delta];
    let mut ls = Vec::new();
    let mut cws = Vec::with_capacity(pre.nu);
    for i in 0..pre.nu {
        ls.resize(nodes.len(), Block::ZERO);
        pre.keys[pre.level_key(i + 1)].h_many(&nodes, &mut ls);
        // ⟨CW_ℓ⟩ = Z_{ℓ,b} ⊕ ⟨ᾱ_ℓ·Δ⟩, ⟨ᾱ_ℓ·Δ⟩ = ⟨Δ⟩ ⊕ ⟨α_ℓ·Δ⟩.
        let z = ls.iter().fold(Block::ZERO, |acc, &l| acc ^ l);
        let share = z ^ delta ^ pre.alpha_delta[i] ^ err_at(err, i);
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
    // Switch: E_b and A_b over level ν.
    let (e_b, a_b) = nodes.iter().filter(|s| s.lsb()).fold((Block::ZERO, 0u64), |(e, c), &s| (e ^ s, c + 1));
    // Party 0 holds a = A_0 mod 4, party 1 e = −A_1 mod 4; ⟨a_0⟩ = (a_0, 0), ⟨e_0⟩ = (0, e_0).
    let v = if b == 0 { a_b % 4 } else { (4 - a_b % 4) % 4 };
    let (x, y) = if b == 0 { (v & 1 == 1, false) } else { (false, v & 1 == 1) };
    let g = bit_times_block(ch, lane, &[(x, Block::ZERO.with_lsb(y))], triples)[0].lsb();
    // 1 ⊕ t_{ν,0} = a_1 ⊕ e_1 ⊕ a_0e_0, then ⟨st_{ν,0}⟩ = ⟨E⟩ ⊕ (1 ⊕ ⟨t_{ν,0}⟩)·⟨Δ⟩.
    let not_t = (v >> 1) & 1 == 1;
    let p = bit_times_block(ch, lane, &[(not_t ^ g, delta)], triples)[0];
    let share = e_b ^ p ^ pre.us[0] ^ err_at(err, n);
    let m_nu = share ^ Block::from_bytes(&ch.exchange_on(lane, share.to_bytes().to_vec()));
    (cws, m_nu)
}

/// Generation up to the leaf: the top phase and the switch on one lane,
/// Step C on another, the AES–MMO calls of the lower levels and the
/// `leaf_jobs` (key index, this party's share of the input) on the main line,
/// then Step B and the openings of `M_ℓ`. Consumes the first
/// [`walk_strings`] triples of `pre` and leaves the rest.
pub(crate) fn walk(pre: &mut Pre, ch: &mut Channel, leaf_jobs: &[(usize, Block)], err: WalkErr) -> Walk {
    let (n, nu, delta) = (pre.alpha_delta.len(), pre.nu, pre.delta);
    let a = pre.alpha_bits();
    let rest = pre.string_triples.split_off(walk_strings(n, nu));
    let mut mine = std::mem::replace(&mut pre.string_triples, rest);
    let mut triples = mine.drain(..);
    // Step C's triples come first, the switch's last.
    let k = n - nu;
    let mut step_c: Vec<(bool, Block, Block)> = triples.by_ref().take(k).collect();
    let mut lane = ch.lane();
    let (mut cws, m_nu) = top(pre, ch, &mut lane, &mut triples, err);
    drop(triples);
    let mut ms = vec![m_nu];
    // Step C: ⟨P_ℓ⟩ = ⟨α_ℓ·U_{ℓ−1}⟩.
    let prods = if k > 0 {
        let mut c_lane = ch.lane();
        let xy: Vec<(bool, Block)> = (0..k).map(|j| (a[nu + j], pre.us[j])).collect();
        bit_times_block(ch, &mut c_lane, &xy, &mut step_c.drain(..))
    } else {
        vec![]
    };
    // Step A (level ℓ = ν + j + 1 hashes U_{ℓ−1} under K_ℓ) and the leaf jobs, in one batch.
    let mut jobs: Vec<(usize, _)> = (0..k)
        .flat_map(|j| {
            let kl = pre.level_key(nu + j + 1);
            [(kl, bits_of(pre.us[j])), (kl, bits_of(pre.us[j] ^ delta))]
        })
        .collect();
    jobs.extend(leaf_jobs.iter().map(|&(kj, x)| (kj, bits_of(x))));
    let mut keys: Vec<SharedKey<bool>> = pre.keys.iter().map(|m| SharedKey::public(&pre.be, m)).collect();
    let out: Vec<Block> = mmo_shared(&mut pre.be, ch, &mut keys, &jobs).iter().map(block_of).collect();
    let leaf_lane = ch.lane();
    if k > 0 {
        // Step B: ⟨CW_ℓ⟩ = ⟨L_{ℓ,0}⟩ ⊕ ⟨L_{ℓ,1}⟩ ⊕ ⟨Δ⟩ ⊕ ⟨α_ℓ·Δ⟩.
        let shares: Vec<Block> = (0..k).map(|j| out[2 * j] ^ out[2 * j + 1] ^ delta ^ pre.alpha_delta[nu + j] ^ err_at(err, nu + j)).collect();
        ch.send_blocks(&shares);
        let low: Vec<Block> = shares.iter().zip(ch.recv_blocks(k)).map(|(&x, y)| x ^ y).collect();
        // ⟨M_ℓ⟩ = ⟨L_{ℓ,0}⟩ ⊕ ⟨P_ℓ⟩ ⊕ lsb(⟨U_{ℓ−1}⟩)·CW_ℓ ⊕ ⟨U_ℓ⟩.
        let shares: Vec<Block> = (0..k).map(|j| out[2 * j] ^ prods[j] ^ low[j].and_bit(pre.us[j].lsb()) ^ pre.us[j + 1]).collect();
        ch.send_blocks(&shares);
        ms.extend(shares.iter().zip(ch.recv_blocks(k)).map(|(&x, y)| x ^ y));
        cws.extend(low);
    }
    ch.join(lane);
    Walk { cws, ms, leaf: out[2 * k..].to_vec(), leaf_lane }
}

/// This party's leaf jobs of the semi-honest Gen: `H_K(s^(c) ∥ 0)` for the
/// on-path leaf states `Y`, `Y ⊕ Δ` with tags 0 and 1, under key `key`.
pub(crate) fn tag_leaf_jobs(pre: &Pre, key: usize) -> [(usize, Block); 2] {
    [(key, leaf_seed(pre.y)), (key, leaf_seed(pre.y ^ pre.delta))]
}

fn gen_with<F: Field>(mut pre: Pre, fpre: FpPre<F, F>, ch: &mut Channel, n_size: u64, beta: F) -> (ShKey<F>, usize) {
    let b = ch.party();
    let jobs = tag_leaf_jobs(&pre, 0);
    let Walk { cws, ms, leaf, mut leaf_lane } = walk(&mut pre, ch, &jobs, None);
    let w_cw = tag_leaf(ch, &mut leaf_lane, [leaf[0], leaf[1]], pre.t_leaf, &fpre.dabits, beta);
    ch.join(leaf_lane);
    let prf = pre.keys.swap_remove(0);
    (ShKey { party: b, n_size, prf, root: pre.delta, nu: pre.nu, cws, ms, w_cw }, pre.be.ands)
}

/// Runs this party's side of setup, preprocessing and generation of a key for
/// a random index α (its share is in the output) and the public payload β,
/// with switch level `nu` ([`default_nu`] if `None`).
///
/// * `ferret`: the silent-OT parameters (`Some(FerretConfig::B13)` for
///   benchmarks); `None` keeps IKNP, for tests.
pub fn gen<F: Field>(ch: &mut Channel, n_size: u64, nu: Option<usize>, beta: F, seed: [u8; 32], ferret: Option<FerretConfig>) -> GenOutput<ShKey<F>> {
    let n = depth_for(n_size);
    let dabits = leaf_dabits::<F>(&[1]);
    drive(
        ch,
        seed,
        ferret,
        n,
        nu.unwrap_or(default_nu(n)),
        fp_pre_cots::<F, F>(dabits, 0),
        |cot, rng, ch| fp_pre::<F, F, _>(ch, cot, dabits, 0, &[], rng),
        |pre, fpre, ch| gen_with(pre, fpre, ch, n_size, beta),
    )
}

/// One party's session state after setup.
pub(crate) struct Setup {
    pub cot: CotPair,
    pub rng: ChaCha20Rng,
    pub stats: CommStats,
    pub time: Duration,
}

/// Base OTs and Ferret, party b's COTs under its Ferret key `Γ_b`.
pub(crate) fn setup(ch: &mut Channel, seed: [u8; 32], ferret: Option<FerretConfig>) -> Setup {
    let t_setup = Instant::now();
    let mut rng = ChaCha20Rng::from_seed(seed);
    let gamma = Block::random(&mut rng);
    let mut cot = CotPair::setup(ch, &mut rng, gamma, false).expect("semi-honest base OT");
    if let Some(cfg) = ferret {
        cot.enable_ferret(ch, cfg, &mut rng).expect("semi-honest Ferret");
    }
    ch.sync();
    Setup { cot, rng, stats: ch.stats(), time: t_setup.elapsed() }
}

/// Setup, then preprocessing ([`precompute`] with `cots` more COTs per
/// direction, then `extra`), then `body`, the generation proper, each phase
/// timed and counted on its own.
#[allow(clippy::too_many_arguments)]
pub(crate) fn drive<K, P>(
    ch: &mut Channel,
    seed: [u8; 32],
    ferret: Option<FerretConfig>,
    n: usize,
    nu: usize,
    cots: usize,
    extra: impl FnOnce(&mut CotPair, &mut ChaCha20Rng, &mut Channel) -> P,
    body: impl FnOnce(Pre, P, &mut Channel) -> (K, usize),
) -> GenOutput<K> {
    let Setup { mut cot, mut rng, stats: setup_stats, time: setup_time } = setup(ch, seed, ferret);
    let cots_before = cot.produced;

    let t_pre = Instant::now();
    let pre = precompute(ch, &mut cot, n, nu, sh_calls(n, nu), false, 0, 0, cots, &mut rng);
    let (alpha_share, onpath_share) = (pre.alpha_share, pre.us.clone());
    let more = extra(&mut cot, &mut rng, ch);
    let pre_stats = ch.stats().since(&setup_stats);
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
        setup_stats,
        pre_stats,
        setup_time,
        pre_time,
        gen_time: t_gen.elapsed(),
        ands,
        cots: cot.produced - cots_before,
    }
}

/// Trusted-dealer generation for given roots (`lsb(root_b) = b`, the root
/// share `Δ_b`), AES key K, switch level ν and on-path states `us = [U_ν, …,
/// U_n]` of party 0: the cleartext Gen, and the bit-exact oracle of [`gen`].
/// `α < 2^n` (n = [`depth_for`]`(n_size)`).
pub fn deal<F: Field>(roots: [Block; 2], key: [u8; 16], n_size: u64, nu: usize, alpha: u64, beta: F, us: &[Block]) -> [ShKey<F>; 2] {
    let prf = Mmo::new(key);
    let (cws, ms, st) = deal_walk_nu(std::slice::from_ref(&prf), roots, depth_for(n_size), nu, alpha, us);
    let w = |s: Block| F::from_block(prf.h(leaf_seed(s)));
    let v = w(st[0]).sub(w(st[1])).sub(beta);
    let w_cw = if st[0].lsb() { v.neg() } else { v };
    let mk = |party: usize| ShKey { party, n_size, prf: prf.clone(), root: roots[party], nu, cws: cws.clone(), ms: ms.clone(), w_cw };
    [mk(0), mk(1)]
}

/// Trusted-dealer generation from a seed, switch level [`default_nu`].
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
