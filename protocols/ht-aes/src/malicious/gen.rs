//! Malicious generation with abort on the semi-honest preprocessing.
//!
//! Gen is the semi-honest one ([`crate::semi_honest`]), on the same
//! preprocessing (the paper's ⟨α⟩, ⟨Δ⟩, keys and ⟨α_ℓ·Δ⟩; the OT tower's
//! COTs, string triples), extended as in the paper's "Authenticated
//! generation":
//!
//! 1. A persistent payload-MAC key `δ = δ_0 ⊕ δ_1 ∈ GF(2^128)`, sampled once
//!    per session and never opened.
//! 2. The MAC mask `F^mac = H_{K''}(· ∥ 0)` under a third shared key K'' on
//!    both leaf seeds, in parallel with `F^pay`; K'' is expanded with K and
//!    K' at level 1 and opened with them.
//! 3. `⟨δ·β⟩ = Σ_i β_i·⟨X^i δ⟩`: ℓ bit-times-block Beaver products, opened
//!    with the level-1 message. The Π_Verify mask `(⟨r⟩, ⟨δr⟩)` for a fresh
//!    random r, input-independent, is 128 more in preprocessing.
//! 4. `W_CW = W_0 ⊕ W_1 ⊕ β` and `W^MAC_CW = W̃_0 ⊕ W̃_1 ⊕ δβ`, opened
//!    together with K, K', K'' (in a binary payload group the sign
//!    `(−1)^{t_{n,0}}` is 1).
//!
//! Every deviation in Gen, in the PRF products, the branch selection or an
//! opening, shows up only in the published key material, which Π_Verify
//! ([`super::verify`]) checks at evaluation time (Propositions "One-Hot" and
//! "MAC Detection" of the paper).
//!
//! Rounds: `41n + 40 + 1 = 41n + 41`.

use super::key::{low, MalKey};
use crate::malicious_arith::VerifyMask;
use crate::semi_honest::gen::{precompute, setup, walk, Pre, Setup, Walk};
use crate::{deal_walk, key_bytes, leaf_seed, open_keys, MAL_KEYS};
use dpf_common::aes_tower::{bits_of, block_of, mmo_shared, Mmo};
use dpf_common::block::{depth_for, Block};
use dpf_common::gf128;
use dpf_common::net::{Channel, CommStats};
use dpf_common::ot::FerretConfig;
use rand::{CryptoRng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use std::time::{Duration, Instant};

/// AES–MMO calls of one malicious Gen: two per level, four at the leaf.
pub fn mal_calls(n: usize) -> usize {
    2 * n + 4
}

/// ANDs of one malicious Gen: the calls and Π_KeyExp of K, K', K''.
pub fn mal_ands(n: usize) -> usize {
    mal_calls(n) * dpf_common::aes_tower::ANDS_PER_CALL + MAL_KEYS * dpf_common::aes_tower::ANDS_PER_KEY
}

/// Deliberate deviation for the abort tests: XOR `err` into this party's
/// share of the word opened at `level` (`n` = the payload word, `n + 1` = the
/// payload-MAC word, `n + 2` = the state key K) before opening it.
#[derive(Clone, Copy, Debug)]
pub struct Fault {
    pub level: usize,
    pub err: Block,
}

/// `x_i·y_i` for XOR-shared bits x and blocks y from bit-times-block Beaver
/// triples, given both parties' openings `(y ⊕ B, x ⊕ a)` (17 bytes each).
fn beaver_products(b: usize, sel: &[(bool, Block)], triples: &[(bool, Block, Block)], theirs: &[u8]) -> Vec<Block> {
    assert_eq!(theirs.len(), 17 * sel.len(), "malformed Beaver opening");
    sel.iter()
        .zip(triples)
        .enumerate()
        .map(|(i, (&(x, y), &(ta, tb, tc)))| {
            let f = y ^ tb ^ Block::from_bytes(&theirs[17 * i..17 * i + 16]);
            let e = x ^ ta ^ (theirs[17 * i + 16] & 1 == 1);
            f.and_bit(e && b == 0) ^ tb.and_bit(e) ^ f.and_bit(ta) ^ tc
        })
        .collect()
}

/// This party's Beaver openings `(y ⊕ B, x ⊕ a)`.
fn beaver_msg(sel: &[(bool, Block)], triples: &[(bool, Block, Block)]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(17 * sel.len());
    for (&(x, y), &(ta, tb, _)) in sel.iter().zip(triples) {
        msg.extend_from_slice(&(y ^ tb).to_bytes());
        msg.push((x ^ ta) as u8);
    }
    msg
}

/// The preprocessing of one malicious Gen: the semi-honest one with three
/// keys and `n + ℓ` string triples, and the key's Π_Verify mask.
pub struct MalPre {
    pub pre: Pre,
    pub mask: VerifyMask<Block>,
}

/// One party's long-lived state.
pub struct MalSession {
    s: Setup,
    /// `δ_b`, this party's share of the persistent payload-MAC key.
    pub delta_mac: Block,
}

impl MalSession {
    /// The semi-honest setup (base OTs, Ferret) and δ_b.
    pub fn setup(ch: &mut Channel, seed: [u8; 32], ferret: Option<FerretConfig>) -> Self {
        let mut s = setup(ch, seed, ferret);
        let delta_mac = Block::random(&mut s.rng);
        MalSession { s, delta_mac }
    }

    /// The preprocessing of one Gen (`semi_honest::gen::precompute` for [`mal_calls`]
    /// AES–MMO calls, three keys, `n + ℓ` string triples for the branch
    /// selection and δ·β), and the Π_Verify mask: a random r and `⟨δr⟩ = Σ_i
    /// r_i·⟨X^i δ⟩` from 128 more string triples, one round.
    pub fn precompute(&mut self, ch: &mut Channel, n: usize, bits: usize) -> MalPre {
        let s = &mut self.s;
        let mut pre = precompute(ch, &mut s.cot, n, mal_calls(n), MAL_KEYS, n + bits + 128, 0, &mut s.rng);
        let mt = pre.string_triples.split_off(n + bits);
        let r = Block::random(&mut s.rng);
        let sel: Vec<(bool, Block)> = (0..128).map(|i| (r.bit(i), gf128::mul(Block(1 << i), self.delta_mac))).collect();
        ch.send(beaver_msg(&sel, &mt));
        let theirs = ch.recv();
        let dr = beaver_products(ch.party(), &sel, &mt, &theirs).into_iter().fold(Block::ZERO, |a, x| a ^ x);
        MalPre { pre, mask: VerifyMask { r, dr } }
    }

    /// One generation of a key for the random α of `pre` and `β ∈ {0,1}^ℓ`
    /// (XOR shares). Returns the key, the ANDs, the key's Π_Verify mask and
    /// this party's share of α.
    #[allow(clippy::too_many_arguments)]
    pub fn gen(
        &mut self,
        ch: &mut Channel,
        n_size: u64,
        bits: usize,
        beta_share: Block,
        pre: MalPre,
        fault: Option<Fault>,
    ) -> (MalKey, usize, VerifyMask<Block>, u64) {
        let b = ch.party();
        let n = depth_for(n_size);
        let err = |lvl: usize| match fault {
            Some(f) if f.level == lvl => f.err,
            _ => Block::ZERO,
        };
        let MalPre { mut pre, mask } = pre;
        let dm = pre.string_triples.split_off(n);

        // 3. Beaver openings of β_i·(X^i δ), riding with level 1.
        let sel: Vec<(bool, Block)> = (0..bits).map(|i| (beta_share.bit(i), gf128::mul(Block(1 << i), self.delta_mac))).collect();
        let extra = beaver_msg(&sel, &dm);
        let cw_err = fault.filter(|f| f.level < n).map(|f| (f.level, f.err));
        let Walk { st, cws, reply } = walk(&mut pre, ch, &extra, cw_err);
        let db = beaver_products(b, &sel, &dm, &reply).into_iter().fold(Block::ZERO, |a, x| a ^ x);

        // 2 + 4. Leaf words.
        let delta = pre.delta;
        let (s0, s1) = (bits_of(leaf_seed(st)), bits_of(leaf_seed(st ^ delta)));
        let w: Vec<Block> = mmo_shared(&mut pre.be, ch, &mut pre.keys, &[(1, s0), (1, s1), (2, s0), (2, s1)]).iter().map(block_of).collect();
        let w_share = low(w[0] ^ w[1], bits) ^ beta_share ^ low(err(n), bits);
        let wm_share = w[2] ^ w[3] ^ db ^ err(n + 1);
        let mut msg = w_share.to_bytes().to_vec();
        msg.extend_from_slice(&wm_share.to_bytes());
        let mut ks = pre.key_shares.clone();
        ks[0] ^= err(n + 2);
        msg.extend(key_bytes(&ks));
        ch.send(msg);
        let mut theirs = ch.recv();
        assert_eq!(theirs.len(), 32 + 16 * MAL_KEYS, "malformed payload words");
        let mut prf = open_keys(&ks, &theirs.split_off(32)).into_iter();
        let (prf, pay, mac) = (prf.next().unwrap(), prf.next().unwrap(), prf.next().unwrap());
        let w_cw = w_share ^ Block::from_bytes(&theirs[..16]);
        let wm_cw = wm_share ^ Block::from_bytes(&theirs[16..]);
        (MalKey { party: b, n_size, bits, prf, pay, mac, root: delta, cws, w_cw: low(w_cw, bits), wm_cw }, pre.be.ands, mask, pre.alpha_share)
    }
}

/// Everything one party gets from [`run_mal`].
pub struct MalRun {
    pub key: MalKey,
    /// This party's XOR share of the random index α.
    pub alpha_share: u64,
    /// This party's share of the payload-MAC key δ.
    pub delta_share: Block,
    /// This party's share of the key's Π_Verify mask.
    pub mask: VerifyMask<Block>,
    /// Base OTs and the Ferret bootstrap.
    pub setup_stats: CommStats,
    pub setup_time: Duration,
    pub pre_stats: CommStats,
    pub pre_time: Duration,
    pub gen_stats: CommStats,
    pub gen_time: Duration,
    /// ANDs of the AES calls.
    pub ands: usize,
    /// COTs consumed after setup (the OT tower's, ⟨α_ℓ·Δ⟩, string triples).
    pub cots: usize,
}

/// Setup, preprocessing and generation for one party.
#[allow(clippy::too_many_arguments)]
pub fn run_mal(
    ch: &mut Channel,
    n_size: u64,
    bits: usize,
    beta_share: Block,
    seed: [u8; 32],
    ferret: Option<FerretConfig>,
    fault: Option<Fault>,
) -> MalRun {
    assert!((1..=128).contains(&bits));
    let mut s = MalSession::setup(ch, seed, ferret);
    let (setup_stats, setup_time) = (s.s.stats, s.s.time);
    let cots_before = s.s.cot.produced;
    let n = depth_for(n_size);
    let t_pre = Instant::now();
    let pre = s.precompute(ch, n, bits);
    let pre_stats = ch.stats().since(&setup_stats);
    let pre_time = t_pre.elapsed();
    // Timing only: counted in no phase.
    ch.sync();
    let before = ch.stats();
    let t = Instant::now();
    let (key, ands, mask, alpha_share) = s.gen(ch, n_size, bits, beta_share, pre, fault);
    MalRun {
        key,
        alpha_share,
        delta_share: s.delta_mac,
        mask,
        setup_stats,
        setup_time,
        pre_stats,
        pre_time,
        gen_stats: ch.stats().since(&before),
        gen_time: t.elapsed(),
        ands,
        cots: s.s.cot.produced - cots_before,
    }
}

/// Trusted-dealer generation for given roots (`lsb(root_b) = b`), AES keys
/// `[K, K', K'']` and payload-MAC key δ: the cleartext Gen and the oracle of
/// [`MalSession::gen`].
pub fn deal(roots: [Block; 2], keys: [[u8; 16]; MAL_KEYS], n_size: u64, bits: usize, alpha: u64, beta: Block, delta_mac: Block) -> [MalKey; 2] {
    assert_eq!(beta, low(beta, bits), "β must fit in the output width");
    let [prf, pay, mac] = keys.map(Mmo::new);
    let (cws, st) = deal_walk(&prf, roots, depth_for(n_size), alpha);
    let s = [leaf_seed(st[0]), leaf_seed(st[1])];
    let w_cw = low(pay.h(s[0]) ^ pay.h(s[1]), bits) ^ beta;
    let wm_cw = mac.h(s[0]) ^ mac.h(s[1]) ^ gf128::mul(delta_mac, beta);
    let mk = |party: usize| MalKey {
        party,
        n_size,
        bits,
        prf: prf.clone(),
        pay: pay.clone(),
        mac: mac.clone(),
        root: roots[party],
        cws: cws.clone(),
        w_cw,
        wm_cw,
    };
    [mk(0), mk(1)]
}

/// Shares of a Π_Verify mask `(r, δr)` in GF(2^128) for a known δ (a dealer's).
pub fn deal_mask<R: RngCore + CryptoRng>(delta_mac: Block, rng: &mut R) -> [VerifyMask<Block>; 2] {
    let (r, r0, d0) = (Block::random(rng), Block::random(rng), Block::random(rng));
    [VerifyMask { r: r0, dr: d0 }, VerifyMask { r: r ^ r0, dr: gf128::mul(delta_mac, r) ^ d0 }]
}

/// Dealer keys from a seed, with the δ shares.
pub fn gen_reference(n_size: u64, bits: usize, alpha: u64, beta: Block, seed: [u8; 32]) -> ([MalKey; 2], [Block; 2]) {
    assert!(alpha < n_size);
    let mut rng = ChaCha20Rng::from_seed(seed);
    let roots = [Block::random(&mut rng).with_lsb(false), Block::random(&mut rng).with_lsb(true)];
    let keys: [[u8; 16]; MAL_KEYS] = std::array::from_fn(|_| Block::random(&mut rng).to_bytes());
    let d = [Block::random(&mut rng), Block::random(&mut rng)];
    (deal(roots, keys, n_size, bits, alpha, beta, d[0] ^ d[1]), d)
}
