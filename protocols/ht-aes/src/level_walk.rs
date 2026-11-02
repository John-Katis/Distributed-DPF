//! The level-by-level Gen under XOR-shared AES keys that the malicious
//! variants run ([`crate::malicious`], [`crate::malicious_arith`]): the
//! paper's §malicious still assumes keys that stay secret until the end of
//! Gen and is yet to be revised to the public-K top phase and level
//! independence of the semi-honest Gen ([`crate::semi_honest::gen`]).
//!
//! Neither party expands a tree: both keep XOR shares of the on-path state
//! `st_{ℓ,0}` (and `st_{ℓ,1} = st_{ℓ,0} ⊕ Δ`). Per level ℓ:
//!
//! * A: `⟨L_b⟩ = F(⟨st_{ℓ−1,b}⟩)` for `b ∈ {0, 1}`, two AES–MMO calls in 2PC;
//! * B: `CW_ℓ = L_0 ⊕ L_1 ⊕ Δ ⊕ α_ℓ·Δ` is opened (`⟨α_ℓ·Δ⟩` preprocessed);
//! * C: `st_{ℓ,0} = L_0 ⊕ α_ℓ·st_{ℓ−1,0} ⊕ t_{ℓ−1,0}·CW_ℓ`, one bit-times-block
//!   product, whose opening rides with B.
//!
//! The keys are expanded on shares by Π_KeyExp alongside the level-1 calls
//! and opened with the last message of Gen.

use crate::sample_keys;
use crate::semi_honest::gen::alpha_delta;
use dpf_common::aes_tower::{bits_of, block_of, mmo_shared, OtTower, SharedKey, COTS_PER_CALL, COTS_PER_KEY};
use dpf_common::block::Block;
use dpf_common::bool2pc::rot_string_triples;
use dpf_common::net::Channel;
use dpf_common::ot::CotPair;
use rand::Rng;
use rand_chacha::ChaCha20Rng;

/// The preprocessing of one generation.
pub struct Pre {
    /// `⟨α⟩`: this party's share, bit `n − 1 − i` for level i + 1.
    pub alpha_share: u64,
    /// `⟨Δ⟩`: this party's share `Δ_b`, `lsb(Δ_b) = b`.
    pub delta: Block,
    /// `⟨α_ℓ·Δ⟩` for the n levels.
    pub alpha_delta: Vec<Block>,
    /// `⟨K⟩, ⟨K'⟩ (, ⟨K''⟩)`: this party's shares and their sharings.
    pub key_shares: Vec<Block>,
    pub keys: Vec<SharedKey<bool>>,
    /// The OT tower, on its random COTs.
    pub be: OtTower,
    /// `(a, B, a·B)`: n for the branch selections, then any extra ones.
    pub string_triples: Vec<(bool, Block, Block)>,
}

impl Pre {
    /// The bits of α, level 1 first.
    pub(crate) fn alpha_bits(&self) -> Vec<bool> {
        let n = self.alpha_delta.len();
        (0..n).map(|i| (self.alpha_share >> (n - 1 - i)) & 1 == 1).collect()
    }
}

/// The preprocessing of one Gen of depth n: the paper's (α, Δ, `keys` AES
/// keys, ⟨α_ℓ·Δ⟩) and the OT tower's COTs for `calls` AES–MMO calls and the
/// `keys` key expansions, `strings` bit-times-block triples from Ferret
/// random OTs (n of them for Step C) and `cots` more COTs per direction.
#[allow(clippy::too_many_arguments)]
pub(crate) fn precompute(
    ch: &mut Channel,
    cot: &mut CotPair,
    n: usize,
    calls: usize,
    keys: usize,
    strings: usize,
    cots: usize,
    rng: &mut ChaCha20Rng,
) -> Pre {
    assert!(n >= 1 && strings >= n);
    let b = ch.party();
    let pool = cot.random_cots(ch, 0, calls * COTS_PER_CALL + keys * COTS_PER_KEY, rng).expect("semi-honest COT");
    let be = OtTower::new(b, pool, cot.delta());
    let string_triples = rot_string_triples(ch, cot, strings, rng);
    cot.precompute(ch, n + cots, n + cots, rng).expect("semi-honest COT");
    let alpha_share: u64 = rng.gen::<u64>() & dpf_common::arith::mask(n);
    let delta = Block::random(rng).with_lsb(b == 1);
    let (key_shares, keys) = sample_keys(rng, keys);
    let a: Vec<bool> = (0..n).map(|i| (alpha_share >> (n - 1 - i)) & 1 == 1).collect();
    let alpha_delta = alpha_delta(ch, cot, &a, delta, rng);
    Pre { alpha_share, delta, alpha_delta, key_shares, keys, be, string_triples }
}

/// What [`walk`] leaves: this party's share of `st_{n,0}`, the n level
/// words, and the peer's `extra`.
pub(crate) struct Walk {
    pub st: Block,
    pub cws: Vec<Block>,
    pub reply: Vec<u8>,
}

/// Initialization and the n levels of Figure "DPF.Gen" under `F = H_K` with
/// `pre.keys[0] = ⟨K⟩`; every key in `pre.keys` is expanded during level 1.
/// `extra` rides with the level-1 message and the other party's `extra` (of
/// the same length) is returned. `cw_err = Some((ℓ, ε))` XORs ε into this
/// party's CW share at level ℓ (a deliberate deviation, for the malicious
/// abort tests).
pub(crate) fn walk(pre: &mut Pre, ch: &mut Channel, extra: &[u8], cw_err: Option<(usize, Block)>) -> Walk {
    let b = ch.party();
    let n = pre.alpha_delta.len();
    let delta = pre.delta;
    let a = pre.alpha_bits();
    // Initialization: ⟨st_{0,0}⟩ = (Δ_0, 0).
    let mut st = if b == 0 { delta } else { Block::ZERO };
    let mut cws = Vec::with_capacity(n);
    let mut reply = Vec::new();
    for i in 0..n {
        // Step A: L_0, L_1.
        let l = mmo_shared(&mut pre.be, ch, &mut pre.keys, &[(0, bits_of(st)), (0, bits_of(st ^ delta))]);
        let (l0, l1) = (block_of(&l[0]), block_of(&l[1]));
        // Step B: ⟨CW_ℓ⟩ = ⟨L_0⟩ ⊕ ⟨L_1⟩ ⊕ ⟨Δ⟩ ⊕ ⟨α_ℓ·Δ⟩, opened with Step C's Beaver masks.
        let mut cw_share = l0 ^ l1 ^ delta ^ pre.alpha_delta[i];
        if let Some((lvl, e)) = cw_err {
            if lvl == i {
                cw_share ^= e;
            }
        }
        let (ta, tb, tc) = pre.string_triples[i];
        let (e, f) = (a[i] ^ ta, st ^ tb);
        let x = if i == 0 { extra.len() } else { 0 };
        let mut msg = Vec::with_capacity(33 + x);
        msg.extend_from_slice(&cw_share.to_bytes());
        msg.extend_from_slice(&f.to_bytes());
        msg.push(e as u8);
        msg.extend_from_slice(&extra[..x]);
        ch.send(msg);
        let mut theirs = ch.recv();
        assert_eq!(theirs.len(), 33 + x, "malformed level message");
        if i == 0 {
            reply = theirs.split_off(33);
        }
        let cw = cw_share ^ Block::from_bytes(&theirs[..16]);
        let (f, e) = (f ^ Block::from_bytes(&theirs[16..32]), e ^ (theirs[32] & 1 == 1));
        // Step C: ⟨P_ℓ⟩ = ⟨α_ℓ·st_{ℓ−1,0}⟩ = e·f ⊕ e·B ⊕ f·a ⊕ C, then
        // ⟨st_{ℓ,0}⟩ = ⟨L_0⟩ ⊕ ⟨P_ℓ⟩ ⊕ ⟨t_{ℓ−1,0}⟩·CW_ℓ.
        let prod = f.and_bit(e && b == 0) ^ tb.and_bit(e) ^ f.and_bit(ta) ^ tc;
        st = l0 ^ prod ^ cw.and_bit(st.lsb());
        cws.push(cw);
    }
    Walk { st, cws, reply }
}
