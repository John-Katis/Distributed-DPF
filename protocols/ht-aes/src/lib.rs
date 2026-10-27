//! Our distributed half-tree DPF (the paper's `htDPF.Gen`, §"Fully
//! Distributed DPF"), with `F_PRF` instantiated by fixed-key AES–MMO in 2PC
//! over the F4 tower ([`dpf_common::aes_tower`]).
//!
//! Unlike the Floram line, neither party ever expands a tree in Gen: both keep
//! only XOR shares of the on-path state `st_{ℓ,0}` (and `st_{ℓ,1} = st_{ℓ,0} ⊕
//! Δ`), so Gen is `O(n)` in local work and communication. Per level ℓ:
//!
//! * A: `⟨L_b⟩ = F(⟨st_{ℓ−1,b}⟩)` for `b ∈ {0, 1}`, two AES–MMO calls in 2PC
//!   (1,920 F4 products and 40 rounds each, run in parallel);
//! * B: `CW_ℓ = L_0 ⊕ L_1 ⊕ Δ ⊕ α_ℓ·Δ` is opened (`⟨α_ℓ·Δ⟩` from one COT per
//!   direction);
//! * C: `st_{ℓ,0} = L_0 ⊕ α_ℓ·st_{ℓ−1,0} ⊕ t_{ℓ−1,0}·CW_ℓ`, one bit-times-block
//!   product, whose opening rides with B.
//!
//! `Δ = Δ_0 ⊕ Δ_1` (`lsb(Δ_b) = b`, so lsb(Δ) = 1) is the XOR of the parties'
//! COT keys. The key of party b is its root `st_{0,b}`, fresh per Gen with
//! `st_{0,0} ⊕ st_{0,1} = Δ` and `lsb(st_{0,b}) = b`, and the public words; evaluation is a local
//! half-tree walk with `L = F(st)`, `R = st ⊕ L`, `st' = child ⊕ t·CW`. The
//! payload is read at the leaf through a second hash `F^pay(s) = H'(s ∥ 0)`.
//!
//! * [`semi_honest`]: payload in `G = F_p` ([`field`]), F4 triples from
//!   FOLEAGE ([`dpf_common::foleage`]), the paper's leaf ([`leaf`]: B2A by
//!   daBits, the sign by a daBit and one Beaver triple).
//! * [`malicious`]: the semi-honest Gen on the same preprocessing, plus the
//!   paper's payload-MAC word `W^MAC_CW` under a persistent key δ and
//!   Π_Verify on the outputs; payload in `{0,1}^ℓ ⊂ GF(2^128)`.
//! * [`malicious_arith`]: the same for an arithmetic payload in F_p, on the
//!   leaf of [`leaf`] (`δ·β` by one more Beaver product).
//! * [`semi_honest::bin`]: the semi-honest Gen with a binary payload, no B2A.
//! * [`malicious_auth`]: additionally every share authenticated (bit MACs in
//!   GF(2^128), the layer (A1)–(A5) against selective failure), F4 triples
//!   from leaky authenticated triples with bucketing on malicious Ferret.

pub mod field;
pub mod leaf;
pub mod malicious;
pub mod malicious_arith;
pub mod malicious_auth;
pub mod semi_honest;

use dpf_common::aes_tower::{Mmo, PRODUCTS_PER_CALL, ROUNDS_PER_CALL};
use dpf_common::block::Block;
use std::sync::OnceLock;

/// The state-expansion PRF `F = H_K` (fixed public AES key).
pub fn state_hash() -> &'static Mmo {
    static H: OnceLock<Mmo> = OnceLock::new();
    H.get_or_init(|| Mmo::new(*b"ht-aes/state-prf"))
}

/// The payload mask `F^pay`, an independent public key.
pub fn pay_hash() -> &'static Mmo {
    static H: OnceLock<Mmo> = OnceLock::new();
    H.get_or_init(|| Mmo::new(*b"ht-aes/payload!!"))
}

/// The payload-MAC mask `F^mac` of the malicious variant, a third key.
pub fn mac_hash() -> &'static Mmo {
    static H: OnceLock<Mmo> = OnceLock::new();
    H.get_or_init(|| Mmo::new(*b"ht-aes/mac-mask!"))
}

/// One half-tree step: the child of `st` in direction `bit`, corrected.
#[inline]
pub fn child(st: Block, cw: Block, bit: bool) -> Block {
    let l = state_hash().h(st);
    let c = if bit { st ^ l } else { l };
    c ^ cw.and_bit(st.lsb())
}

/// [`child`] for a whole batch: appends both corrected children of every
/// parent to `out`, interleaved `[L(p0), R(p0), L(p1), …]`.
pub fn children(parents: &[Block], cw: Block, out: &mut Vec<Block>) {
    let (start, k) = (out.len(), parents.len());
    out.resize(start + 2 * k, Block::ZERO);
    let kids = &mut out[start..];
    // H(parents) into the upper half, then spread in place: slot i is read
    // before slots 2i, 2i + 1 ≤ k + i are written.
    state_hash().h_many(parents, &mut kids[k..]);
    for (i, &st) in parents.iter().enumerate() {
        let lv = kids[k + i] ^ cw.and_bit(st.lsb());
        kids[2 * i] = lv;
        kids[2 * i + 1] = st ^ lv;
    }
}

/// The leaf input of the payload hashes: the seed with its control bit cleared.
#[inline]
pub fn leaf_seed(st: Block) -> Block {
    st.with_lsb(false)
}

/// AES–MMO calls in one semi-honest Gen of depth n: two per level, two at the
/// leaf.
pub fn sh_calls(n: usize) -> usize {
    2 * n + 2
}

/// F4 products in one semi-honest Gen of depth n.
pub fn sh_products(n: usize) -> usize {
    sh_calls(n) * PRODUCTS_PER_CALL
}

/// Rounds of the AES calls of one Gen of depth n (levels and leaf).
pub fn aes_rounds(n: usize) -> usize {
    (n + 1) * ROUNDS_PER_CALL
}
