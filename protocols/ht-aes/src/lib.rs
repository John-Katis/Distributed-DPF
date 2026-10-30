//! Our distributed half-tree DPF (the paper's `htDPF.Gen`, §"Fully
//! Distributed DPF"), with `F_PRF` instantiated by AES–MMO under a shared key in 2PC
//! on the OT tower ([`dpf_common::aes_tower::OtTower`]): every AND of the
//! S-boxes from Ferret COTs.
//!
//! Unlike the Floram line, neither party ever expands a tree in Gen: both keep
//! only XOR shares of the on-path state `st_{ℓ,0}` (and `st_{ℓ,1} = st_{ℓ,0} ⊕
//! Δ`), so Gen is `O(n)` in local work and communication. Per level ℓ:
//!
//! * A: `⟨L_b⟩ = F(⟨st_{ℓ−1,b}⟩)` for `b ∈ {0, 1}`, two AES–MMO calls in 2PC
//!   (5,760 ANDs, 2,880 COTs and 40 rounds each, run in parallel);
//! * B: `CW_ℓ = L_0 ⊕ L_1 ⊕ Δ ⊕ α_ℓ·Δ` is opened (`⟨α_ℓ·Δ⟩` from one COT per
//!   direction);
//! * C: `st_{ℓ,0} = L_0 ⊕ α_ℓ·st_{ℓ−1,0} ⊕ t_{ℓ−1,0}·CW_ℓ`, one bit-times-block
//!   product, whose opening rides with B.
//!
//! `Δ = Δ_0 ⊕ Δ_1` (`lsb(Δ_b) = b`, so lsb(Δ) = 1) is the XOR of the parties'
//! COT keys. The AES keys K (state), K' (payload) and, in the malicious
//! variants, K'' (MAC) are XOR-shared per Gen (`𝓕_rand`), expanded on shares
//! by Π_KeyExp alongside the level-1 calls, and opened with the last message
//! of Gen. The key of party b is its root `st_{0,b}`, fresh per Gen with
//! `st_{0,0} ⊕ st_{0,1} = Δ` and `lsb(st_{0,b}) = b`, and the public part: K,
//! K' (K''), the words; evaluation is a local half-tree walk with `L =
//! H_K(st)`, `R = st ⊕ L`, `st' = child ⊕ t·CW`. The payload is read at the
//! leaf through `F^pay(s) = H_{K'}(s ∥ 0)`.
//!
//! * [`semi_honest`]: payload in `G = F_p` ([`field`]), the paper's leaf
//!   ([`leaf`]: B2A by daBits, the sign by a daBit and one Beaver triple).
//! * [`malicious`]: the semi-honest Gen on the same preprocessing, plus the
//!   paper's payload-MAC word `W^MAC_CW` under a persistent key δ and
//!   Π_Verify on the outputs; payload in `{0,1}^ℓ ⊂ GF(2^128)`.
//! * [`malicious_arith`]: the same for an arithmetic payload in F_p, on the
//!   leaf of [`leaf`] (`δ·β` by one more Beaver product).
//! * [`semi_honest::bin`]: the semi-honest Gen with a binary payload, no B2A.

pub mod field;
pub mod leaf;
pub mod malicious;
pub mod malicious_arith;
pub mod semi_honest;

use dpf_common::aes_tower::{bits_of, Mmo, SharedKey, ANDS_PER_CALL, ANDS_PER_KEY};
use dpf_common::block::Block;
use rand::{CryptoRng, RngCore};

/// AES keys of the semi-honest variants: `K` (the state expansion `F = H_K`)
/// and `K'` (the payload mask `F^pay = H_{K'}(· ∥ 0)`).
pub const SH_KEYS: usize = 2;
/// AES keys of the malicious variants: `K`, `K'` and `K''` (the MAC mask
/// `F^mac = H_{K''}(· ∥ 0)`).
pub const MAL_KEYS: usize = 3;

/// This party's shares of `k` fresh AES keys (`𝓕_rand`: each party samples
/// its own share), and their sharings for [`dpf_common::aes_tower::mmo_shared`].
pub(crate) fn sample_keys<R: RngCore + CryptoRng>(rng: &mut R, k: usize) -> (Vec<Block>, Vec<SharedKey<bool>>) {
    let mine: Vec<Block> = (0..k).map(|_| Block::random(rng)).collect();
    let shared = mine.iter().map(|&x| SharedKey::new(bits_of(x))).collect();
    (mine, shared)
}

/// The key shares as one message, opened with the last message of Gen.
pub(crate) fn key_bytes(mine: &[Block]) -> Vec<u8> {
    mine.iter().flat_map(|k| k.to_bytes()).collect()
}

/// `𝓕_Reveal(⟨K_j⟩)` from this party's shares and the other party's message.
pub(crate) fn open_keys(mine: &[Block], theirs: &[u8]) -> Vec<Mmo> {
    assert_eq!(theirs.len(), 16 * mine.len(), "malformed key shares");
    mine.iter().zip(theirs.chunks(16)).map(|(&k, t)| Mmo::new((k ^ Block::from_bytes(t)).to_bytes())).collect()
}

/// One half-tree step under `F = f`: the child of `st` in direction `bit`, corrected.
#[inline]
pub fn child(f: &Mmo, st: Block, cw: Block, bit: bool) -> Block {
    let l = f.h(st);
    let c = if bit { st ^ l } else { l };
    c ^ cw.and_bit(st.lsb())
}

/// [`child`] for a whole batch: appends both corrected children of every
/// parent to `out`, interleaved `[L(p0), R(p0), L(p1), …]`.
pub fn children(f: &Mmo, parents: &[Block], cw: Block, out: &mut Vec<Block>) {
    let (start, k) = (out.len(), parents.len());
    out.resize(start + 2 * k, Block::ZERO);
    let kids = &mut out[start..];
    // H(parents) into the upper half, then spread in place: slot i is read
    // before slots 2i, 2i + 1 ≤ k + i are written.
    f.h_many(parents, &mut kids[k..]);
    for (i, &st) in parents.iter().enumerate() {
        let lv = kids[k + i] ^ cw.and_bit(st.lsb());
        kids[2 * i] = lv;
        kids[2 * i + 1] = st ^ lv;
    }
}

/// The cleartext walk of a dealer: the n level words for roots `st` (`st_0 ⊕
/// st_1 = Δ`) and α, and the two leaf states.
pub(crate) fn deal_walk(f: &Mmo, roots: [Block; 2], n: usize, alpha: u64) -> (Vec<Block>, [Block; 2]) {
    assert!(!roots[0].lsb() && roots[1].lsb(), "lsb(root_b) = b");
    let delta = roots[0] ^ roots[1];
    let mut st = roots;
    let mut cws = Vec::with_capacity(n);
    for i in 0..n {
        let a = (alpha >> (n - 1 - i)) & 1 == 1;
        let cw = f.h(st[0]) ^ f.h(st[1]) ^ delta.and_bit(!a);
        st = [child(f, st[0], cw, a), child(f, st[1], cw, a)];
        cws.push(cw);
    }
    debug_assert_eq!(st[0] ^ st[1], delta);
    (cws, st)
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

/// ANDs in one semi-honest Gen of depth n: the calls and Π_KeyExp of K, K'.
pub fn sh_ands(n: usize) -> usize {
    sh_calls(n) * ANDS_PER_CALL + SH_KEYS * ANDS_PER_KEY
}
