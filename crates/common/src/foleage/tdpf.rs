//! The ternary random DPF of FOLEAGE (Fig. 5, `libs/tri-dpf`) with early
//! termination.
//!
//! A node is a 128-bit seed whose lsb is its control bit `t`. Its three
//! children are `G_j(s) = AES_{k_j}(s) ⊕ s`, `j ∈ {0, 1, 2}` (three fixed
//! keys, Davies–Meyer, as `PRFEval`), and a level's correction word is three
//! blocks `CW_i = (CW_{i,0}, CW_{i,1}, CW_{i,2})`, XORed into the children of
//! every node with `t = 1`. Below the last level a leaf seed `s` is stretched
//! to [`LEAF_BLOCKS`] blocks, `AES_{k_ext}(s ⊕ j) ⊕ (s ⊕ j)` (`ExtendOutput`),
//! and the leaf output is `Ext(s) ⊕ t·CW_out`. One leaf holds `3^v` F4
//! elements (lane `i` of the 4 blocks, `v ≤ 5`), so a key covers the domain
//! `3^{depth + v}`.
//!
//! As a random DPF (Def. 7), the on-path seeds differ by a random value at
//! every level (`CW_{i,α_i} = S_{i,α_i} ⊕ r_i` with `lsb(r_i)` chosen so the
//! control bits differ) and off-path ones are equal; `CW_out` then programs the
//! leaf at α ([`deal`]).

// `aes` 0.8 re-exports generic-array 0.14, whose newest patch release marks it deprecated.
#![allow(deprecated)]

use crate::block::Block;
use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockEncrypt, KeyInit};
use aes::Aes128;
use rand::{CryptoRng, RngCore};
use std::sync::OnceLock;

/// Blocks per leaf: 256 F4 lanes, of which `3^v ≤ 243` are used.
pub const LEAF_BLOCKS: usize = 4;
/// F4 elements in a leaf for `v` leaf trits.
pub const fn leaf_len(v: usize) -> usize {
    3usize.pow(v as u32)
}

/// The length-tripling PRG and the leaf extension.
pub struct TriPrg {
    child: [Aes128; 3],
    ext: Aes128,
}

/// The fixed keys of [`TriPrg`].
pub fn tri_prg() -> &'static TriPrg {
    static P: OnceLock<TriPrg> = OnceLock::new();
    P.get_or_init(|| {
        let k = |key: &[u8; 16]| Aes128::new(GenericArray::from_slice(key));
        TriPrg { child: [k(b"foleage/tdpf/G-0"), k(b"foleage/tdpf/G-1"), k(b"foleage/tdpf/G-2")], ext: k(b"foleage/tdpf/ext") }
    })
}

const BATCH: usize = 64;

fn dm_many(aes: &Aes128, xs: &[Block], mut out: impl FnMut(usize, Block)) {
    let mut buf = [GenericArray::default(); BATCH];
    for (c, chunk) in xs.chunks(BATCH).enumerate() {
        for (i, x) in chunk.iter().enumerate() {
            buf[i] = GenericArray::from(x.to_bytes());
        }
        aes.encrypt_blocks(&mut buf[..chunk.len()]);
        for (i, x) in chunk.iter().enumerate() {
            out(c * BATCH + i, Block::from_bytes(buf[i].as_slice()) ^ *x);
        }
    }
}

impl TriPrg {
    /// The uncorrected children of every parent, `out[3p + j] = G_j(parents[p])`.
    pub fn expand(&self, parents: &[Block], out: &mut Vec<Block>) {
        out.clear();
        out.resize(3 * parents.len(), Block::ZERO);
        for j in 0..3 {
            dm_many(&self.child[j], parents, |p, v| out[3 * p + j] = v);
        }
    }

    /// `Ext(s)` for every leaf seed, `LEAF_BLOCKS` blocks each.
    pub fn extend(&self, leaves: &[Block], out: &mut Vec<Block>) {
        let tweaked: Vec<Block> = leaves.iter().flat_map(|&s| (0..LEAF_BLOCKS as u128).map(move |j| s ^ Block(j))).collect();
        out.clear();
        out.resize(tweaked.len(), Block::ZERO);
        dm_many(&self.ext, &tweaked, |i, v| out[i] = v);
    }
}

/// One party's key: root seed (lsb = party), one correction word per level and
/// the output correction word.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TdpfKey {
    pub root: Block,
    pub cws: Vec<[Block; 3]>,
    pub cw_out: [Block; LEAF_BLOCKS],
}

impl TdpfKey {
    /// Bytes on the wire if the key were sent.
    pub fn size_bytes(&self) -> usize {
        16 * (1 + 3 * self.cws.len() + LEAF_BLOCKS)
    }

    /// The `3^depth` corrected leaf seeds.
    pub fn leaves(&self) -> Vec<Block> {
        let prg = tri_prg();
        let mut nodes = vec![self.root];
        let mut next = Vec::new();
        for cw in &self.cws {
            prg.expand(&nodes, &mut next);
            for (p, &parent) in nodes.iter().enumerate() {
                if parent.lsb() {
                    for j in 0..3 {
                        next[3 * p + j] ^= cw[j];
                    }
                }
            }
            std::mem::swap(&mut nodes, &mut next);
        }
        nodes
    }

    /// The full-domain output: `LEAF_BLOCKS` packed blocks per leaf, in leaf
    /// order. XORing both parties' outputs gives `β` in lane `slot` of leaf
    /// `path` (the DPF's point) and zero everywhere else.
    pub fn full_eval(&self) -> Vec<Block> {
        let leaves = self.leaves();
        let mut out = Vec::new();
        tri_prg().extend(&leaves, &mut out);
        for (i, s) in leaves.iter().enumerate() {
            if s.lsb() {
                for j in 0..LEAF_BLOCKS {
                    out[LEAF_BLOCKS * i + j] ^= self.cw_out[j];
                }
            }
        }
        out
    }
}

/// The leaf vector with `beta` in lane `slot` (F4 lane order of [`crate::f4::Packed`]).
pub fn unit_leaf(slot: usize, beta: u8) -> [Block; LEAF_BLOCKS] {
    let mut v = [Block::ZERO; LEAF_BLOCKS];
    v[slot / 64].0 ^= ((beta & 3) as u128) << (2 * (slot % 64));
    v
}

/// Trusted-dealer rDPF + output word: keys for `path ∈ [3^depth]` (top trit
/// first) whose leaf at `path` evaluates to `leaf` and all others to zero.
pub fn deal<R: RngCore + CryptoRng>(depth: usize, path: usize, leaf: [Block; LEAF_BLOCKS], rng: &mut R) -> [TdpfKey; 2] {
    let prg = tri_prg();
    let mut s = [Block::random(rng).with_lsb(false), Block::random(rng).with_lsb(true)];
    let roots = s;
    let mut cws = Vec::with_capacity(depth);
    let mut kids = Vec::new();
    for i in 0..depth {
        let a = path / 3usize.pow((depth - 1 - i) as u32) % 3;
        prg.expand(&s, &mut kids);
        let mut cw = [kids[0] ^ kids[3], kids[1] ^ kids[4], kids[2] ^ kids[5]];
        // On path the corrected seeds differ by a random r with lsb(r) = 1, so
        // their control bits differ; off path they become equal.
        cw[a] ^= Block::random(rng).with_lsb(true);
        s = [kids[a] ^ cw[a].and_bit(s[0].lsb()), kids[3 + a] ^ cw[a].and_bit(s[1].lsb())];
        debug_assert!(s[0].lsb() ^ s[1].lsb());
        cws.push(cw);
    }
    let mut ext = Vec::new();
    prg.extend(&s, &mut ext);
    let cw_out: [Block; LEAF_BLOCKS] = std::array::from_fn(|j| leaf[j] ^ ext[j] ^ ext[LEAF_BLOCKS + j]);
    [TdpfKey { root: roots[0], cws: cws.clone(), cw_out }, TdpfKey { root: roots[1], cws, cw_out }]
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn dealt_keys_evaluate_to_the_point() {
        let mut rng = ChaCha20Rng::seed_from_u64(3);
        for depth in [1usize, 2, 4] {
            for _ in 0..5 {
                let path = rng.gen_range(0..3usize.pow(depth as u32));
                let slot = rng.gen_range(0..leaf_len(5));
                let beta = rng.gen_range(1..4u8);
                let k = deal(depth, path, unit_leaf(slot, beta), &mut rng);
                let (y0, y1) = (k[0].full_eval(), k[1].full_eval());
                for leaf in 0..3usize.pow(depth as u32) {
                    for j in 0..LEAF_BLOCKS {
                        let want = if leaf == path { unit_leaf(slot, beta)[j] } else { Block::ZERO };
                        assert_eq!(y0[LEAF_BLOCKS * leaf + j] ^ y1[LEAF_BLOCKS * leaf + j], want, "depth {depth} leaf {leaf}");
                    }
                }
            }
        }
    }
}
