//! Streaming walk over one level of a GGM-style tree, for the `--stream` mode.
//!
//! The faithful protocols store every level of the tree: a level's correction
//! word depends on the XOR of all its nodes, and the next level can only be
//! corrected once that word is opened. Memory therefore peaks at a few times
//! `2^n` blocks. The streaming mode stores only the root and the correction
//! words opened so far, and regenerates a level whenever it is needed: a
//! batched depth-first walk from the root, which hands the nodes of the target
//! level to a visitor in left-to-right order and drops them right after.
//!
//! Re-walking from the root for every level costs about twice the PRG calls of
//! the stored tree (`Σ_ℓ 2^{ℓ+1}` against `Σ_ℓ 2^ℓ`); the messages, bytes and
//! rounds of a protocol are unchanged, since only the order of each party's
//! local work differs. Memory is about `batch · (depth − log₂ batch)` blocks.

use crate::block::Block;

/// Nodes per batch in the streaming walk (1 MiB of blocks).
pub const DEFAULT_BATCH: usize = 1 << 16;

/// How a protocol holds its tree during Gen and full-domain evaluation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TreeMode {
    /// Every level in memory, as in the papers and reference code.
    Stored,
    /// Regenerate levels from the root in batches of `batch` nodes.
    Stream { batch: usize },
}

impl TreeMode {
    pub fn stream() -> Self {
        TreeMode::Stream { batch: DEFAULT_BATCH }
    }

    /// The batch size (only meaningful for [`TreeMode::Stream`]).
    pub fn batch(self) -> usize {
        match self {
            TreeMode::Stored => DEFAULT_BATCH,
            TreeMode::Stream { batch } => batch,
        }
    }
}

/// Visits every node of level `depth` below `root`, in order.
///
/// * `expand(ℓ, parents, out)` must write the (corrected) children at level
///   `ℓ ≥ 1` of `parents` into `out`, interleaved `[L(p0), R(p0), L(p1), …]`.
/// * `visit(i, nodes)` receives consecutive nodes of level `depth`; `i` is the
///   index of `nodes[0]` within the level.
///
/// At most `batch` nodes (at least 2) are expanded at once on each level.
pub fn walk(
    root: Block,
    depth: usize,
    batch: usize,
    mut expand: impl FnMut(usize, &[Block], &mut Vec<Block>),
    mut visit: impl FnMut(u64, &[Block]),
) {
    let mut bufs: Vec<Vec<Block>> = (0..depth).map(|_| Vec::new()).collect();
    rec(&[root], 0, 0, depth, (batch / 2).max(1), &mut bufs, &mut expand, &mut visit);
}

#[allow(clippy::too_many_arguments)]
fn rec(
    nodes: &[Block],
    level: usize,
    first: u64,
    depth: usize,
    chunk: usize,
    bufs: &mut [Vec<Block>],
    expand: &mut impl FnMut(usize, &[Block], &mut Vec<Block>),
    visit: &mut impl FnMut(u64, &[Block]),
) {
    if level == depth {
        visit(first, nodes);
        return;
    }
    let (kids, rest) = bufs.split_first_mut().expect("one buffer per level");
    for (c, part) in nodes.chunks(chunk).enumerate() {
        kids.clear();
        expand(level + 1, part, kids);
        debug_assert_eq!(kids.len(), 2 * part.len());
        let start = 2 * (first + (c * chunk) as u64);
        rec(kids, level + 1, start, depth, chunk, rest, expand, visit);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A toy tree whose node is its (level, index) pair, packed.
    fn toy(level: usize, parents: &[Block], out: &mut Vec<Block>) {
        for p in parents {
            let i = p.0 & 0xffff_ffff;
            for side in 0..2 {
                out.push(Block(((level as u128) << 64) | (2 * i + side)));
            }
        }
    }

    #[test]
    fn visits_every_node_in_order() {
        for depth in 0..9 {
            for batch in [2, 3, 4, 16, 1 << 10] {
                let mut seen = Vec::new();
                walk(Block(0), depth, batch, toy, |i, nodes| {
                    for (k, n) in nodes.iter().enumerate() {
                        assert_eq!(n.0 & 0xffff_ffff, i as u128 + k as u128);
                        if depth > 0 {
                            assert_eq!((n.0 >> 64) as usize, depth);
                        }
                    }
                    assert!(nodes.len() <= batch.max(2));
                    seen.extend(nodes.iter().map(|n| n.0 & 0xffff_ffff));
                });
                assert_eq!(seen, (0..1u128 << depth).collect::<Vec<_>>(), "depth {depth} batch {batch}");
            }
        }
    }
}
