//! Floram's Constant-PRG (CPRG) distributed DPF generation (paper §5, Fig. 6–7).
//!
//! Each party expands its own copy of the whole FSS tree in the clear. At each
//! level it XOR-accumulates all left children into `acc_L` and all right
//! children into `acc_R`. On-path children are the only ones that differ between
//! the parties, so `acc_X^0 ⊕ acc_X^1` is the on-path difference. A tiny garbled
//! circuit then selects the off-path difference with the secret index bit α_j
//! (giving the correction word σ_j) and computes the advice bits. No PRG is ever
//! evaluated inside the 2PC.
//!
//! Ported from `src/oram_fssl/fss_cprg.{c,oc}` of the Floram code:
//! [`CprgLocal`] is `fss_cprg_offline` and [`gen`] is `fss_cprg_traverselevels`.

use crate::key::{CorrectionWord, DpfKey};
use dpf_common::block::{bits_msb_first, blocks_for_bits, depth_for, xor_blocks, Block};
use dpf_common::gc::{Evaluator, GcParty, Garbler, Wire};
use dpf_common::net::{Channel, CommStats};
use dpf_common::prg::Prg;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::time::{Duration, Instant};

/// Nodes on level `l` (0 = root) of a tree of `depth` levels with `n_size`
/// leaves. Only nodes with a descendant leaf below `n_size` are expanded. This
/// is Floram's `nextlevelblocks` formula.
pub fn level_count(n_size: u64, depth: usize, l: usize) -> usize {
    n_size.div_ceil(1u64 << (depth - l)) as usize
}

/// One party's full-domain output: `bm` blocks for each of the `n` points.
/// Stored column-major, so sub-block `k` of every point is contiguous.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FullEval {
    pub n: usize,
    pub bm: usize,
    cols: Vec<Vec<Block>>,
}

impl FullEval {
    pub fn get(&self, x: usize) -> Vec<Block> {
        self.cols.iter().map(|c| c[x]).collect()
    }

    pub fn column(&self, k: usize) -> &[Block] {
        &self.cols[k]
    }
}

/// One party's local share of the CPRG tree (`fss_cprg_offline`).
pub struct CprgLocal {
    prg: Prg,
    n_size: u64,
    depth: usize,
    bm: usize,
    /// Level of the nodes currently held in `nodes`.
    level: usize,
    /// Uncorrected children at `level` before `step`, corrected nodes after.
    nodes: Vec<Block>,
    /// t-bits of the corrected parents of `nodes` (level − 1).
    parent_t: Vec<bool>,
    /// Scratch buffer for the next level, swapped with `nodes`.
    scratch: Vec<Block>,
    /// Leaves extended to `bm` columns. Filled by `finalize`.
    leaf_cols: Vec<Vec<Block>>,
    leaf_t: Vec<bool>,
}

fn accumulate(children: &[Block]) -> (Block, Block) {
    let mut acc_l = Block::ZERO;
    let mut acc_r = Block::ZERO;
    for pair in children.chunks(2) {
        acc_l ^= pair[0];
        if let Some(r) = pair.get(1) {
            acc_r ^= *r;
        }
    }
    (acc_l, acc_r)
}

impl CprgLocal {
    /// `fss_cprg_offline_start`: expands the root and returns the level-1
    /// accumulators. The root's lsb is the party's initial t-bit.
    pub fn start(prg: Prg, n_size: u64, bm: usize, root: Block) -> (Self, (Block, Block)) {
        let depth = depth_for(n_size);
        let mut nodes = Vec::with_capacity(n_size as usize);
        nodes.resize(level_count(n_size, depth, 1), Block::ZERO);
        prg.expand_many(&[root], &mut nodes);
        let acc = accumulate(&nodes);
        let local = CprgLocal {
            prg,
            n_size,
            depth,
            bm,
            level: 1,
            nodes,
            parent_t: vec![root.lsb()],
            scratch: Vec::with_capacity(n_size as usize),
            leaf_cols: Vec::new(),
            leaf_t: Vec::new(),
        };
        (local, acc)
    }

    /// `fss_cprg_offline_process_round`. Applies the level's correction word to
    /// the uncorrected children:
    ///
    /// ```text
    /// t_child = lsb(child) ⊕ (t_parent ∧ τ_side)
    /// s_child = child ⊕ t_parent·Z
    /// ```
    ///
    /// Below the last level it then expands the corrected nodes and returns the
    /// next accumulators. At the leaf level it returns `None`.
    pub fn step(&mut self, z: Block, tau_l: bool, tau_r: bool) -> Option<(Block, Block)> {
        let mut t = Vec::with_capacity(self.nodes.len());
        for (c, node) in self.nodes.iter_mut().enumerate() {
            let tp = self.parent_t[c / 2];
            let tau = if c & 1 == 0 { tau_l } else { tau_r };
            t.push(node.lsb() ^ (tp & tau));
            *node ^= z.and_bit(tp);
        }
        self.parent_t = t;

        if self.level == self.depth {
            return None;
        }
        self.level += 1;
        self.scratch.clear();
        self.scratch.resize(level_count(self.n_size, self.depth, self.level), Block::ZERO);
        self.prg.expand_many(&self.nodes, &mut self.scratch);
        std::mem::swap(&mut self.nodes, &mut self.scratch);
        Some(accumulate(&self.nodes))
    }

    /// `fss_cprg_offline_finalize`, after the last `step`. Extends each corrected
    /// leaf to `bm` blocks by chaining `keyL`, and returns the XOR of every column.
    pub fn finalize(&mut self) -> Vec<Block> {
        assert_eq!(self.level, self.depth);
        assert_eq!(self.nodes.len(), self.n_size as usize);
        let mut cols = vec![std::mem::take(&mut self.nodes)];
        for k in 1..self.bm {
            let mut next = vec![Block::ZERO; self.n_size as usize];
            self.prg.left_many(&cols[k - 1], &mut next);
            cols.push(next);
        }
        let acc = cols.iter().map(|c| c.iter().fold(Block::ZERO, |a, b| a ^ *b)).collect();
        self.leaf_cols = cols;
        self.leaf_t = std::mem::take(&mut self.parent_t);
        acc
    }

    /// After `finalize`: the corrected leaf seeds and their t-bits.
    pub fn leaves(&self) -> (&[Block], &[bool]) {
        (&self.leaf_cols[0], &self.leaf_t)
    }

    /// Output shares `y(x) = leaf(x) ⊕ t(x)·γ`, as in Floram's
    /// `scanwrom_write_with_blockvector_offline`.
    pub fn output(self, gamma: &[Block]) -> FullEval {
        assert_eq!(gamma.len(), self.bm);
        let t = &self.leaf_t;
        let cols = self
            .leaf_cols
            .into_iter()
            .zip(gamma)
            .map(|(mut col, g)| {
                for (y, &tx) in col.iter_mut().zip(t) {
                    *y ^= g.and_bit(tx);
                }
                col
            })
            .collect();
        FullEval { n: self.n_size as usize, bm: self.bm, cols }
    }
}

/// The two RNG streams of a party: one for its tree (PRG keys, root) and one for
/// the 2PC machinery. Splitting them lets the reference driver reproduce the tree
/// bit for bit without running the 2PC.
fn party_rngs(seed: [u8; 32]) -> (ChaCha20Rng, ChaCha20Rng) {
    let tree = ChaCha20Rng::from_seed(seed);
    let mut proto = ChaCha20Rng::from_seed(seed);
    proto.set_stream(1);
    (tree, proto)
}

/// Samples the root with its lsb forced to the party's t-bit (party 0 → 0,
/// party 1 → 1), as in `fss_cprg_offline_start`.
fn sample_root(rng: &mut ChaCha20Rng, party: usize) -> Block {
    let r = Block::random(rng);
    Block((r.0 & !1) | party as u128)
}

/// Everything one party gets out of [`gen`].
pub struct GenOutput {
    pub key: DpfKey,
    /// Full-domain output, computed as a by-product of generation (Floram's
    /// `blockvector`/`bitvector`, already combined with γ).
    pub full: FullEval,
    /// Traffic for setup: PRG-key transfer and base OTs.
    pub setup_stats: CommStats,
    /// Traffic for the generation proper.
    pub gen_stats: CommStats,
    pub and_gates: usize,
    /// Wall time for setup (PRG keys, base OTs) and for generation proper.
    pub setup_time: Duration,
    pub gen_time: Duration,
}

/// The per-level 2PC (`fss_cprg_traverselevels` + `fss_cprg_getadvice`). Returns
/// the revealed `(Z, τ_L, τ_R)`.
pub fn level_circuit<P: GcParty>(
    p: &mut P,
    ch: &mut Channel,
    alpha_j: Wire,
    acc: (Block, Block),
) -> CorrectionWord {
    // ocFromSharedCharN(diff_L), then ocFromSharedCharN(diff_R).
    let dl = p.input_shared(ch, &acc.0.to_bits());
    let dr = p.input_shared(ch, &acc.1.to_bits());
    // obliv if (levelindex == 0) Z = diff_R; else Z = diff_L;
    let z = p.mux(ch, alpha_j, &dl, &dr);
    // advicebits[0] = diff_L[0] ^ rightblock ^ 1; advicebits[1] = diff_R[0] ^ rightblock;
    let tau_l = p.not(p.xor(dl[0], alpha_j));
    let tau_r = p.xor(dr[0], alpha_j);
    let mut out = z;
    out.push(tau_l);
    out.push(tau_r);
    let bits = p.reveal_both(ch, &out);
    CorrectionWord { z: Block::from_bits(&bits[..128]), tau_l: bits[128], tau_r: bits[129] }
}

#[allow(clippy::too_many_arguments)]
fn gen_with<P: GcParty>(
    p: &mut P,
    ch: &mut Channel,
    prg: Prg,
    n_size: u64,
    bm: usize,
    root: Block,
    alpha_share: u64,
    beta_share: &[Block],
) -> (DpfKey, FullEval) {
    let depth = depth_for(n_size);
    let alpha = p.input_shared(ch, &bits_msb_first(alpha_share, depth));

    let (mut local, mut acc) = CprgLocal::start(prg.clone(), n_size, bm, root);
    let mut cws = Vec::with_capacity(depth);
    for &alpha_j in &alpha {
        let cw = level_circuit(p, ch, alpha_j, acc);
        cws.push(cw);
        if let Some(next) = local.step(cw.z, cw.tau_l, cw.tau_r) {
            acc = next;
        }
    }
    let leaf_acc = local.finalize();

    // γ = acc^0 ⊕ acc^1 ⊕ β. Floram computes this in the circuit, but it has only
    // XOR gates, so opening the XOR shares directly gives the same result.
    let mine = xor_blocks(&leaf_acc, beta_share);
    ch.send_blocks(&mine);
    let theirs = ch.recv_blocks(bm);
    let gamma = xor_blocks(&mine, &theirs);

    let full = local.output(&gamma);
    let key = DpfKey { party: ch.party(), n_size, bm, prg, root, cws, gamma };
    (key, full)
}

/// Runs this party's side of distributed DPF generation.
///
/// * `n_size` is the domain size N ≥ 2 and need not be a power of two.
/// * `out_bits` is the payload width; it sets `bm = ceil(out_bits / 128)`.
/// * `alpha_share` and `beta_share` are this party's XOR shares of α < N and β
///   (`bm` blocks).
/// * `seed` is this party's randomness.
pub fn gen(
    ch: &mut Channel,
    n_size: u64,
    out_bits: usize,
    alpha_share: u64,
    beta_share: &[Block],
    seed: [u8; 32],
) -> GenOutput {
    let party = ch.party();
    let t_setup = Instant::now();
    let bm = blocks_for_bits(out_bits);
    assert_eq!(beta_share.len(), bm, "beta share must have ceil(out_bits/128) blocks");
    let (mut rng_tree, mut rng_proto) = party_rngs(seed);

    // As in fss_cprg_new: party 1 (our party 0) picks the public PRG keys and sends them.
    let prg = if party == 0 {
        let (kl, kr) = (Block::random(&mut rng_tree), Block::random(&mut rng_tree));
        ch.send_blocks(&[kl, kr]);
        Prg::new(kl, kr)
    } else {
        let k = ch.recv_blocks(2);
        Prg::new(k[0], k[1])
    };
    let root = sample_root(&mut rng_tree, party);

    let mut setup_time = Duration::ZERO;
    let mut t_gen = Instant::now();
    let mut mark = |ch: &mut Channel| {
        // Synchronise at the end of setup so that neither party's gen time
        // includes waiting for the other's base OTs. Counted as setup traffic.
        if ch.party() == 1 {
            ch.send(vec![0]);
        } else {
            ch.recv();
        }
        setup_time = t_setup.elapsed();
        t_gen = Instant::now();
        ch.stats()
    };
    let (key, full, setup_stats, and_gates) = if party == 0 {
        let mut g = Garbler::setup(ch, &mut rng_proto);
        let s = mark(ch);
        let (k, f) = gen_with(&mut g, ch, prg, n_size, bm, root, alpha_share, beta_share);
        (k, f, s, g.and_count())
    } else {
        let mut e = Evaluator::setup(ch, &mut rng_proto);
        let s = mark(ch);
        let (k, f) = gen_with(&mut e, ch, prg, n_size, bm, root, alpha_share, beta_share);
        (k, f, s, e.and_count())
    };
    let gen_time = t_gen.elapsed();
    let gen_stats = ch.stats().since(&setup_stats);
    GenOutput { key, full, setup_stats, gen_stats, and_gates, setup_time, gen_time }
}

/// Plaintext reference for [`gen`]. It runs both parties' trees in one thread
/// and computes the correction words in the clear from α (Fig. 7 without the
/// 2PC). Given the same seeds it produces exactly the keys and outputs that
/// [`gen`] does, so it serves as the bit-exact oracle in tests. With fresh seeds
/// it is a trusted-dealer generator.
pub fn gen_reference(
    n_size: u64,
    out_bits: usize,
    alpha: u64,
    beta: &[Block],
    seeds: [[u8; 32]; 2],
) -> ([DpfKey; 2], [FullEval; 2]) {
    assert!(alpha < n_size);
    let bm = blocks_for_bits(out_bits);
    assert_eq!(beta.len(), bm);
    let depth = depth_for(n_size);
    let (mut r0, _) = party_rngs(seeds[0]);
    let (mut r1, _) = party_rngs(seeds[1]);
    let prg = Prg::new(Block::random(&mut r0), Block::random(&mut r0));
    let roots = [sample_root(&mut r0, 0), sample_root(&mut r1, 1)];

    let (mut l0, mut a0) = CprgLocal::start(prg.clone(), n_size, bm, roots[0]);
    let (mut l1, mut a1) = CprgLocal::start(prg.clone(), n_size, bm, roots[1]);
    let mut cws = Vec::with_capacity(depth);
    for (j, &aj) in bits_msb_first(alpha, depth).iter().enumerate() {
        let dl = a0.0 ^ a1.0;
        let dr = a0.1 ^ a1.1;
        let cw = CorrectionWord {
            z: if aj { dl } else { dr },
            tau_l: dl.lsb() ^ aj ^ true,
            tau_r: dr.lsb() ^ aj,
        };
        cws.push(cw);
        let n0 = l0.step(cw.z, cw.tau_l, cw.tau_r);
        let n1 = l1.step(cw.z, cw.tau_l, cw.tau_r);
        if j + 1 < depth {
            a0 = n0.unwrap();
            a1 = n1.unwrap();
        }
    }
    let acc0 = l0.finalize();
    let acc1 = l1.finalize();
    let gamma = xor_blocks(&xor_blocks(&acc0, &acc1), beta);
    let f0 = l0.output(&gamma);
    let f1 = l1.output(&gamma);
    let mk = |party: usize| DpfKey {
        party,
        n_size,
        bm,
        prg: prg.clone(),
        root: roots[party],
        cws: cws.clone(),
        gamma: gamma.clone(),
    };
    ([mk(0), mk(1)], [f0, f1])
}
