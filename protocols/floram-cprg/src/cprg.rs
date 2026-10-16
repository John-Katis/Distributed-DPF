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
//!
//! Unlike Floram's code, the tree is always the full `2^n`-leaf tree: a domain
//! size N that is not a power of two is padded, every level expands every
//! node, and only the outputs for `x < N` are returned.
//!
//! Two deviations from Fig. 7 as printed, each closing a leak:
//!
//! * A node's lsb is its t-bit, so σ_j is revealed without its lsb (and a
//!   corrected node's lsb is set to t). Opening the full block gives
//!   `lsb(σ_j) = τ_{j,ᾱ_j}`, which reveals α_j whenever `τ_{j,0} ≠ τ_{j,1}`.
//! * The payload never contains a leaf's lsb ([`leaf_columns`]). Otherwise
//!   `lsb(γ) = lsb(β) ⊕ 1 ⊕ τ_{m,0} ⊕ τ_{m,1}` is public.

use crate::key::{CorrectionWord, DpfKey};
use dpf_common::block::{bits_msb_first, blocks_for_bits, depth_for, expand_in_place, last_block_mask, mask_to_bits, xor_blocks, Block};
use dpf_common::gc::{Evaluator, GcParty, Garbler, Wire};
use dpf_common::net::{Channel, CommStats};
use dpf_common::prg::Prg;
use dpf_common::stream::{walk, TreeMode};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::time::{Duration, Instant};

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
    out_bits: usize,
    bm: usize,
    /// Level of the nodes currently held in `nodes`.
    level: usize,
    /// Uncorrected children at `level` before `step`, corrected nodes after.
    /// Allocated once for `2^n` nodes; every level is expanded into it in
    /// place.
    nodes: Vec<Block>,
    /// t-bits of the corrected parents of `nodes` (level − 1).
    parent_t: Vec<bool>,
    /// Payload columns of the leaves. Filled by `finalize`.
    leaf_cols: Vec<Vec<Block>>,
    leaf_t: Vec<bool>,
}

fn accumulate(children: &[Block]) -> (Block, Block) {
    let mut acc_l = Block::ZERO;
    let mut acc_r = Block::ZERO;
    for pair in children.chunks(2) {
        acc_l ^= pair[0];
        acc_r ^= pair[1];
    }
    (acc_l, acc_r)
}

/// Expands every parent into both children (`out.len() = 2·parents`) and
/// returns the accumulators.
fn expand_level(prg: &Prg, parents: &[Block], out: &mut Vec<Block>) -> (Block, Block) {
    out.clear();
    out.resize(2 * parents.len(), Block::ZERO);
    prg.expand_many(parents, out);
    accumulate(out)
}

/// Payload columns of the leaves (`Convert`). A leaf's lsb is its t-bit and
/// must not reach the payload. Up to 127 bits, column 0 is the leaf shifted
/// down (Half-Tree's PRG-free Convert); wider payloads chain `keyL` from the
/// leaf, column k = `left^{k+1}(leaf)`. Bits from `out_bits` on are cleared,
/// so the payload is exactly `out_bits` wide and γ is opened in
/// `ceil(out_bits/8)` bytes.
pub fn leaf_columns(prg: &Prg, leaves: &[Block], out_bits: usize) -> Vec<Vec<Block>> {
    let m = last_block_mask(out_bits);
    if out_bits <= 127 {
        return vec![leaves.iter().map(|x| Block((x.0 >> 1) & m)).collect()];
    }
    let mut cols: Vec<Vec<Block>> = Vec::with_capacity(blocks_for_bits(out_bits));
    for k in 0..blocks_for_bits(out_bits) {
        let mut next = vec![Block::ZERO; leaves.len()];
        prg.left_many(if k == 0 { leaves } else { &cols[k - 1] }, &mut next);
        cols.push(next);
    }
    if m != u128::MAX {
        // The chain needs the full blocks, so mask only after it.
        cols.last_mut().unwrap().iter_mut().for_each(|x| x.0 &= m);
    }
    cols
}

/// [`leaf_columns`] for one leaf.
pub fn leaf_words(prg: &Prg, leaf: Block, out_bits: usize, out: &mut [Block]) {
    let m = last_block_mask(out_bits);
    if out_bits <= 127 {
        out[0] = Block((leaf.0 >> 1) & m);
        return;
    }
    let mut s = leaf;
    for o in out.iter_mut() {
        s = prg.left(s);
        *o = s;
    }
    out.last_mut().unwrap().0 &= m;
}

impl CprgLocal {
    /// `fss_cprg_offline_start`: expands the root and returns the level-1
    /// accumulators. The root's lsb is the party's initial t-bit.
    pub fn start(prg: Prg, n_size: u64, out_bits: usize, root: Block) -> (Self, (Block, Block)) {
        let depth = depth_for(n_size);
        let mut nodes = Vec::with_capacity(1 << depth);
        let acc = expand_level(&prg, &[root], &mut nodes);
        let local = CprgLocal {
            prg,
            n_size,
            depth,
            out_bits,
            bm: blocks_for_bits(out_bits),
            level: 1,
            nodes,
            parent_t: vec![root.lsb()],
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
    /// s_child = (child ⊕ t_parent·Z) with lsb t_child
    /// ```
    ///
    /// Below the last level it then expands the corrected nodes and returns the
    /// next accumulators. At the leaf level it returns `None`.
    pub fn step(&mut self, z: Block, tau_l: bool, tau_r: bool) -> Option<(Block, Block)> {
        let mut t = Vec::with_capacity(self.nodes.len());
        for (c, node) in self.nodes.iter_mut().enumerate() {
            let tp = self.parent_t[c / 2];
            let tau = if c & 1 == 0 { tau_l } else { tau_r };
            let tc = node.lsb() ^ (tp & tau);
            t.push(tc);
            *node = (*node ^ z.and_bit(tp)).with_lsb(tc);
        }
        self.parent_t = t;

        if self.level == self.depth {
            return None;
        }
        self.level += 1;
        let prg = &self.prg;
        expand_in_place(&mut self.nodes, |ps, out| prg.expand_many(ps, out));
        Some(accumulate(&self.nodes))
    }

    /// `fss_cprg_offline_finalize`, after the last `step`. Converts all `2^n`
    /// corrected leaves into payload columns ([`leaf_columns`]) and returns the
    /// XOR of every column.
    pub fn finalize(&mut self) -> Vec<Block> {
        assert_eq!(self.level, self.depth);
        assert_eq!(self.nodes.len(), 1 << self.depth);
        let cols = if self.out_bits <= 127 {
            // One payload column: shift the leaves in place.
            let m = last_block_mask(self.out_bits);
            let mut col = std::mem::take(&mut self.nodes);
            for x in col.iter_mut() {
                *x = Block((x.0 >> 1) & m);
            }
            vec![col]
        } else {
            leaf_columns(&self.prg, &self.nodes, self.out_bits)
        };
        let acc = cols.iter().map(|c| c.iter().fold(Block::ZERO, |a, b| a ^ *b)).collect();
        self.leaf_cols = cols;
        self.leaf_t = std::mem::take(&mut self.parent_t);
        acc
    }

    /// Output shares `y(x) = leaf(x) ⊕ t(x)·γ` for `x < N`, as in Floram's
    /// `scanwrom_write_with_blockvector_offline`.
    pub fn output(self, gamma: &[Block]) -> FullEval {
        assert_eq!(gamma.len(), self.bm);
        let n = self.n_size as usize;
        let t = &self.leaf_t[..n];
        let cols = self
            .leaf_cols
            .into_iter()
            .zip(gamma)
            .map(|(mut col, g)| {
                col.truncate(n);
                for (y, &tx) in col.iter_mut().zip(t) {
                    *y ^= g.and_bit(tx);
                }
                col
            })
            .collect();
        FullEval { n: self.n_size as usize, bm: self.bm, cols }
    }
}

/// The per-level interface that Gen drives. [`CprgLocal`] stores every level
/// (Floram's code); [`CprgStream`] regenerates them ([`dpf_common::stream`]).
pub trait CprgTree: Sized {
    /// Expands the root; returns the tree and the level-1 accumulators.
    fn start(prg: Prg, n_size: u64, out_bits: usize, root: Block, mode: TreeMode) -> (Self, (Block, Block));
    /// Applies the current level's correction word; returns the next level's
    /// accumulators, or `None` after the leaf level.
    fn step(&mut self, z: Block, tau_l: bool, tau_r: bool) -> Option<(Block, Block)>;
    /// The XOR of every payload column over all `2^n` leaves.
    fn finalize(&mut self) -> Vec<Block>;
    /// The full-domain output, if the tree keeps one.
    fn output(self, gamma: &[Block]) -> Option<FullEval>;
}

impl CprgTree for CprgLocal {
    fn start(prg: Prg, n_size: u64, out_bits: usize, root: Block, _: TreeMode) -> (Self, (Block, Block)) {
        CprgLocal::start(prg, n_size, out_bits, root)
    }
    fn step(&mut self, z: Block, tau_l: bool, tau_r: bool) -> Option<(Block, Block)> {
        CprgLocal::step(self, z, tau_l, tau_r)
    }
    fn finalize(&mut self) -> Vec<Block> {
        CprgLocal::finalize(self)
    }
    fn output(self, gamma: &[Block]) -> Option<FullEval> {
        Some(CprgLocal::output(self, gamma))
    }
}

/// The same tree as [`CprgLocal`], holding only the root and the correction
/// words so far. Every accumulator is recomputed by a batched walk from the
/// root; there is no full-domain output.
pub struct CprgStream {
    prg: Prg,
    depth: usize,
    out_bits: usize,
    batch: usize,
    root: Block,
    cws: Vec<CorrectionWord>,
}

/// Corrected children at level `level` (1-based) of `parents`, whose lsb is
/// their t-bit: `step` applied to `expand_many`.
fn expand_corrected(prg: &Prg, cws: &[CorrectionWord], level: usize, parents: &[Block], out: &mut Vec<Block>) {
    let cw = cws[level - 1];
    out.clear();
    out.resize(2 * parents.len(), Block::ZERO);
    prg.expand_many(parents, out);
    for (c, node) in out.iter_mut().enumerate() {
        let tp = parents[c / 2].lsb();
        let tau = if c & 1 == 0 { cw.tau_l } else { cw.tau_r };
        let tc = node.lsb() ^ (tp & tau);
        *node = (*node ^ cw.z.and_bit(tp)).with_lsb(tc);
    }
}

impl CprgStream {
    /// A streaming tree over known correction words (for key evaluation).
    pub fn with_cws(prg: Prg, n_size: u64, out_bits: usize, root: Block, cws: Vec<CorrectionWord>, batch: usize) -> Self {
        CprgStream { prg, depth: depth_for(n_size), out_bits, batch, root, cws }
    }

    /// Visits the corrected nodes of level `depth ≤ cws.len()`.
    fn walk_level(&self, depth: usize, visit: impl FnMut(u64, &[Block])) {
        walk(self.root, depth, self.batch, |l, p, o| expand_corrected(&self.prg, &self.cws, l, p, o), visit);
    }

    /// Output shares `leaf(x) ⊕ t(x)·γ` for `x < n_size`, in batches:
    /// `visit(x0, cols)` with `cols[k][i]` the block k of point `x0 + i`.
    pub fn outputs(&self, n_size: u64, gamma: &[Block], mut visit: impl FnMut(u64, &[Vec<Block>])) {
        assert_eq!(self.cws.len(), self.depth);
        self.walk_level(self.depth, |x0, leaves| {
            if x0 >= n_size {
                return;
            }
            let leaves = &leaves[..leaves.len().min((n_size - x0) as usize)];
            let mut cols = leaf_columns(&self.prg, leaves, self.out_bits);
            for (col, g) in cols.iter_mut().zip(gamma) {
                for (y, l) in col.iter_mut().zip(leaves) {
                    *y ^= g.and_bit(l.lsb());
                }
            }
            visit(x0, &cols);
        });
    }
}

impl CprgTree for CprgStream {
    fn start(prg: Prg, n_size: u64, out_bits: usize, root: Block, mode: TreeMode) -> (Self, (Block, Block)) {
        let acc = expand_level(&prg, &[root], &mut Vec::new());
        let depth = depth_for(n_size);
        (CprgStream { prg, depth, out_bits, batch: mode.batch(), root, cws: Vec::with_capacity(depth) }, acc)
    }

    fn step(&mut self, z: Block, tau_l: bool, tau_r: bool) -> Option<(Block, Block)> {
        self.cws.push(CorrectionWord { z, tau_l, tau_r });
        if self.cws.len() == self.depth {
            return None;
        }
        let (mut acc, mut kids) = ((Block::ZERO, Block::ZERO), Vec::new());
        self.walk_level(self.cws.len(), |_, nodes| {
            let (l, r) = expand_level(&self.prg, nodes, &mut kids);
            acc = (acc.0 ^ l, acc.1 ^ r);
        });
        Some(acc)
    }

    fn finalize(&mut self) -> Vec<Block> {
        let mut acc = vec![Block::ZERO; blocks_for_bits(self.out_bits)];
        self.walk_level(self.depth, |_, leaves| {
            for (a, col) in acc.iter_mut().zip(leaf_columns(&self.prg, leaves, self.out_bits)) {
                *a = col.iter().fold(*a, |x, y| x ^ *y);
            }
        });
        acc
    }

    fn output(self, _: &[Block]) -> Option<FullEval> {
        None
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
    /// `blockvector`/`bitvector`, already combined with γ). `None` with the
    /// streaming tree.
    pub full: Option<FullEval>,
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
    // obliv if (levelindex == 0) Z = diff_R; else Z = diff_L; without bit 0,
    // which would equal the off-path advice bit and so reveal α_j.
    let z = p.mux(ch, alpha_j, &dl[1..], &dr[1..]);
    // advicebits[0] = diff_L[0] ^ rightblock ^ 1; advicebits[1] = diff_R[0] ^ rightblock;
    let tau_l = p.not(p.xor(dl[0], alpha_j));
    let tau_r = p.xor(dr[0], alpha_j);
    let mut out = z;
    out.push(tau_l);
    out.push(tau_r);
    let bits = p.reveal_both(ch, &out);
    let z = Block(Block::from_bits(&bits[..127]).0 << 1);
    CorrectionWord { z, tau_l: bits[127], tau_r: bits[128] }
}

#[allow(clippy::too_many_arguments)]
fn gen_with<P: GcParty, T: CprgTree>(
    p: &mut P,
    ch: &mut Channel,
    prg: Prg,
    n_size: u64,
    out_bits: usize,
    root: Block,
    alpha_share: u64,
    beta_share: &[Block],
    mode: TreeMode,
) -> (DpfKey, Option<FullEval>) {
    let depth = depth_for(n_size);
    let alpha = p.input_shared(ch, &bits_msb_first(alpha_share, depth));

    let (mut local, mut acc) = T::start(prg.clone(), n_size, out_bits, root, mode);
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
    // The leaf sum is `out_bits` wide and β ∈ F_2^out_bits, so the share is
    // reduced to `out_bits` and γ goes in `ceil(out_bits/8)` bytes.
    let mut mine = xor_blocks(&leaf_acc, beta_share);
    mask_to_bits(&mut mine, out_bits);
    ch.send_payload(&mine, out_bits);
    let theirs = ch.recv_payload(out_bits);
    let gamma = xor_blocks(&mine, &theirs);

    let full = local.output(&gamma);
    let key = DpfKey { party: ch.party(), n_size, out_bits, bm: gamma.len(), prg, root, cws, gamma };
    (key, full)
}

/// [`gen_with`] on the tree type that `mode` selects.
#[allow(clippy::too_many_arguments)]
fn gen_tree<P: GcParty>(
    p: &mut P,
    ch: &mut Channel,
    prg: Prg,
    n_size: u64,
    out_bits: usize,
    root: Block,
    alpha_share: u64,
    beta_share: &[Block],
    mode: TreeMode,
) -> (DpfKey, Option<FullEval>) {
    match mode {
        TreeMode::Stored => gen_with::<P, CprgLocal>(p, ch, prg, n_size, out_bits, root, alpha_share, beta_share, mode),
        TreeMode::Stream { .. } => gen_with::<P, CprgStream>(p, ch, prg, n_size, out_bits, root, alpha_share, beta_share, mode),
    }
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
    gen_mode(ch, n_size, out_bits, alpha_share, beta_share, seed, TreeMode::Stored)
}

/// [`gen`] with the tree held as `mode` says. Both modes send the same
/// messages; [`TreeMode::Stream`] returns no full-domain output.
pub fn gen_mode(
    ch: &mut Channel,
    n_size: u64,
    out_bits: usize,
    alpha_share: u64,
    beta_share: &[Block],
    seed: [u8; 32],
    mode: TreeMode,
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
        let (k, f) = gen_tree(&mut g, ch, prg, n_size, out_bits, root, alpha_share, beta_share, mode);
        (k, f, s, g.and_count())
    } else {
        let mut e = Evaluator::setup(ch, &mut rng_proto);
        let s = mark(ch);
        let (k, f) = gen_tree(&mut e, ch, prg, n_size, out_bits, root, alpha_share, beta_share, mode);
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
    let (keys, [f0, f1]) = reference_with::<CprgLocal>(n_size, out_bits, alpha, beta, seeds, TreeMode::Stored);
    (keys, [f0.expect("stored tree"), f1.expect("stored tree")])
}

/// The keys of [`gen_reference`], with the tree held as `mode` says.
pub fn gen_reference_keys(n_size: u64, out_bits: usize, alpha: u64, beta: &[Block], seeds: [[u8; 32]; 2], mode: TreeMode) -> [DpfKey; 2] {
    match mode {
        TreeMode::Stored => reference_with::<CprgLocal>(n_size, out_bits, alpha, beta, seeds, mode).0,
        TreeMode::Stream { .. } => reference_with::<CprgStream>(n_size, out_bits, alpha, beta, seeds, mode).0,
    }
}

fn reference_with<T: CprgTree>(
    n_size: u64,
    out_bits: usize,
    alpha: u64,
    beta: &[Block],
    seeds: [[u8; 32]; 2],
    mode: TreeMode,
) -> ([DpfKey; 2], [Option<FullEval>; 2]) {
    assert!(alpha < n_size);
    let bm = blocks_for_bits(out_bits);
    assert_eq!(beta.len(), bm);
    let depth = depth_for(n_size);
    let (mut r0, _) = party_rngs(seeds[0]);
    let (mut r1, _) = party_rngs(seeds[1]);
    let prg = Prg::new(Block::random(&mut r0), Block::random(&mut r0));
    let roots = [sample_root(&mut r0, 0), sample_root(&mut r1, 1)];

    let (mut l0, mut a0) = T::start(prg.clone(), n_size, out_bits, roots[0], mode);
    let (mut l1, mut a1) = T::start(prg.clone(), n_size, out_bits, roots[1], mode);
    let mut cws = Vec::with_capacity(depth);
    for (j, &aj) in bits_msb_first(alpha, depth).iter().enumerate() {
        let dl = a0.0 ^ a1.0;
        let dr = a0.1 ^ a1.1;
        let cw = CorrectionWord {
            z: Block(if aj { dl } else { dr }.0 & !1),
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
        out_bits,
        bm,
        prg: prg.clone(),
        root: roots[party],
        cws: cws.clone(),
        gamma: gamma.clone(),
    };
    ([mk(0), mk(1)], [f0, f1])
}
