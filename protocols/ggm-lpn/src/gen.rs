//! Key generation: the cleartext Gen ([`deal`]) and the semi-honest 2PC Gen
//! ([`gen`]).
//!
//! **Setup** (once per Gen here, as in `fssnn`): base OTs and the Ferret
//! bootstrap.
//!
//! **Preprocessing** (input-independent, [`precompute`]):
//! * for every level ℓ, one bit-times-3-block triple `(a, [Y_1, Y_2, Y_3],
//!   [a·Y_1, a·Y_2, a·Y_3])` from one random COT per direction. Its bit is
//!   `α_ℓ` (so α is random, as in `ht-aes`), `Y_1` gives `U_ℓ` and `⟨α_ℓ·U_ℓ⟩`,
//!   `Y_2` gives the pre-sampled `u_{ℓ−1,0}` of a bottom level and, through
//!   its lsb, `⟨t_{ℓ−1,0}·α_ℓ⟩`, and `(Y_3, a·Y_3)` is the triple of the
//!   level's online multiplexer (its bit is α_ℓ itself, so only the block is
//!   opened);
//! * `u_{n,0}`, and each party's root `r_b` with `lsb(r_b) = b`;
//! * one bit-times-block triple for the glue (ν ≥ 1);
//! * the LPN-PRG correlations of [`crate::prg_calls`] 2PC calls (DGH+21 §5.5,
//!   from Ferret COTs; [`fssnn::semi_honest::sec_prg::preprocess`]).
//!
//! **Generation**:
//! 1. Top phase, `ℓ = 1, …, ν`, on its own lane: each party expands its own
//!    tree; `⟨D_σ⟩` is its sum of σ-children over level ℓ − 1, and `s^L_CW`,
//!    `s^R_CW`, `t^L_CW`, `t^R_CW` are opened (one round per level). Glue: `E_b`,
//!    `A_b` over level ν; `⟨t_{ν,0}⟩ = (¬a_1, e_1)` locally, from the high
//!    bits of `a = A_0 mod 4` and `e = −A_1 mod 4` (as in `ht-aes`, Lemma
//!    "Glue"); `⟨st_{ν,0}⟩ = ⟨E⟩ ⊕ ¬⟨t_{ν,0}⟩·⟨V_ν⟩` (one product); `M_ν =
//!    st_{ν,0} ⊕ u_{ν,0}` opened.
//! 2. Bottom, `ν < ℓ ≤ n`, on the main line: `G(⟨u_{ℓ−1,0}⟩)`, `G(⟨u_{ℓ−1,1}⟩)`
//!    for all levels (and the leaf for ℓ > 127) in one batch (two rounds);
//!    then the side and tag words and the multiplexer's masked block are
//!    opened (one round), then `M_ℓ = st^Keep_0 ⊕ t_{ℓ−1,0}·(s^Keep_CW ∥
//!    t^Keep_CW) ⊕ u_{ℓ,0}` (one round), with `st^Keep_0 = st^L_0 ⊕
//!    α_ℓ·(st^L_0 ⊕ st^R_0)` from the multiplexer.
//! 3. Leaf: `W_CW = Conv(V_n) ⊕ β` (ℓ ≤ 127, linear) opened on its own lane
//!    in the first round; for ℓ > 127 `Conv` of the two G outputs, opened
//!    after the batch.
//!
//! Rounds: `max(ν + 2, 4)` for 1 ≤ ν < n (`4` for ν = 0, `n + 2` for ν = n).
//!
//! **Arithmetic payload** ([`gen_arith`]): the tree as above and the leaf of
//! the half-tree instance, indexed by tag: with `t = t_{n,0} = lsb(u_{n,0})`
//! and `⟨Y⟩ = ⟨u_{n,0}⟩ ⊕ ⟨t·V_n⟩` (one Beaver product), `Y` and `Y ⊕ V_n` are
//! the on-path leaf states with tags 0 and 1, and `W_CW = W^(0) − W^(1) −
//! (1 − 2σ)·β` is linear in the B2A outputs of their mask bits and of `t`
//! ([`ht_aes::leaf::tag_leaf`], two rounds, daBits from
//! [`ht_aes::leaf::fp_pre`] in preprocessing). A mask is the integer of κ
//! seed bits for κ ≤ λ = 127, as `Conv` of the Boolean leaf, so these three
//! rounds run beside the bottom phase. For κ > 127 (`2^127 − 1`) it comes from
//! two more calls of `G` in the batch, on inputs known after the product, so
//! Gen takes 5 rounds below ν.

use crate::key::{leaf_mask, mask_from_seed, seed_mask, ArithKey, BinKey, LevelWord, Tree};
use crate::{default_nu, prg_calls, seed, Word};
use dpf_common::block::{depth_for, Block};
use dpf_common::bool2pc::rot_string_triples;
use dpf_common::hash::cot_hash;
use dpf_common::net::{run_two_party, Channel, CommStats, Lane};
use dpf_common::ot::{CotPair, FerretConfig, RandomCots};
use fssnn::semi_honest::sec_prg::{eval_shared, preprocess, PrgCorr};
use fssnn::tree::{conv, conv_prg, expand, SEED_BITS};
use ht_aes::field::Field;
use ht_aes::leaf::{fp_pre, leaf_dabits, tag_leaf};
use rand::{CryptoRng, Rng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use std::time::{Duration, Instant};

/// The randomness that fixes a key pair besides α and β: the cleartext
/// counterpart of the preprocessing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DealParams {
    /// Party b's root, `lsb(r_b) = b`.
    pub roots: [Block; 2],
    /// The glue level ν.
    pub nu: usize,
    /// `V_1, …, V_n`, `lsb(V_ℓ) = 1`: the on-path offset of level ℓ.
    pub v: Vec<Block>,
    /// `u_{ℓ,0}` for `ℓ = max(ν, 1), …, n`.
    pub u: Vec<Block>,
}

impl DealParams {
    /// Random parameters for depth n and glue level ν.
    pub fn random<R: RngCore + CryptoRng>(rng: &mut R, n: usize, nu: usize) -> Self {
        assert!(nu <= n && n >= 1);
        DealParams {
            roots: [Block::random(rng).with_lsb(false), Block::random(rng).with_lsb(true)],
            nu,
            v: (0..n).map(|_| Block::random(rng).with_lsb(true)).collect(),
            u: (nu.max(1)..=n).map(|_| Block::random(rng)).collect(),
        }
    }
}

/// The public words of one level from the on-path nodes' `G` outputs (`g[j]`
/// of party j's node), `α_ℓ` and `U_ℓ`.
fn level_word(g: [[Block; 2]; 2], a: bool, v: Block) -> LevelWord {
    let d = [g[0][0] ^ g[1][0], g[0][1] ^ g[1][1]];
    let us = seed(v);
    LevelWord { s: [seed(d[0] ^ us.and_bit(!a)), seed(d[1] ^ us.and_bit(a))], t: [d[0].lsb() ^ a ^ true, d[1].lsb() ^ a] }
}

/// The cleartext tree: the level words, the shifts and the on-path leaf
/// states. Asserts the invariant at every level: the on-path nodes differ by
/// `V_ℓ`, and from the glue level on they are `u_{ℓ,0}`, `u_{ℓ,0} ⊕ V_ℓ`.
fn deal_tree(p: &DealParams, n_size: u64, alpha: u64) -> (Vec<LevelWord>, Vec<Block>, [Block; 2]) {
    let n = depth_for(n_size);
    let nu = p.nu;
    assert!(alpha < n_size && nu <= n && p.v.len() == n && p.u.len() == n + 1 - nu.max(1));
    assert!(!p.roots[0].lsb() && p.roots[1].lsb(), "lsb(r_b) = b");
    assert!(p.v.iter().all(|v| v.lsb()), "lsb(V_ℓ) = 1");
    let first = nu.max(1);
    let mut st = p.roots;
    let (mut cws, mut ms) = (Vec::with_capacity(n), Vec::with_capacity(p.u.len()));
    for i in 0..n {
        let level = i + 1;
        let a = (alpha >> (n - 1 - i)) & 1 == 1;
        let g = [expand(st[0]), expand(st[1])];
        let cw = level_word(g, a, p.v[i]);
        st = [0, 1].map(|j| cw.children(g[j], st[j].lsb(), Block::ZERO)[a as usize]);
        assert_eq!(st[0] ^ st[1], p.v[i], "on-path offset at level {level}");
        if level >= first {
            let m = st[0] ^ p.u[level - first];
            st = [st[0] ^ m, st[1] ^ m];
            ms.push(m);
        }
        cws.push(cw);
    }
    (cws, ms, st)
}

/// Trusted-dealer generation: the cleartext Gen, and the bit-exact oracle of
/// [`gen`].
pub fn deal(p: &DealParams, n_size: u64, bits: usize, alpha: u64, beta: Word) -> [BinKey; 2] {
    assert!((1..=256).contains(&bits) && beta == beta.masked(bits));
    let (cws, ms, st) = deal_tree(p, n_size, alpha);
    let w_cw = conv(st[0], bits) ^ conv(st[1], bits) ^ beta;
    let mk = |party: usize| BinKey { party, bits, tree: Tree { n_size, nu: p.nu, root: p.roots[party], cws: cws.clone(), ms: ms.clone() }, w_cw };
    [mk(0), mk(1)]
}

/// The cleartext Gen with an arithmetic payload, the oracle of [`gen_arith`].
pub fn deal_arith<F: Field>(p: &DealParams, n_size: u64, alpha: u64, beta: F) -> [ArithKey<F>; 2] {
    let (cws, ms, st) = deal_tree(p, n_size, alpha);
    let sigma = st[0].lsb();
    let v = st[0] ^ st[1];
    let y = st[0] ^ v.and_bit(sigma);
    let w = |s: Block| F::from_block(leaf_mask::<F>(s));
    let w_cw = w(y).sub(w(y ^ v)).sub(if sigma { beta.neg() } else { beta });
    let mk = |party: usize| ArithKey { party, tree: Tree { n_size, nu: p.nu, root: p.roots[party], cws: cws.clone(), ms: ms.clone() }, w_cw };
    [mk(0), mk(1)]
}

/// Trusted-dealer generation from a seed, glue level ν (default
/// [`default_nu`]).
pub fn gen_reference(n_size: u64, nu: Option<usize>, bits: usize, alpha: u64, beta: Word, seed: [u8; 32]) -> [BinKey; 2] {
    let n = depth_for(n_size);
    let mut rng = ChaCha20Rng::from_seed(seed);
    let p = DealParams::random(&mut rng, n, nu.unwrap_or(default_nu(n)));
    deal(&p, n_size, bits, alpha, beta)
}

/// [`gen_reference`] with an arithmetic payload.
pub fn gen_reference_arith<F: Field>(n_size: u64, nu: Option<usize>, alpha: u64, beta: F, seed: [u8; 32]) -> [ArithKey<F>; 2] {
    let n = depth_for(n_size);
    let mut rng = ChaCha20Rng::from_seed(seed);
    let p = DealParams::random(&mut rng, n, nu.unwrap_or(default_nu(n)));
    deal_arith(&p, n_size, alpha, beta)
}

/// A bit-times-3-block Beaver triple's shares.
type WideTriple = (bool, [Block; 3], [Block; 3]);

/// `m` bit-times-3-block triples from one random COT per direction each, the
/// COT hashed into three blocks (as `rot_string_triples`, with one hash per
/// block). Sends nothing beyond Ferret's own refills.
fn rot_wide_triples<R: RngCore + CryptoRng>(ch: &mut Channel, cot: &mut CotPair, m: usize, rng: &mut R) -> Vec<WideTriple> {
    let gamma = cot.delta();
    let h = |x: Block, i: usize| [0, 1, 2].map(|j| cot_hash().h(x, (5 << 60) | (3 * i + j) as u64));
    let x3 = |a: [Block; 3], b: [Block; 3]| [a[0] ^ b[0], a[1] ^ b[1], a[2] ^ b[2]];
    let (mut a, mut bb, mut c) = (vec![false; m], vec![[Block::ZERO; 3]; m], vec![[Block::ZERO; 3]; m]);
    for s in 0..2 {
        match cot.random_cots(ch, s, m, rng).expect("semi-honest COT") {
            RandomCots::Sender(k) => {
                for i in 0..m {
                    let (y0, y1) = (h(k[i], i), h(k[i] ^ gamma, i));
                    bb[i] = x3(y0, y1);
                    c[i] = x3(c[i], y0);
                }
            }
            RandomCots::Receiver(r, macs) => {
                for i in 0..m {
                    a[i] = r[i];
                    c[i] = x3(c[i], h(macs[i], i));
                }
            }
        }
    }
    (0..m).map(|i| (a[i], bb[i], [0, 1, 2].map(|j| c[i][j] ^ bb[i][j].and_bit(a[i])))).collect()
}

/// One party's preprocessing of one Gen.
pub struct Pre {
    pub n: usize,
    pub nu: usize,
    /// `⟨α_ℓ⟩`, level 1 first.
    pub alpha: Vec<bool>,
    /// `⟨V_ℓ⟩` (the tag bit 1 is party 0's), `ℓ = 1, …, n`.
    pub v: Vec<Block>,
    /// `⟨α_ℓ·seed(U_ℓ)⟩`.
    pub av: Vec<Block>,
    /// `⟨u_{ℓ,0}⟩` for `ℓ = max(ν, 1), …, n`.
    pub u: Vec<Block>,
    /// `⟨t_{ℓ−1,0}·α_ℓ⟩` for the bottom levels (index ℓ − 1).
    pub ta: Vec<bool>,
    /// The multiplexer triple of each level: `(⟨Y_3⟩, ⟨α_ℓ·Y_3⟩)`.
    pub mux: Vec<(Block, Block)>,
    /// This party's root.
    pub root: Block,
    /// The glue's bit-times-block triple.
    pub glue: Vec<(bool, Block, Block)>,
    /// The bit-times-block triple of `⟨Y⟩` (arithmetic payload).
    pub leaf_triple: Option<(bool, Block, Block)>,
    /// The LPN-PRG correlations.
    pub prg: Vec<PrgCorr>,
}

impl Pre {
    fn first(&self) -> usize {
        self.nu.max(1)
    }

    /// `⟨u_{ℓ,0}⟩` for `ℓ ≥ max(ν, 1)`.
    fn u0(&self, level: usize) -> Block {
        self.u[level - self.first()]
    }

    /// This party's α share as an integer (bit `n − 1 − i` is level i + 1).
    pub fn alpha_share(&self) -> u64 {
        self.alpha.iter().fold(0, |acc, &a| (acc << 1) | a as u64)
    }
}

/// The preprocessing of one Gen of depth n and glue level ν, with ℓ = `bits`
/// mask bits per leaf and, if `y`, the triple of `⟨Y⟩`.
pub fn precompute<R: RngCore + CryptoRng>(ch: &mut Channel, cot: &mut CotPair, n: usize, nu: usize, bits: usize, y: bool, rng: &mut R) -> Pre {
    assert!(n >= 1 && nu <= n);
    let b = ch.party();
    let mut tweak = 0;
    let prg = preprocess(ch, cot, prg_calls(n, nu, bits), &mut tweak, rng);
    let wide = rot_wide_triples(ch, cot, n, rng);
    let mut glue = rot_string_triples(ch, cot, (nu >= 1) as usize + y as usize, rng);
    let leaf_triple = if y { glue.pop() } else { None };
    let first = nu.max(1);
    let alpha: Vec<bool> = wide.iter().map(|t| t.0).collect();
    let v: Vec<Block> = wide.iter().map(|t| t.1[0].with_lsb(b == 0)).collect();
    let av: Vec<Block> = wide.iter().map(|t| seed(t.2[0])).collect();
    // u_{ℓ−1,0} of bottom level ℓ is Y_2 of level ℓ; u_{n,0} is fresh.
    let mut u: Vec<Block> = (first + 1..=n).map(|l| wide[l - 1].1[1]).collect();
    u.push(Block::random(rng));
    let ta: Vec<bool> = wide.iter().map(|t| t.2[1].lsb()).collect();
    let mux = wide.iter().map(|t| (t.1[2], t.2[2])).collect();
    let root = Block::random(rng).with_lsb(b == 1);
    Pre { n, nu, alpha, v, av, u, ta, mux, root, glue, leaf_triple, prg }
}

/// Opens an XOR-shared message on `lane` (one round).
fn open_on(ch: &mut Channel, lane: &mut Lane, mine: Vec<u8>) -> Vec<u8> {
    let theirs = ch.exchange_on(lane, mine.clone());
    assert_eq!(theirs.len(), mine.len(), "malformed share");
    mine.iter().zip(theirs).map(|(x, y)| x ^ y).collect()
}

/// This party's share of a level word, packed: `s^L ∥ s^R ∥ (t^L | t^R << 1)`.
fn word_share(b: usize, d: [Block; 2], a: bool, v: Block, av: Block) -> Vec<u8> {
    // ¬α·U = U ⊕ α·U.
    let sl = seed(d[0] ^ seed(v) ^ av);
    let sr = seed(d[1] ^ av);
    let tl = d[0].lsb() ^ a ^ (b == 0);
    let tr = d[1].lsb() ^ a;
    let mut msg = Vec::with_capacity(33);
    msg.extend_from_slice(&sl.to_bytes());
    msg.extend_from_slice(&sr.to_bytes());
    msg.push(tl as u8 | (tr as u8) << 1);
    msg
}

fn unpack_word(m: &[u8]) -> LevelWord {
    LevelWord { s: [Block::from_bytes(&m[..16]), Block::from_bytes(&m[16..32])], t: [m[32] & 1 == 1, m[32] & 2 == 2] }
}

/// `⟨x_i·Y_i⟩` for shared bits and blocks, by Beaver on bit-times-block
/// triples: one round on `lane`.
fn bit_times_block(ch: &mut Channel, lane: &mut Lane, xy: &[(bool, Block)], t: &[(bool, Block, Block)]) -> Vec<Block> {
    let b = ch.party();
    assert_eq!(t.len(), xy.len(), "bit-times-block triples exhausted");
    let mut msg = Vec::with_capacity(17 * xy.len());
    for (&(x, y), &(a, bb, _)) in xy.iter().zip(t) {
        msg.extend_from_slice(&(y ^ bb).to_bytes());
        msg.push((x ^ a) as u8);
    }
    let opened = open_on(ch, lane, msg);
    (0..xy.len())
        .map(|i| {
            let (a, bb, c) = t[i];
            let f = Block::from_bytes(&opened[17 * i..17 * i + 16]);
            let e = opened[17 * i + 16] & 1 == 1;
            // x·Y = e·f ⊕ e·B ⊕ a·f ⊕ a·B.
            f.and_bit(e && b == 0) ^ bb.and_bit(e) ^ f.and_bit(a) ^ c
        })
        .collect()
}

/// The top phase and the glue on `lane`: the level words of levels 1..=ν and
/// `M_ν`.
fn top(pre: &Pre, ch: &mut Channel, lane: &mut Lane) -> (Vec<LevelWord>, Block) {
    let b = ch.party();
    let nu = pre.nu;
    let mut nodes = vec![pre.root];
    let mut cws = Vec::with_capacity(nu);
    for i in 0..nu {
        let gs: Vec<[Block; 2]> = nodes.iter().map(|&s| expand(s)).collect();
        let d = gs.iter().fold([Block::ZERO; 2], |acc, g| [acc[0] ^ g[0], acc[1] ^ g[1]]);
        let share = word_share(b, d, pre.alpha[i], pre.v[i], pre.av[i]);
        let cw = unpack_word(&open_on(ch, lane, share));
        let mut next = Vec::with_capacity(2 * nodes.len());
        for (&st, &g) in nodes.iter().zip(&gs) {
            next.extend(cw.children(g, st.lsb(), Block::ZERO));
        }
        nodes = next;
        cws.push(cw);
    }
    // Glue: E_b and A_b over level ν.
    let (e_b, a_b) = nodes.iter().filter(|s| s.lsb()).fold((Block::ZERO, 0u64), |(e, c), &s| (e ^ s, c + 1));
    // Party 0 holds a = A_0 mod 4, party 1 e = −A_1 mod 4; t_{ν,0} = 1 iff
    // a + e ≡ 1 (mod 4). a + e is odd, so a_0·e_0 = 0 and ¬t_{ν,0} = a_1 ⊕ e_1:
    // each party's share is its high bit (as in ht-aes, Lemma "Glue").
    let v = if b == 0 { a_b % 4 } else { (4 - a_b % 4) % 4 };
    let not_t = (v >> 1) & 1 == 1;
    // ⟨st_{ν,0}⟩ = ⟨E⟩ ⊕ ¬⟨t_{ν,0}⟩·⟨V_ν⟩.
    let st = e_b ^ bit_times_block(ch, lane, &[(not_t, pre.v[nu - 1])], &pre.glue[..1])[0];
    let m = open_on(ch, lane, (st ^ pre.u0(nu)).to_bytes().to_vec());
    (cws, Block::from_bytes(&m))
}

/// `⟨Y⟩ = ⟨u_{n,0}⟩ ⊕ ⟨t_{n,0}·V_n⟩`, one round on `lane`.
fn leaf_y(pre: &Pre, ch: &mut Channel, lane: &mut Lane) -> Block {
    let (u, v) = (pre.u0(pre.n), pre.v[pre.n - 1]);
    let triple = pre.leaf_triple.expect("the triple of Y");
    u ^ bit_times_block(ch, lane, &[(u.lsb(), v)], &[triple])[0]
}

/// Generation proper, given the preprocessing: the level words, the shifts
/// and the leaf word. `before` runs on the leaf lane before the batch of PRG
/// calls and returns the leaf word if it needs no PRG call, and the extra
/// inputs of the batch otherwise; `after` gets the outputs of those inputs,
/// on a lane that starts after the batch.
fn gen_with<L>(
    pre: &Pre,
    ch: &mut Channel,
    before: impl FnOnce(&mut Channel, &mut Lane) -> (Option<L>, Vec<u128>),
    after: impl FnOnce(&mut Channel, &mut Lane, &[[Block; 2]]) -> L,
) -> (Vec<LevelWord>, Vec<Block>, L) {
    let b = ch.party();
    let (n, nu) = (pre.n, pre.nu);
    let k = n - nu;
    // Top phase and glue on their own lane.
    let mut top_lane = ch.lane();
    let (mut cws, mut ms) = if nu >= 1 {
        let (c, m) = top(pre, ch, &mut top_lane);
        (c, vec![m])
    } else {
        (vec![], vec![])
    };
    let mut leaf_lane = ch.lane();
    let (mut w_cw, extra) = before(ch, &mut leaf_lane);
    // Bottom: the on-path inputs of levels ν + 1..=n, and the leaf's.
    let inputs = |level: usize| -> [Block; 2] {
        // The on-path nodes of level `level` (≥ ν).
        if level == 0 {
            let mut r = [Block::ZERO; 2];
            r[b] = pre.root;
            r
        } else {
            let u0 = pre.u0(level);
            [u0, u0 ^ pre.v[level - 1]]
        }
    };
    let mut xs: Vec<u128> = (nu..n).flat_map(|l| inputs(l).map(|x| seed(x).0)).collect();
    xs.extend(extra);
    let y: Vec<[Block; 2]> = eval_shared(ch, &pre.prg, &xs).into_iter().map(|g| [Block(g[0]), Block(g[1])]).collect();
    let mut after_lane = ch.lane();
    if w_cw.is_none() {
        w_cw = Some(after(ch, &mut after_lane, &y[2 * k..]));
    }
    if k > 0 {
        // Side and tag words, and the multiplexer's opened block f = (st^L_0 ⊕ st^R_0) ⊕ Y_3.
        let mut msg = Vec::with_capacity(49 * k);
        for j in 0..k {
            let i = nu + j;
            let (g0, g1) = (y[2 * j], y[2 * j + 1]);
            msg.extend(word_share(b, [g0[0] ^ g1[0], g0[1] ^ g1[1]], pre.alpha[i], pre.v[i], pre.av[i]));
            msg.extend_from_slice(&(g0[0] ^ g0[1] ^ pre.mux[i].0).to_bytes());
        }
        ch.send(msg.clone());
        let theirs = ch.recv();
        assert_eq!(theirs.len(), msg.len(), "malformed bottom-level share");
        let opened: Vec<u8> = msg.iter().zip(theirs).map(|(x, y)| x ^ y).collect();
        let mut m_shares = Vec::with_capacity(k);
        for j in 0..k {
            let (i, level) = (nu + j, nu + j + 1);
            let o = &opened[49 * j..49 * (j + 1)];
            let cw = unpack_word(&o[..33]);
            let f = Block::from_bytes(&o[33..]);
            let g0 = y[2 * j];
            // st^Keep_0 = st^L_0 ⊕ α·(st^L_0 ⊕ st^R_0), α·Y = α·f ⊕ α·Y_3.
            let keep0 = g0[0] ^ f.and_bit(pre.alpha[i]) ^ pre.mux[i].1;
            // t_{ℓ−1,0}·(s^Keep ∥ t^Keep) = t·w_L ⊕ (t·α)·(w_L ⊕ w_R).
            let (t, ta) = if level == 1 { (false, false) } else { (pre.u0(level - 1).lsb(), pre.ta[i]) };
            let (wl, wr) = (cw.side(0), cw.side(1));
            let corr = wl.and_bit(t) ^ (wl ^ wr).and_bit(ta);
            m_shares.push(keep0 ^ corr ^ pre.u0(level));
            cws.push(cw);
        }
        ch.send_blocks(&m_shares);
        ms.extend(m_shares.iter().zip(ch.recv_blocks(k)).map(|(&x, y)| x ^ y));
    }
    ch.join(after_lane);
    ch.join(leaf_lane);
    ch.join(top_lane);
    (cws, ms, w_cw.expect("leaf word"))
}

/// The leaf of the Boolean payload around [`gen_with`]: for ℓ ≤ λ,
/// `Conv(u_{n,0}) ⊕ Conv(u_{n,1}) = Conv(V_n)`, linear.
fn gen_bin_key(pre: &Pre, ch: &mut Channel, n_size: u64, bits: usize, beta_share: Word) -> BinKey {
    let (cws, ms, w_cw) = gen_with(
        pre,
        ch,
        |ch, lane| {
            if bits <= SEED_BITS {
                let share = conv(pre.v[pre.n - 1], bits) ^ beta_share;
                (Some(Word::from_bytes(&open_on(ch, lane, share.to_bytes(bits)))), vec![])
            } else {
                let u = pre.u0(pre.n);
                (None, vec![seed(u).0, seed(u ^ pre.v[pre.n - 1]).0])
            }
        },
        |ch, lane, y| {
            let share = conv_prg(y[0], bits) ^ conv_prg(y[1], bits) ^ beta_share;
            Word::from_bytes(&open_on(ch, lane, share.to_bytes(bits)))
        },
    );
    BinKey { party: ch.party(), bits, tree: Tree { n_size, nu: pre.nu, root: pre.root, cws, ms }, w_cw }
}

/// The tag-indexed leaf of an arithmetic payload around [`gen_with`].
fn gen_arith_key<F: Field>(pre: &Pre, dabits: &[(bool, F)], ch: &mut Channel, n_size: u64, beta: F) -> ArithKey<F> {
    let t = pre.u0(pre.n).lsb();
    let v = pre.v[pre.n - 1];
    let (cws, ms, w_cw) = gen_with(
        pre,
        ch,
        |ch, lane| {
            if mask_from_seed::<F>() {
                let y = leaf_y(pre, ch, lane);
                (Some(tag_leaf(ch, lane, [seed_mask(y), seed_mask(y ^ v)], t, dabits, beta)), vec![])
            } else {
                // The batch's inputs depend on the product.
                let mut first = ch.lane();
                let y = leaf_y(pre, ch, &mut first);
                ch.join(first);
                (None, vec![seed(y).0, seed(y ^ v).0])
            }
        },
        |ch, lane, g| tag_leaf(ch, lane, [g[0][0], g[1][0]], t, dabits, beta),
    );
    ArithKey { party: ch.party(), tree: Tree { n_size, nu: pre.nu, root: pre.root, cws, ms }, w_cw }
}

/// Everything one party gets out of [`gen`] or [`gen_arith`].
pub struct GenOutput<K = BinKey> {
    pub key: K,
    /// This party's XOR share of the random α (bit `n − 1 − i` is level i + 1).
    pub alpha_share: u64,
    /// This party's shares of `V_1, …, V_n` and of `u_{ℓ,0}`, `ℓ ≥ max(ν, 1)`
    /// (for the tests' oracle).
    pub v_share: Vec<Block>,
    pub u_share: Vec<Block>,
    pub setup_stats: CommStats,
    pub pre_stats: CommStats,
    pub gen_stats: CommStats,
    pub setup_time: Duration,
    pub pre_time: Duration,
    pub gen_time: Duration,
    /// 2PC calls of the LPN-PRG.
    pub prg_calls: usize,
    /// Bit products in Gen: the glue's product, one multiplexer per
    /// bottom level, and the product of `⟨Y⟩` for an arithmetic payload.
    pub products: usize,
    /// COTs consumed after setup (both directions).
    pub cots: usize,
}

/// Setup, preprocessing (the common part and `extra`), then `run`.
#[allow(clippy::too_many_arguments)]
fn drive<K, X>(
    ch: &mut Channel,
    n_size: u64,
    nu: Option<usize>,
    bits: usize,
    y: bool,
    seed: [u8; 32],
    ferret: FerretConfig,
    extra: impl FnOnce(&mut Channel, &mut CotPair, &mut ChaCha20Rng) -> X,
    run: impl FnOnce(&Pre, X, &mut Channel) -> K,
) -> GenOutput<K> {
    let n = depth_for(n_size);
    let nu = nu.unwrap_or(default_nu(n));
    assert!(nu <= n, "0 ≤ ν ≤ n");
    let t_setup = Instant::now();
    let mut rng = ChaCha20Rng::from_seed(seed);
    let delta = Block::random(&mut rng);
    let mut cot = CotPair::setup(ch, &mut rng, delta, false).expect("semi-honest base OT");
    cot.enable_ferret(ch, ferret, &mut rng).expect("semi-honest Ferret");
    ch.sync();
    let setup_stats = ch.stats();
    let setup_time = t_setup.elapsed();
    let cots_before = cot.produced;
    let t_pre = Instant::now();
    let pre = precompute(ch, &mut cot, n, nu, bits, y, &mut rng);
    let x = extra(ch, &mut cot, &mut rng);
    let pre_stats = ch.stats().since(&setup_stats);
    let pre_time = t_pre.elapsed();
    // Timing only: neither party's gen time includes waiting for the other's
    // preprocessing. Counted in no phase.
    ch.sync();
    let gen_start = ch.stats();
    let t_gen = Instant::now();
    let key = run(&pre, x, ch);
    GenOutput {
        key,
        alpha_share: pre.alpha_share(),
        v_share: pre.v.clone(),
        u_share: pre.u.clone(),
        gen_stats: ch.stats().since(&gen_start),
        setup_stats,
        pre_stats,
        setup_time,
        pre_time,
        gen_time: t_gen.elapsed(),
        prg_calls: prg_calls(n, nu, bits),
        products: (nu >= 1) as usize + (n - nu) + y as usize,
        cots: cot.produced - cots_before,
    }
}

/// This party's side of the generation: setup, preprocessing, then Gen with
/// glue level ν (`0 ≤ ν ≤ n`, [`default_nu`] if `None`), a random α and an
/// XOR-shared `β ∈ {0,1}^ℓ`, `1 ≤ ℓ ≤ 256`. `ferret`: the silent-OT
/// parameters (`B13` for benchmarks, `TOY` for tests).
pub fn gen(ch: &mut Channel, n_size: u64, nu: Option<usize>, bits: usize, beta_share: Word, seed: [u8; 32], ferret: FerretConfig) -> GenOutput {
    assert!((1..=256).contains(&bits));
    drive(ch, n_size, nu, bits, false, seed, ferret, |_, _, _| (), |pre, (), ch| gen_bin_key(pre, ch, n_size, bits, beta_share))
}

/// [`gen`] with a public payload in the prime field F and additive output
/// shares. The daBits of the leaf follow the common preprocessing, as in the
/// half-tree instance.
pub fn gen_arith<F: Field>(ch: &mut Channel, n_size: u64, nu: Option<usize>, beta: F, seed: [u8; 32], ferret: FerretConfig) -> GenOutput<ArithKey<F>> {
    drive(
        ch,
        n_size,
        nu,
        F::KAPPA,
        true,
        seed,
        ferret,
        |ch, cot, rng| fp_pre::<F, F, _>(ch, cot, leaf_dabits::<F>(&[1]), 0, &[], rng),
        |pre, fpre, ch| gen_arith_key(pre, &fpre.dabits, ch, n_size, beta),
    )
}

/// Both parties' [`gen`] on an in-process channel, β XOR-shared at random;
/// returns the outputs and each party's wall time.
pub fn run_gen(n_size: u64, nu: Option<usize>, bits: usize, beta: Word, seed: u64, ferret: FerretConfig) -> ([GenOutput; 2], [Duration; 2]) {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let seeds: [[u8; 32]; 2] = [rng.gen(), rng.gen()];
    let b0 = Word::random(&mut rng, bits);
    let shares = [b0, b0 ^ beta];
    let timed = |party: usize| {
        move |c: &mut Channel| {
            let t = Instant::now();
            let o = gen(c, n_size, nu, bits, shares[party], seeds[party], ferret);
            (o, t.elapsed())
        }
    };
    let ((o0, t0), (o1, t1)) = run_two_party(timed(0), timed(1));
    ([o0, o1], [t0, t1])
}

/// Both parties' [`gen_arith`] on an in-process channel.
pub fn run_gen_arith<F: Field>(n_size: u64, nu: Option<usize>, beta: F, seed: u64, ferret: FerretConfig) -> ([GenOutput<ArithKey<F>>; 2], [Duration; 2]) {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let seeds: [[u8; 32]; 2] = [rng.gen(), rng.gen()];
    let timed = |party: usize| {
        move |c: &mut Channel| {
            let t = Instant::now();
            let o = gen_arith(c, n_size, nu, beta, seeds[party], ferret);
            (o, t.elapsed())
        }
    };
    let ((o0, t0), (o1, t1)) = run_two_party(timed(0), timed(1));
    ([o0, o1], [t0, t1])
}
