//! Semi-honest dealer-free generation (Figure "DPF.Gen" of the paper) with
//! `F_PRF` = AES–MMO in 2PC and F4 triples from FOLEAGE.
//!
//! **Setup** (once per session): each party picks `Δ_b` with `lsb(Δ_b) = b`
//! and runs the base OTs of a COT instance keyed by `Δ_b` in each direction,
//! then bootstraps Ferret on it. The FOLEAGE seeds for `3^N` F4-OLEs are then
//! generated without a dealer ([`dpf_common::foleage::seedgen`]); N is the
//! smallest (≥ 12) that covers the Gen's [`crate::sh_products`] triples.
//!
//! **Preprocessing** (before α and β are known): FOLEAGE expansion and the F4
//! triples, n bit-times-block triples for the branch selection from Ferret
//! random OTs ([`rot_string_triples`]), and Ferret COTs for the n α-bits and
//! the 2ℓ + 1 MUXes.
//!
//! **Generation**, with `α` XOR-shared (bit `n − 1 − i` is level i + 1) and
//! `β` additively shared in Z_2^ℓ:
//!
//! 1. `⟨α_ℓ·Δ⟩` for all levels from the derandomised COTs (one round):
//!    `α_{ℓ,b}·Δ_b ⊕ M_b[α_{ℓ,b}] ⊕ K_b[α_{ℓ,1−b}]`.
//! 2. `⟨st_{0,0}⟩ = (Δ_0, 0)`, `⟨Δ⟩ = (Δ_0, Δ_1)`, so `⟨st_{0,1}⟩ = (0, Δ_1)`.
//! 3. Per level: two AES–MMO calls on `⟨st_{ℓ−1,0}⟩`, `⟨st_{ℓ−1,0}⟩ ⊕ ⟨Δ⟩` (40
//!    rounds), then one exchange carrying the CW share and the Beaver opening
//!    `(α_ℓ ⊕ a, st_{ℓ−1,0} ⊕ B)` of the branch selection; the new state is
//!    local.
//! 4. Leaf: `W_b = F^pay(s_{n,b} ∥ 0)` for both b (40 rounds), B2A of the 2ℓ
//!    bits with one SIRNN MUX each and the sign with one more on `t_{n,0}`, as
//!    FssNN's arithmetic final word (two rounds each), and the opening of
//!    `W_CW = (−1)^{t_{n,0}}(W_0 − W_1 − β)`.
//!
//! Rounds: `1 + 41n + 40 + 2 + 2 + 1 = 41n + 46`.

use super::key::ShKey;
use crate::{leaf_seed, pay_hash, sh_products, state_hash};
use dpf_common::aes_tower::{bits_of, block_of, mmo_shared, BeaverF4, Mmo, Shared128};
use dpf_common::arith::{mux, Ring};
use dpf_common::block::{depth_for, Block};
use dpf_common::bool2pc::rot_string_triples;
use dpf_common::foleage::{self, seedgen::seed_gen, Params};
use dpf_common::net::{Channel, CommStats};
use dpf_common::ot::{CotPair, FerretConfig};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::time::{Duration, Instant};

/// Everything one party gets out of [`gen`].
pub struct GenOutput<T: Ring> {
    pub key: ShKey<T>,
    /// Base OTs, Ferret bootstrap and the FOLEAGE seed generation.
    pub setup_stats: CommStats,
    pub pre_stats: CommStats,
    pub gen_stats: CommStats,
    pub setup_time: Duration,
    pub pre_time: Duration,
    pub gen_time: Duration,
    /// F4 products (Beaver triples) used by the AES calls.
    pub products: usize,
    /// COTs consumed after setup (α-bits, MUXes, branch-selection triples).
    pub cots: usize,
    /// The FOLEAGE instance: `3^N` OLEs.
    pub foleage: Params,
    /// FOLEAGE seed generation alone (part of setup).
    pub seedgen_stats: CommStats,
    pub seedgen_time: Duration,
}

/// The correlations one generation consumes.
pub struct Pre {
    pub be: BeaverF4,
    /// `(a, B, a·B)` for the n branch selections.
    pub string_triples: Vec<(bool, Block, Block)>,
}

/// Preprocessing for depth `n` and width `bits`: FOLEAGE expansion and
/// triples, string triples, Ferret COTs.
pub fn precompute(ch: &mut Channel, cot: &mut CotPair, seed: &foleage::Seed, n: usize, bits: usize, rng: &mut ChaCha20Rng) -> Pre {
    let ole = seed.expand();
    let be = BeaverF4::new(ch.party(), foleage::triples(&ole, ch.party(), sh_products(n)));
    drop(ole);
    let string_triples = rot_string_triples(ch, cot, n, rng);
    let cots = n + 2 * bits + 1;
    cot.precompute(ch, cots, cots, rng).expect("semi-honest COT");
    Pre { be, string_triples }
}

#[allow(clippy::too_many_arguments)]
fn gen_with<T: Ring>(
    cot: &mut CotPair,
    pre: Pre,
    rng: &mut ChaCha20Rng,
    ch: &mut Channel,
    n_size: u64,
    bits: usize,
    alpha_share: u64,
    beta_share: T,
) -> (ShKey<T>, usize) {
    let b = ch.party();
    let n = depth_for(n_size);
    let Pre { mut be, string_triples } = pre;
    let delta = cot.delta();
    let (fs, fp): (&Mmo, &Mmo) = (state_hash(), pay_hash());

    // 1. ⟨α_ℓ·Δ⟩.
    let a: Vec<bool> = (0..n).map(|i| (alpha_share >> (n - 1 - i)) & 1 == 1).collect();
    let (k, m) = cot.extend(ch, &a, n, rng).expect("semi-honest COT");
    let a_delta: Vec<Block> = (0..n).map(|i| delta.and_bit(a[i]) ^ m[i] ^ k[i]).collect();

    // 2. Root shares.
    let mut st = if b == 0 { delta } else { Block::ZERO };
    let mut cws = Vec::with_capacity(n);
    for i in 0..n {
        // 3A. L_0, L_1.
        let jobs: [(&Mmo, Shared128<bool>); 2] = [(fs, bits_of(st)), (fs, bits_of(st ^ delta))];
        let l = mmo_shared(&mut be, ch, &jobs);
        let (l0, l1) = (block_of(&l[0]), block_of(&l[1]));
        // 3B + C opening.
        let cw_share = l0 ^ l1 ^ delta ^ a_delta[i];
        let (ta, tb, tc) = string_triples[i];
        let (e, f) = (a[i] ^ ta, st ^ tb);
        let mut msg = Vec::with_capacity(33);
        msg.extend_from_slice(&cw_share.to_bytes());
        msg.extend_from_slice(&f.to_bytes());
        msg.push(e as u8);
        ch.send(msg);
        let theirs = ch.recv();
        assert_eq!(theirs.len(), 33, "malformed level message");
        let cw = cw_share ^ Block::from_bytes(&theirs[..16]);
        let (f, e) = (f ^ Block::from_bytes(&theirs[16..32]), e ^ (theirs[32] & 1 == 1));
        // α·st = e·f ⊕ e·B ⊕ f·a ⊕ C.
        let prod = f.and_bit(e && b == 0) ^ tb.and_bit(e) ^ f.and_bit(ta) ^ tc;
        st = l0 ^ prod ^ cw.and_bit(st.lsb());
        cws.push(cw);
    }

    // 4. Leaf word.
    let jobs: [(&Mmo, Shared128<bool>); 2] = [(fp, bits_of(leaf_seed(st))), (fp, bits_of(leaf_seed(st ^ delta)))];
    let w = mmo_shared(&mut be, ch, &jobs);
    let wb = [block_of(&w[0]), block_of(&w[1])];
    let g: Vec<bool> = wb.iter().flat_map(|w| (0..bits).map(move |i| w.bit(i))).collect();
    let w1: Vec<T> = (0..2 * bits).map(|k| if b == 0 { T::ONE.shl(k % bits) } else { T::ZERO }).collect();
    let y = mux(ch, cot, &g, &vec![T::ZERO; 2 * bits], &w1, bits, rng).expect("semi-honest MUX");
    let msk = T::mask(bits);
    let sum = |ys: &[T]| ys.iter().fold(T::ZERO, |acc, &v| acc.add(v)).and(msk);
    let v = sum(&y[..bits]).sub(sum(&y[bits..])).sub(beta_share).and(msk);
    let signed = mux(ch, cot, &[st.lsb()], &[v], &[v.neg().and(msk)], bits, rng).expect("semi-honest MUX")[0];
    let mut out = Vec::with_capacity(T::BYTES);
    signed.put(&mut out);
    ch.send(out);
    let theirs = ch.recv();
    assert_eq!(theirs.len(), T::BYTES, "malformed payload share");
    let w_cw = signed.add(T::get(&theirs)).and(msk);

    let products = be.products;
    (ShKey { party: b, n_size, bits, root: delta, cws, w_cw }, products)
}

/// Runs this party's side of setup, preprocessing and generation.
///
/// * `bits`: ℓ, `1 ≤ ℓ ≤ T::BITS` (≤ 128).
/// * `alpha_share`: XOR share of `α < N`; `beta_share`: additive share of β.
/// * `ferret`: the silent-OT parameters (`Some(FerretConfig::B13)` for
///   benchmarks); `None` keeps IKNP, for tests.
/// * `foleage`: the PCG instance, at least [`foleage_for`]`(n)`.
#[allow(clippy::too_many_arguments)]
pub fn gen<T: Ring>(ch: &mut Channel, n_size: u64, bits: usize, alpha_share: u64, beta_share: T, seed: [u8; 32], ferret: Option<FerretConfig>, foleage: Params) -> GenOutput<T> {
    assert!(bits >= 1 && bits <= T::BITS && bits <= 128);
    let t_setup = Instant::now();
    let mut rng = ChaCha20Rng::from_seed(seed);
    let party = ch.party();
    let delta = Block::random(&mut rng).with_lsb(party == 1);
    let mut cot = CotPair::setup(ch, &mut rng, delta, false).expect("semi-honest base OT");
    if let Some(cfg) = ferret {
        cot.enable_ferret(ch, cfg, &mut rng).expect("semi-honest Ferret");
    }
    let before_seed = ch.stats();
    let t_seed = Instant::now();
    let fseed = seed_gen(ch, &mut cot, foleage, &mut rng);
    let seedgen_stats = ch.stats().since(&before_seed);
    let seedgen_time = t_seed.elapsed();
    ch.sync();
    let setup_stats = ch.stats();
    let setup_time = t_setup.elapsed();
    let cots_before = cot.produced;

    let t_pre = Instant::now();
    let n = depth_for(n_size);
    assert!(2 * sh_products(n) <= foleage.oles(), "FOLEAGE instance too small for depth {n}");
    let pre = precompute(ch, &mut cot, &fseed, n, bits, &mut rng);
    drop(fseed);
    let pre_stats = ch.stats().since(&setup_stats);
    let pre_time = t_pre.elapsed();
    // Timing only: neither party's gen time includes waiting for the other's
    // preprocessing. Counted in no phase.
    ch.sync();
    let gen_start = ch.stats();
    let t_gen = Instant::now();
    let (key, products) = gen_with(&mut cot, pre, &mut rng, ch, n_size, bits, alpha_share, beta_share);
    GenOutput {
        key,
        gen_stats: ch.stats().since(&gen_start),
        setup_stats,
        pre_stats,
        setup_time,
        pre_time,
        gen_time: t_gen.elapsed(),
        products,
        cots: cot.produced - cots_before,
        foleage,
        seedgen_stats,
        seedgen_time,
    }
}

/// The FOLEAGE instance a Gen of depth n needs (two OLEs per F4 triple).
pub fn foleage_for(n: usize) -> Params {
    Params::for_oles(2 * sh_products(n))
}

/// Trusted-dealer generation for given roots (`lsb(root_b) = b`): the cleartext
/// Gen, and the bit-exact oracle of [`gen`].
pub fn deal<T: Ring>(roots: [Block; 2], n_size: u64, bits: usize, alpha: u64, beta: T) -> [ShKey<T>; 2] {
    assert!(alpha < n_size);
    assert!(!roots[0].lsb() && roots[1].lsb(), "lsb(Δ_b) = b");
    let msk = T::mask(bits);
    assert_eq!(beta, beta.and(msk), "β must fit in the output width");
    let n = depth_for(n_size);
    let delta = roots[0] ^ roots[1];
    let mut st = roots;
    let mut cws = Vec::with_capacity(n);
    for i in 0..n {
        let a = (alpha >> (n - 1 - i)) & 1 == 1;
        let l = [state_hash().h(st[0]), state_hash().h(st[1])];
        let cw = l[0] ^ l[1] ^ delta.and_bit(!a);
        st = [crate::child(st[0], cw, a), crate::child(st[1], cw, a)];
        cws.push(cw);
    }
    debug_assert_eq!(st[0] ^ st[1], delta);
    let w = |s: Block| T::from_block(pay_hash().h(leaf_seed(s))).and(msk);
    let v = w(st[0]).sub(w(st[1])).sub(beta).and(msk);
    let w_cw = if st[0].lsb() { v.neg().and(msk) } else { v };
    let mk = |party: usize| ShKey { party, n_size, bits, root: roots[party], cws: cws.clone(), w_cw };
    [mk(0), mk(1)]
}

/// Trusted-dealer generation from a seed.
pub fn gen_reference<T: Ring>(n_size: u64, bits: usize, alpha: u64, beta: T, seed: [u8; 32]) -> [ShKey<T>; 2] {
    let mut rng = ChaCha20Rng::from_seed(seed);
    let roots = [Block::random(&mut rng).with_lsb(false), Block::random(&mut rng).with_lsb(true)];
    deal(roots, n_size, bits, alpha, beta)
}
