//! Malicious generation with abort, Boolean payload (the paper's paragraph
//! "Boolean payloads"): the semi-honest Boolean Gen ([`crate::semi_honest::bin`])
//! in its session, with the MAC key `⟨δ⟩`, δ ∈ `F_{2^k}`, and addition (A) only.
//!
//! The leaf hash has `τ = ⌈(ℓ + k)/λ⌉` blocks ([`bin_tau`]), linked as in the
//! arithmetic variant: its first ℓ bits are `W(h)`, and the next k bits
//! `F^mac(h)`. The servers open `W_CW = W(h^(0)) ⊕ W(h^(1)) ⊕ β` and `W^MAC_CW =
//! F^mac(h^(0)) ⊕ F^mac(h^(1)) ⊕ β·δ`, both local XORs of the pairs' outputs (β
//! is public, so `β·⟨δ⟩` is local), right after the pairs: no B2A, no tag and no
//! `𝓕_Mul`. There is no (B), and the glue takes the semi-honest Boolean shortcut.
//!
//! The field is the type parameter K: [`crate::field::Gf64`] for ℓ ≤ 64 and
//! [`crate::field::Gf128`] above. Rounds as the semi-honest Boolean Gen: `max(ν +
//! 2, 23)` for ν < n, `max(ν + 1, 22)` for ν = n.

use super::key::{low, mac_of, MalKey};
use crate::field::Field;
use crate::leaf::{fp_pre, fp_pre_cots, FpPre};
use crate::semi_honest::gen::{drive, reference_params, setup, walk_pairs, Fault, GenOutput, PairPre, PairWalk, PreSpec, Setup, Word};
use crate::verify::VerifyMask;
use crate::{deal_leaf_words, deal_pairs, default_nu};
use dpf_common::aes_tower::Mmo;
use dpf_common::block::{depth_for, Block};
use dpf_common::net::{Channel, CommStats};
use dpf_common::ot::FerretConfig;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::time::Duration;

/// Blocks of the leaf hash: `τ = ⌈(ℓ + k)/λ⌉`.
pub fn bin_tau<K: Field>(bits: usize) -> usize {
    (bits + K::P_BITS).div_ceil(128)
}

/// One party's long-lived state.
pub struct MalSession<K: Field> {
    s: Setup,
    /// `δ_b`, this party's share of the persistent payload-MAC key.
    pub delta_mac: K,
}

/// Everything one party gets from a Gen.
pub struct MalRun<K: Field> {
    pub key: MalKey<K>,
    /// This party's XOR share of the random index α.
    pub alpha_share: u64,
    /// This party's XOR shares of the pair inputs: `[X^0_ℓ, X^1_ℓ]`, `ν ≤ ℓ ≤ n`,
    /// then `[X^{j,0}, X^{j,1}]`, `2 ≤ j ≤ τ`.
    pub pairs: Vec<[Block; 2]>,
    /// This party's XOR shares of the bits `r_ν, …, r_n`.
    pub rs: Vec<bool>,
    /// This party's share of the payload-MAC key δ.
    pub delta_share: K,
    /// This party's share of the key's Π_Verify mask.
    pub mask: VerifyMask<K>,
    /// Base OTs and the Ferret bootstrap.
    pub setup_stats: CommStats,
    pub setup_time: Duration,
    pub pre_stats: CommStats,
    pub pre_time: Duration,
    pub gen_stats: CommStats,
    pub gen_time: Duration,
    /// ANDs of the AES calls.
    pub ands: usize,
    /// COTs consumed after setup.
    pub cots: usize,
}

impl<K: Field> MalSession<K> {
    /// Π_setup (base OTs, Ferret, ⟨Δ⟩, K) and δ_b.
    pub fn setup(ch: &mut Channel, seed: [u8; 32], ferret: Option<FerretConfig>) -> Self {
        let mut s = setup(ch, seed, ferret);
        let delta_mac = K::random(&mut s.rng);
        MalSession { s, delta_mac }
    }

    /// Preprocessing and one generation of a key for a random α and the public
    /// `β ∈ F_2^ℓ`, glue level `nu ≥ 1` ([`default_nu`] if `None`), with the
    /// deviation `fault` of this party.
    pub fn gen(&mut self, ch: &mut Channel, n_size: u64, nu: Option<usize>, bits: usize, beta: Block, fault: Option<Fault>) -> MalRun<K> {
        assert!((1..=K::P_BITS).contains(&bits), "ℓ ≤ k");
        assert_eq!(beta, low(beta, bits), "β must fit in the output width");
        let n = depth_for(n_size);
        let delta_mac = self.delta_mac;
        let spec = PreSpec {
            binary: true,
            cots: fp_pre_cots::<K, K>(0, 2),
            leaf_pairs: bin_tau::<K>(bits) - 1,
            flip_alpha: match fault {
                Some(Fault::Alpha(i)) => Some(i),
                _ => None,
            },
        };
        let out = drive(
            ch,
            &mut self.s,
            n,
            nu.unwrap_or(default_nu(n)),
            spec,
            |cot, rng, ch| fp_pre::<K, K, _>(ch, cot, 0, 2, &[delta_mac], rng),
            |pre, fpre, ch| body(pre, fpre, ch, n_size, bits, beta, delta_mac, fault),
        );
        let GenOutput { key: (key, mask), alpha_share, pairs, rs, setup_stats, pre_stats, gen_stats, setup_time, pre_time, gen_time, ands, cots } = out;
        MalRun { key, alpha_share, pairs, rs, delta_share: delta_mac, mask, setup_stats, setup_time, pre_stats, pre_time, gen_stats, gen_time, ands, cots }
    }
}

#[allow(clippy::too_many_arguments, clippy::type_complexity)]
fn body<K: Field>(mut pre: PairPre, fpre: FpPre<K, K>, ch: &mut Channel, n_size: u64, bits: usize, beta: Block, delta_mac: K, fault: Option<Fault>) -> ((MalKey<K>, VerifyMask<K>), usize, Vec<[Block; 2]>) {
    let b = ch.party();
    let t = fpre.triples;
    let mask = VerifyMask { r: t[0].0, dr: t[0].2, blind: t[1] };
    let PairWalk { cws, bottom, hs, xs, leaf_words, leaf_hs, mut leaf_lane, .. } = walk_pairs(&mut pre, ch, fault, false);

    // (A) The leaf words, on the hashes of the two servers' leaf states.
    let side = |s: usize| -> Vec<Block> { std::iter::once(hs[s]).chain(leaf_hs.iter().map(|x| x[s])).collect() };
    let (h0, h1) = (side(0), side(1));
    let beta0 = if b == 0 { beta } else { Block::ZERO };
    let w_share = low(h0[0] ^ h1[0], bits) ^ beta0 ^ low(Fault::at(fault, Word::Payload), bits);
    let wm_share = mac_of::<K>(&h0, bits).add(mac_of::<K>(&h1, bits)).add(K::from_u128(beta.0).mul(delta_mac)).add(K::from_u128(Fault::at(fault, Word::Mac).0));
    let mut msg = w_share.to_bytes().to_vec();
    wm_share.put(&mut msg);
    let theirs = ch.exchange_on(&mut leaf_lane, msg);
    assert_eq!(theirs.len(), 16 + K::BYTES, "malformed payload words");
    ch.join(leaf_lane);
    let w_cw = w_share ^ Block::from_bytes(&theirs[..16]);
    let wm_cw = wm_share.add(K::get(&theirs[16..]));

    let root = pre.root();
    let key = MalKey { party: b, n_size, bits, prf: pre.key, root, cws, bottom, leaf_words, w_cw: low(w_cw, bits), wm_cw };
    ((key, mask), pre.be.ands, xs)
}

/// One session setup and one [`MalSession::gen`].
#[allow(clippy::too_many_arguments)]
pub fn run_mal<K: Field>(ch: &mut Channel, n_size: u64, nu: Option<usize>, bits: usize, beta: Block, seed: [u8; 32], ferret: Option<FerretConfig>, fault: Option<Fault>) -> MalRun<K> {
    MalSession::<K>::setup(ch, seed, ferret).gen(ch, n_size, nu, bits, beta, fault)
}

/// Trusted-dealer generation for given roots, K, glue level ν ≥ 1, pair inputs
/// and bits of levels ν..=n, the leaf pairs and δ: the cleartext Gen and the
/// bit-exact oracle of [`MalSession::gen`].
#[allow(clippy::too_many_arguments)]
pub fn deal<K: Field>(
    roots: [Block; 2],
    key: [u8; 16],
    n_size: u64,
    nu: usize,
    bits: usize,
    alpha: u64,
    beta: Block,
    delta_mac: K,
    pairs: &[[Block; 2]],
    leaf_pairs: &[[Block; 2]],
    rs: &[bool],
) -> [MalKey<K>; 2] {
    assert_eq!(beta, low(beta, bits), "β must fit in the output width");
    assert_eq!(leaf_pairs.len(), bin_tau::<K>(bits) - 1, "τ − 1 leaf pairs");
    let prf = Mmo::new(key);
    let (cws, bottom, h) = deal_pairs(&prf, roots, depth_for(n_size), nu, alpha, pairs, rs, true);
    let r_n = *rs.last().unwrap();
    let un0 = pairs.last().unwrap()[0].with_lsb(r_n);
    let leaf_words = deal_leaf_words(roots[0] ^ roots[1], un0, *bottom.c.last().unwrap(), r_n, leaf_pairs);
    let side = |s: usize| -> Vec<Block> { std::iter::once(h[s]).chain(leaf_pairs.iter().map(|p| prf.h(p[s]))).collect() };
    let (h0, h1) = (side(0), side(1));
    let w_cw = low(h0[0] ^ h1[0], bits) ^ beta;
    let wm_cw = mac_of::<K>(&h0, bits).add(mac_of::<K>(&h1, bits)).add(K::from_u128(beta.0).mul(delta_mac));
    let mk = |party: usize| MalKey { party, n_size, bits, prf: prf.clone(), root: roots[party], cws: cws.clone(), bottom: bottom.clone(), leaf_words: leaf_words.clone(), w_cw, wm_cw };
    [mk(0), mk(1)]
}

/// Dealer keys from a seed, with the δ shares.
pub fn gen_reference<K: Field>(n_size: u64, bits: usize, alpha: u64, beta: Block, seed: [u8; 32]) -> ([MalKey<K>; 2], [K; 2]) {
    assert!(alpha < n_size);
    let mut rng = ChaCha20Rng::from_seed(seed);
    let (roots, key, nu, pairs, rs) = reference_params(n_size, &mut rng);
    let leaf_pairs: Vec<[Block; 2]> = (1..bin_tau::<K>(bits)).map(|_| [Block::random(&mut rng), Block::random(&mut rng)]).collect();
    let d = [K::random(&mut rng), K::random(&mut rng)];
    (deal(roots, key, n_size, nu, bits, alpha, beta, d[0].add(d[1]), &pairs, &leaf_pairs, &rs), d)
}
