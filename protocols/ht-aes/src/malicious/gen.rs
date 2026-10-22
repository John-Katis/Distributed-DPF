//! Maliciously secure generation with abort (the paper's malicious DPF with
//! the authentication layer (A1)–(A5) of "Removing the Selective-Failure
//! Leakage"): every value either party can influence is an authenticated
//! share, so every deviation is an additive error on an opened value, caught
//! by one batched check at the end independently of α and β.
//!
//! Shares are SPDZ bit MACs in GF(2^128) ([`ABit`], MAC key `Δ = Δ_0 ⊕ Δ_1` of
//! [`MacParty`]); F4 products use authenticated triples made without a dealer
//! from malicious-Ferret aBits (leaky triples + bucketing,
//! [`dpf_common::mac::af4`]).
//!
//! **Setup**: malicious base OTs, KOS-checked COTs keyed by `Δ_b` (`lsb(Δ_b) =
//! b`, proven), Ferret, and the persistent payload-MAC key `⟨δ⟩` (128
//! authenticated random bits, never opened).
//!
//! **Preprocessing**: [`mal_products`] authenticated F4 triples and their
//! check; COTs for the input authentication.
//!
//! **Generation** (XOR shares of α and β):
//!
//! 1. Authenticate α, β and each party's root `R_b` (127 random bits above the
//!    control bit b): `⟨st_{0,0}⟩ = ⟨R_0⟩`, `⟨Δ_dpf⟩ = ⟨R_0⟩ ⊕ ⟨R_1⟩` (lsb the
//!    public 1). One round.
//! 2. `⟨α_ℓ·Δ_dpf⟩` for all levels and `⟨δ·β⟩ = Σ_i X^i·β_i⟨δ⟩`: bit-times-block
//!    products, 64 F4 products each (`α·(hω + l) = (αh)ω + αl`). One round.
//! 3. Per level: `⟨L_0⟩, ⟨L_1⟩` by authenticated AES–MMO (40 rounds); one round
//!    opens `CW_ℓ` and the Beaver masks of `α_ℓ·st_{ℓ−1,0}`; the new state is
//!    local.
//! 4. Leaf: `F^pay` and `F^mac` on both leaf seeds (40 rounds), then
//!    `W_CW = W_0 ⊕ W_1 ⊕ β` and `W^MAC_CW = W̃_0 ⊕ W̃_1 ⊕ δβ` are opened.
//! 5. The check of every opening (two rounds); abort on failure.
//!
//! Rounds: `1 + 1 + 41n + 40 + 1 + 2 = 41n + 45`.

use super::key::{low, MalKey};
use crate::{mac_hash, pay_hash, state_hash};
use dpf_common::aes_tower::{mmo_shared, F4Sh, Mmo, Shared128, TowerBackend, PRODUCTS_PER_CALL};
use dpf_common::block::{depth_for, Block};
use dpf_common::coin::Abort;
use dpf_common::mac::af4::{auth_triples, ABit, AuthF4, AuthTriple, OpenChecker};
use dpf_common::mac::binary::MacParty;
use dpf_common::net::{Channel, CommStats};
use dpf_common::ot::FerretConfig;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use std::time::{Duration, Instant};

/// F4 products of one malicious Gen: 2 MMO calls per level, 4 at the leaf,
/// 64 per bit-times-block product (n for α·Δ, n for the branch selection, ℓ
/// for δ·β).
pub fn mal_products(n: usize, bits: usize) -> usize {
    (2 * n + 4) * PRODUCTS_PER_CALL + 64 * (2 * n + bits)
}

/// Deliberate deviation for the abort tests: XOR `err` into this party's
/// share of the word opened at `level` (`n` = the payload word, `n + 1` = the
/// payload-MAC word) before opening it.
#[derive(Clone, Copy, Debug)]
pub struct Fault {
    pub level: usize,
    pub err: Block,
}

/// One party's long-lived state.
pub struct MalSession {
    pub mac: MacParty,
    /// `⟨δ⟩`, the persistent payload-MAC key.
    pub delta_mac: Shared128<ABit>,
    pub setup_stats: CommStats,
    pub setup_time: Duration,
}

impl MalSession {
    pub fn setup(ch: &mut Channel, seed: [u8; 32], ferret: Option<FerretConfig>) -> Result<Self, Abort> {
        let t = Instant::now();
        let before = ch.stats();
        let mut mac = MacParty::setup(ch, seed)?;
        if let Some(cfg) = ferret {
            let mut rng = mac.rng().clone();
            mac.cot.enable_ferret(ch, cfg, &mut rng)?;
            *mac.rng() = rng;
        }
        let r: Vec<bool> = (0..128).map(|_| mac.rng().gen()).collect();
        let d = mac.delta();
        let bits = mac.share_bits(ch, &r)?;
        let delta_mac = std::array::from_fn(|i| ABit::from_bdoz(&bits[i], d));
        ch.sync();
        Ok(MalSession { mac, delta_mac, setup_stats: ch.stats().since(&before), setup_time: t.elapsed() })
    }

    /// This party's share of δ, for [`super::verify`].
    pub fn delta_share(&self) -> Block {
        Block::from_bits(&self.delta_mac.map(|b| b.x))
    }

    /// Preprocessing for one Gen: the authenticated triples (checked here) and
    /// the COTs for the `n + ℓ + 254` input bits.
    pub fn precompute(&mut self, ch: &mut Channel, n: usize, bits: usize) -> Result<Vec<AuthTriple>, Abort> {
        let d = self.mac.delta();
        let mut chk = OpenChecker::new(d);
        let t = auth_triples(ch, &mut self.mac, &mut chk, mal_products(n, bits))?;
        let mut rng = self.mac.rng().clone();
        chk.check(ch, &mut rng)?;
        let m = n + bits + 254;
        self.mac.cot.precompute(ch, m, m, &mut rng)?;
        *self.mac.rng() = rng;
        Ok(t)
    }

    /// One generation, ending with the check of all its openings.
    #[allow(clippy::too_many_arguments)]
    pub fn gen(&mut self, ch: &mut Channel, n_size: u64, bits: usize, alpha_share: u64, beta_share: Block, triples: Vec<AuthTriple>, fault: Option<Fault>) -> Result<(MalKey, usize), Abort> {
        let b = ch.party();
        let n = depth_for(n_size);
        let d = self.mac.delta();
        let err = |lvl: usize| match fault {
            Some(f) if f.level == lvl => f.err,
            _ => Block::ZERO,
        };
        let mut be = AuthF4::new(b, d, triples, OpenChecker::new(d));
        let zero = ABit::default();

        // 1. Inputs: α (n bits), β (ℓ bits), R_0 and R_1 (127 bits each).
        let root = Block::random(self.mac.rng()).with_lsb(b == 1);
        let mut mine: Vec<bool> = (0..n).map(|i| (alpha_share >> (n - 1 - i)) & 1 == 1).collect();
        mine.extend((0..bits).map(|i| beta_share.bit(i)));
        for p in 0..2 {
            mine.extend((1..128).map(|i| p == b && root.bit(i)));
        }
        let inp: Vec<ABit> = self.mac.share_bits(ch, &mine)?.iter().map(|a| ABit::from_bdoz(a, d)).collect();
        let (alpha, rest) = inp.split_at(n);
        let (beta, roots) = rest.split_at(bits);
        let r = |p: usize, i: usize| if i == 0 { zero } else { roots[127 * p + i - 1] };
        let mut st: Shared128<ABit> = std::array::from_fn(|i| r(0, i));
        let delta_dpf: Shared128<ABit> = std::array::from_fn(|i| if i == 0 { be.constant(true) } else { r(0, i) ^ r(1, i) });

        // 2. α_ℓ·Δ_dpf and β_i·δ, in one round.
        let bit_f4 = |x: ABit| F4Sh { h: zero, l: x };
        let pairs = |v: &Shared128<ABit>| -> Vec<F4Sh<ABit>> { (0..64).map(|k| F4Sh { h: v[2 * k + 1], l: v[2 * k] }).collect() };
        let unpair = |p: &[F4Sh<ABit>]| -> Shared128<ABit> { std::array::from_fn(|i| if i % 2 == 1 { p[i / 2].h } else { p[i / 2].l }) };
        let (pd, pm) = (pairs(&delta_dpf), pairs(&self.delta_mac));
        let mut xs = Vec::with_capacity(64 * (n + bits));
        let mut ys = Vec::with_capacity(64 * (n + bits));
        for a in alpha {
            xs.extend(std::iter::repeat(bit_f4(*a)).take(64));
            ys.extend_from_slice(&pd);
        }
        for bi in beta {
            xs.extend(std::iter::repeat(bit_f4(*bi)).take(64));
            ys.extend_from_slice(&pm);
        }
        let (prods, _) = be.mul_and_open(ch, &xs, &ys, &[])?;
        let a_delta: Vec<Shared128<ABit>> = (0..n).map(|i| unpair(&prods[64 * i..64 * (i + 1)])).collect();
        // δβ = Σ_i X^i·(β_i δ), by Horner with the multiplication by X on bits
        // (X^128 = X^7 + X^2 + X + 1).
        let mut db: Shared128<ABit> = [zero; 128];
        for i in (0..bits).rev() {
            let top = db[127];
            let mut s: Shared128<ABit> = std::array::from_fn(|k| if k == 0 { top } else { db[k - 1] });
            for k in [1, 2, 7] {
                s[k] = s[k] ^ top;
            }
            let bd = unpair(&prods[64 * (n + i)..64 * (n + i + 1)]);
            db = std::array::from_fn(|k| s[k] ^ bd[k]);
        }

        // 3. Levels.
        let xor = |a: &Shared128<ABit>, c: &Shared128<ABit>| -> Shared128<ABit> { std::array::from_fn(|i| a[i] ^ c[i]) };
        let fs: &Mmo = state_hash();
        let mut cws = Vec::with_capacity(n);
        for i in 0..n {
            let l = mmo_shared(&mut be, ch, &[(fs, st), (fs, xor(&st, &delta_dpf))]);
            let mut share = xor(&xor(&l[0], &l[1]), &xor(&delta_dpf, &a_delta[i]));
            let e = err(i);
            for (k, s) in share.iter_mut().enumerate() {
                s.x ^= e.bit(k);
            }
            let (p, cwb) = be.mul_and_open(ch, &vec![bit_f4(alpha[i]); 64], &pairs(&st), &share)?;
            let cw = Block::from_bits(&cwb);
            let prod = unpair(&p);
            let t = st[0];
            st = std::array::from_fn(|k| l[0][k] ^ prod[k] ^ t.and_const(cw.bit(k)));
            cws.push(cw);
        }

        // 4. Leaf words.
        let mut s0 = st;
        s0[0] = zero;
        let mut s1 = xor(&st, &delta_dpf);
        s1[0] = zero;
        let (fp, fm): (&Mmo, &Mmo) = (pay_hash(), mac_hash());
        let w = mmo_shared(&mut be, ch, &[(fp, s0), (fp, s1), (fm, s0), (fm, s1)]);
        let mut open: Vec<ABit> = (0..bits).map(|k| w[0][k] ^ w[1][k] ^ beta[k]).collect();
        open.extend((0..128).map(|k| w[2][k] ^ w[3][k] ^ db[k]));
        let (e_pay, e_mac) = (err(n), err(n + 1));
        for (k, s) in open.iter_mut().enumerate() {
            s.x ^= if k < bits { e_pay.bit(k) } else { e_mac.bit(k - bits) };
        }
        let v = be.checker.open(ch, &open)?;
        let w_cw = Block::from_bits(&v[..bits]);
        let wm_cw = Block::from_bits(&v[bits..]);

        // 5. One check for everything opened in this Gen.
        let mut rng = self.mac.rng().clone();
        be.checker.check(ch, &mut rng)?;
        *self.mac.rng() = rng;
        let products = be.products;
        Ok((MalKey { party: b, n_size, bits, root, cws, w_cw: low(w_cw, bits), wm_cw }, products))
    }
}

/// Everything one party gets from [`run_mal`].
pub struct MalRun {
    pub key: MalKey,
    /// This party's share of the payload-MAC key δ.
    pub delta_share: Block,
    pub setup_stats: CommStats,
    pub setup_time: Duration,
    pub pre_stats: CommStats,
    pub pre_time: Duration,
    pub gen_stats: CommStats,
    pub gen_time: Duration,
    pub products: usize,
    /// COTs consumed after setup (aBits of the triples and the inputs).
    pub cots: usize,
}

/// Setup, preprocessing and generation for one party.
#[allow(clippy::too_many_arguments)]
pub fn run_mal(ch: &mut Channel, n_size: u64, bits: usize, alpha_share: u64, beta_share: Block, seed: [u8; 32], ferret: Option<FerretConfig>, fault: Option<Fault>) -> Result<MalRun, Abort> {
    assert!((1..=128).contains(&bits));
    let mut s = MalSession::setup(ch, seed, ferret)?;
    let cots_before = s.mac.cot.produced;
    let n = depth_for(n_size);
    let t_pre = Instant::now();
    let before = ch.stats();
    let triples = s.precompute(ch, n, bits)?;
    let pre_stats = ch.stats().since(&before);
    let pre_time = t_pre.elapsed();
    // Timing only: counted in no phase.
    ch.sync();
    let before = ch.stats();
    let t = Instant::now();
    let (key, products) = s.gen(ch, n_size, bits, alpha_share, beta_share, triples, fault)?;
    Ok(MalRun {
        key,
        delta_share: s.delta_share(),
        setup_stats: s.setup_stats,
        setup_time: s.setup_time,
        pre_stats,
        pre_time,
        gen_stats: ch.stats().since(&before),
        gen_time: t.elapsed(),
        products,
        cots: s.mac.cot.produced - cots_before,
    })
}

/// Trusted-dealer generation for given roots (`lsb(root_b) = b`) and
/// payload-MAC key δ: the cleartext Gen and the oracle of [`MalSession::gen`].
pub fn deal(roots: [Block; 2], n_size: u64, bits: usize, alpha: u64, beta: Block, delta_mac: Block) -> [MalKey; 2] {
    assert!(alpha < n_size);
    assert!(!roots[0].lsb() && roots[1].lsb(), "lsb(root_b) = b");
    assert_eq!(beta, low(beta, bits), "β must fit in the output width");
    let n = depth_for(n_size);
    let delta = roots[0] ^ roots[1];
    let mut st = roots;
    let mut cws = Vec::with_capacity(n);
    for i in 0..n {
        let a = (alpha >> (n - 1 - i)) & 1 == 1;
        let cw = state_hash().h(st[0]) ^ state_hash().h(st[1]) ^ delta.and_bit(!a);
        st = [crate::child(st[0], cw, a), crate::child(st[1], cw, a)];
        cws.push(cw);
    }
    let s = [crate::leaf_seed(st[0]), crate::leaf_seed(st[1])];
    let w_cw = low(pay_hash().h(s[0]) ^ pay_hash().h(s[1]), bits) ^ beta;
    let wm_cw = mac_hash().h(s[0]) ^ mac_hash().h(s[1]) ^ dpf_common::gf128::mul(delta_mac, beta);
    let mk = |party: usize| MalKey { party, n_size, bits, root: roots[party], cws: cws.clone(), w_cw, wm_cw };
    [mk(0), mk(1)]
}

/// Dealer keys from a seed, with the δ shares.
pub fn gen_reference(n_size: u64, bits: usize, alpha: u64, beta: Block, seed: [u8; 32]) -> ([MalKey; 2], [Block; 2]) {
    let mut rng = ChaCha20Rng::from_seed(seed);
    let roots = [Block::random(&mut rng).with_lsb(false), Block::random(&mut rng).with_lsb(true)];
    let d = [Block::random(&mut rng), Block::random(&mut rng)];
    (deal(roots, n_size, bits, alpha, beta, d[0] ^ d[1]), d)
}
