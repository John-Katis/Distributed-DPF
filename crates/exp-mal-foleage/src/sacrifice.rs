//! Approach (b): authenticate c with aBits, then sacrifice with bucketing.
//!
//! After a mode-[`Linear`](crate::pcg::Mode::Linear) expansion, a and b carry
//! MACs from the PCG and c is a plain XOR sharing. With random aBits `⟨r⟩`
//! (malicious-Ferret COTs, BDOZ → SPDZ) the parties open `d = c ⊕ r` and set
//! `⟨c⟩ = ⟨r⟩ ⊕ d`. A cheater can only shift its share of d, i.e. make
//! `c' = ab + e_c` with `e_c` chosen without any honest information, so the
//! checks below abort independently of the honest values (given well-formed
//! seeds).
//!
//! Sacrifice (SPDZ): for a triple `(a, b, c)` and a second one `(f, g, h)`,
//! with a public `t ∈ F4^*`, open `ρ = t·a + f`, `σ = b + g`, then open
//! `w = t·c + h + σ·f + ρ·g + ρσ`, which is 0 for correct triples. If exactly
//! one of the two is wrong, `w ≠ 0` always (t ≠ 0); if both are, w = 0 for one
//! of the three t. Buckets of B: a coin-tossed permutation, the first triple
//! of each bucket checked against the B − 1 others and kept. [`bucket_size`]:
//! the smallest B with `(B − 1)(log₂ N + log₂ 3) ≥ ρ = 40`.

use dpf_common::aes_tower::F4Sh;
use dpf_common::block::{pack_bits, unpack_bits, Block};
use dpf_common::coin::{coin_block, Abort};
use dpf_common::f4;
use dpf_common::hash::CtrPrg;
use dpf_common::mac::af4::{ABit, AuthTriple, OpenChecker};
use dpf_common::mac::binary::{AuthBit, MacParty};
use dpf_common::net::Channel;
use dpf_common::ot::RandomCots;
use rand::seq::SliceRandom;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

use crate::pcg::Raw;

/// Statistical security of the bucketing.
pub const RHO: f64 = 40.0;

/// Bucket size for `n` output triples.
pub fn bucket_size(n: usize) -> usize {
    let per = (n.max(2) as f64).log2() + 3f64.log2();
    1 + (RHO / per).ceil() as usize
}

/// Deliberate deviation for the tests: flip this party's share of `d` for
/// triple `index`.
#[derive(Clone, Copy, Debug)]
pub struct Cheat {
    pub index: usize,
}

/// `n` authenticated triples from `bucket_size(n)·n` PCG triples. All
/// openings are checked before returning.
pub fn authenticate_and_sacrifice(ch: &mut Channel, mac: &mut MacParty, raw: &Raw, n: usize, cheat: Option<Cheat>) -> Result<Vec<AuthTriple>, Abort> {
    let bkt = bucket_size(n);
    let total = bkt * n;
    assert!(total <= raw.len(), "PCG instance too small: {} triples for {n} × {bkt}", raw.len());
    let me = ch.party();
    let delta = mac.delta();
    let mut rng = mac.rng().clone();

    // Random aBits r for the 2 bits of every c.
    let nb = 2 * total;
    let (mut bits, mut keys) = (Vec::new(), Vec::new());
    for s in 0..2 {
        match mac.cot.random_cots(ch, s, nb, &mut rng)? {
            RandomCots::Sender(k) => keys = k,
            RandomCots::Receiver(r, m) => bits = r.into_iter().zip(m).collect(),
        }
    }
    let r: Vec<ABit> = (0..nb).map(|j| ABit::from_bdoz(&AuthBit { x: bits[j].0, m: bits[j].1, k: keys[j] }, delta)).collect();

    // d = c ⊕ r, ⟨c⟩ = ⟨r⟩ ⊕ d.
    let mut d: Vec<bool> = (0..total).flat_map(|k| [raw.c[k] & 2 == 2, raw.c[k] & 1 == 1]).zip(&r).map(|(c, r)| c ^ r.x).collect();
    if let Some(c) = cheat {
        d[2 * c.index] ^= true;
    }
    ch.send(pack_bits(&d));
    let theirs = ch.recv();
    if theirs.len() != nb.div_ceil(8) {
        return Err(Abort("malformed opening"));
    }
    let dd: Vec<bool> = d.iter().zip(unpack_bits(&theirs, nb)).map(|(a, b)| a ^ b).collect();
    let cst = |v: bool| ABit::constant(v, me, delta);
    let mut ts: Vec<AuthTriple> = (0..total)
        .map(|k| AuthTriple {
            a: Raw::auth(&raw.a, &raw.ma, k),
            b: Raw::auth(&raw.b, &raw.mb, k),
            c: F4Sh { h: r[2 * k] ^ cst(dd[2 * k]), l: r[2 * k + 1] ^ cst(dd[2 * k + 1]) },
        })
        .collect();

    // Permutation and challenges from one coin.
    let seed = coin_block(ch, &mut rng)?;
    let mut perm = ChaCha20Rng::from_seed(std::array::from_fn(|i| seed.to_bytes()[i % 16] ^ (i / 16) as u8));
    ts.shuffle(&mut perm);
    let chal = CtrPrg::new(seed ^ Block(1)).next_words(n.div_ceil(64) * (bkt - 1) + 1);
    let t_of = |i: usize| (chal[i / 64] >> (2 * (i % 64)) & 3) as u8 % 3 + 1;
    let constf = |c: u8| F4Sh { h: cst(c & 2 == 2), l: cst(c & 1 == 1) };

    let mut chk = OpenChecker::new(delta);
    let mut open1 = Vec::with_capacity(8 * n * (bkt - 1));
    for q in 0..n {
        let first = ts[q * bkt];
        for k in 1..bkt {
            let o = ts[q * bkt + k];
            let t = t_of(q * (bkt - 1) + k - 1);
            let (rho, sig) = (first.a.scale(t).add(o.a), first.b.add(o.b));
            open1.extend([rho.h, rho.l, sig.h, sig.l]);
        }
    }
    let v = chk.open(ch, &open1)?;
    let f4v = |j: usize| (v[j] as u8) << 1 | v[j + 1] as u8;
    let mut open2 = Vec::with_capacity(2 * n * (bkt - 1));
    for q in 0..n {
        let first = ts[q * bkt];
        for k in 1..bkt {
            let idx = q * (bkt - 1) + k - 1;
            let o = ts[q * bkt + k];
            let t = t_of(idx);
            let (rho, sig) = (f4v(4 * idx), f4v(4 * idx + 2));
            let w = first.c.scale(t).add(o.c).add(o.a.scale(sig)).add(o.b.scale(rho)).add(constf(f4::mul(rho, sig)));
            open2.extend([w.h, w.l]);
        }
    }
    let w = chk.open(ch, &open2)?;
    chk.check(ch, &mut rng)?;
    *mac.rng() = rng;
    if w.iter().any(|&b| b) {
        return Err(Abort("sacrifice check failed"));
    }
    Ok((0..n).map(|q| ts[q * bkt]).collect())
}
