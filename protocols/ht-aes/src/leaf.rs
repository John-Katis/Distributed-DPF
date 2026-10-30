//! The arithmetic leaf of Figure "DPF.Gen", shared by the semi-honest and the
//! malicious arithmetic variants: payload words in the payload field F
//! (Babybear in the paper) and MAC words in the MAC field `E ⊇ F` ([`Ext`],
//! `F_{q^4}` in the paper; E = F in the semi-honest variant).
//!
//! **Preprocessing** ([`fp_pre`], input-independent): daBits `(⟨r⟩, ⟦r⟧)`
//! over F and Beaver triples `(⟦u⟧, ⟦v⟧, ⟦uv⟧)` over E, from COT-based OLEs
//! ([`ole`]): one batch (two rounds) if E = F, one per field otherwise. A
//! daBit is two random bits `r_0, r_1` with `⟦r⟧ = r_0 + r_1 − 2r_0r_1`, the
//! cross term from one OLE per direction; a triple's cross terms `u_0v_1 +
//! u_1v_0` are Gilboa products, one OLE per bit of `u_b`. A triple may take a
//! given v (`fixed`), which gives `⟦u·v⟧` for a random u and a shared v: the
//! mask `(⟦r⟧, ⟦δr⟧)` of Π_Verify.
//!
//! **Online** ([`arith_leaf`]), for words `V_i = W_{i,0} − W_{i,1} − S_i` with
//! `W_{i,j}` an XOR-shared leaf mask of `d_i` coordinates, each the integer
//! of κ mask bits (`κ = `[`Field::KAPPA`] of F, within `2^−40` of uniform),
//! and `S_i` a known share or a product of shares:
//!
//! 1. Open `c_k = h_k ⊕ r_k` for every mask bit (B2A by daBits:
//!    `⟦h⟧ = c + ⟦r⟧ − 2c⟦r⟧`), `c = t_{n,0} ⊕ r` for the tag's daBit, the
//!    Beaver mask `d_i = ρ − u_i` of each sign product (`ρ = 1 − 2r`), and
//!    the masks of the products in `S_i`.
//! 2. Open `e_i = V_i − v_i`.
//! 3. Open `X_i = ρ·V_i`, with the AES key shares; then `W_CW,i = (1 −
//!    2c)·X_i`, since `1 − 2t = (1 − 2c)(1 − 2r)`.
//!
//! Three rounds after the leaf PRF calls.

use crate::field::{ole, Ext, Field};
use dpf_common::block::Block;
use dpf_common::net::Channel;
use dpf_common::ot::CotPair;
use rand::{CryptoRng, Rng, RngCore};

/// A Beaver triple's shares `(u, v, w)`, `w = uv` across the parties.
pub type Triple<E> = (E, E, E);

/// Preprocessed daBits `(r_b, ⟦r⟧_b)` over F and Beaver triples over E.
pub struct FpPre<F: Field, E: Ext<F>> {
    pub dabits: Vec<(bool, F)>,
    pub triples: Vec<Triple<E>>,
}

/// COTs per direction that [`fp_pre`] consumes.
pub fn fp_pre_cots<F: Field, E: Ext<F>>(dabits: usize, triples: usize) -> usize {
    dabits + triples * E::P_BITS
}

/// daBits needed by [`arith_leaf`] for words of `degs[i]` coordinates: κ
/// bits per coordinate, two masks per word, one for the tag.
pub fn leaf_dabits<F: Field>(degs: &[usize]) -> usize {
    2 * degs.iter().sum::<usize>() * F::KAPPA + 1
}

/// Gilboa inputs of triples: `(g, c)` with g the bits of `u` and `c = v·2^k`.
fn gilboa<E: Field>(uv: &[(E, E)], g: &mut Vec<bool>, c: &mut Vec<E>) {
    for &(u, v) in uv {
        let ui = u.to_u128();
        for k in 0..E::P_BITS {
            g.push((ui >> k) & 1 == 1);
            c.push(v.mul(E::pow2(k)));
        }
    }
}

/// `w = uv + Σ cross` for each triple from its OLE outputs `z`.
fn triples_from<E: Field>(uv: &[(E, E)], z: &[E]) -> Vec<Triple<E>> {
    uv.iter()
        .enumerate()
        .map(|(j, &(u, v))| {
            let cross = z[j * E::P_BITS..(j + 1) * E::P_BITS].iter().fold(E::ZERO, |a, &x| a.add(x));
            (u, v, u.mul(v).add(cross))
        })
        .collect()
}

/// `dabits` daBits over F and `triples` Beaver triples over E; the first
/// `fixed.len()` triples take `v = fixed[j]` (this party's share of a given
/// value) instead of a random v.
pub fn fp_pre<F: Field, E: Ext<F>, R: RngCore + CryptoRng>(
    ch: &mut Channel,
    cot: &mut CotPair,
    dabits: usize,
    triples: usize,
    fixed: &[E],
    rng: &mut R,
) -> FpPre<F, E> {
    assert!(fixed.len() <= triples);
    let r: Vec<bool> = (0..dabits).map(|_| rng.gen()).collect();
    let uv: Vec<(E, E)> = (0..triples).map(|j| (E::random(rng), if j < fixed.len() { fixed[j] } else { E::random(rng) })).collect();
    // z_0 + z_1 = 2·r_0·r_1, so r_b − z_b shares r_0 ⊕ r_1.
    let (dabits, triples) = if E::DEG == 1 {
        // One OLE batch over E = F.
        let mut g = r.clone();
        let mut c: Vec<E> = r.iter().map(|&x| if x { E::ONE } else { E::ZERO }).collect();
        gilboa(&uv, &mut g, &mut c);
        let z = ole(ch, cot, &g, &c, rng);
        let d = (0..dabits).map(|i| (r[i], c[i].sub(z[i]).coord(0))).collect();
        (d, triples_from(&uv, &z[dabits..]))
    } else {
        let c: Vec<F> = r.iter().map(|&x| if x { F::ONE } else { F::ZERO }).collect();
        let z = ole(ch, cot, &r, &c, rng);
        let d = (0..dabits).map(|i| (r[i], c[i].sub(z[i]))).collect();
        let (mut g, mut c) = (Vec::new(), Vec::new());
        gilboa(&uv, &mut g, &mut c);
        let z = ole(ch, cot, &g, &c, rng);
        (d, triples_from(&uv, &z))
    };
    FpPre { dabits, triples }
}

/// The term `S_i` subtracted in `V_i`: a share this party knows, or the
/// product of two shared values (computed with a triple in round 1).
#[derive(Clone, Copy, Debug)]
pub enum Sub<E: Field> {
    Share(E),
    Product(E, E),
}

/// Exchanges `mine` and returns the other party's message (lengths equal).
fn swap(ch: &mut Channel, mine: Vec<u8>) -> Vec<u8> {
    let n = mine.len();
    ch.send(mine);
    let theirs = ch.recv();
    assert_eq!(theirs.len(), n, "malformed leaf message");
    theirs
}

/// Reads field elements written with [`Field::put`].
fn elems<E: Field>(b: &[u8]) -> Vec<E> {
    b.chunks(E::BYTES).map(E::get).collect()
}

/// The words `W_CW,i = (1 − 2t)·(W_{i,0} − W_{i,1} − S_i)` for the XOR-shared
/// mask blocks `masks[i] = [W_{i,0}, W_{i,1}]` of `degs[i]` coordinates each
/// (κ bits per coordinate, read across the blocks), this party's share `t`
/// of the tag `t_{n,0}`, and `subs[i]`. `err[i]` is added to this party's
/// share of `X_i` before it is opened (a deliberate deviation, for the abort
/// tests). `tail` rides with the last message (the AES key shares) and the
/// other party's tail, of the same length, is returned with the words.
/// Consumes [`leaf_dabits`]`(degs)` daBits and one triple per word and per
/// product.
#[allow(clippy::too_many_arguments)]
pub fn arith_leaf<F: Field, E: Ext<F>>(
    ch: &mut Channel,
    masks: &[[Vec<Block>; 2]],
    degs: &[usize],
    subs: &[Sub<E>],
    t: bool,
    pre: &mut FpPre<F, E>,
    err: &[E],
    tail: &[u8],
) -> (Vec<E>, Vec<u8>) {
    let b = ch.party();
    let words = masks.len();
    assert!(subs.len() == words && err.len() == words && degs.len() == words);
    assert!(degs.iter().all(|&d| (1..=E::DEG).contains(&d)));
    let kappa = F::KAPPA;
    let nbits = leaf_dabits::<F>(degs);
    let dabits: Vec<(bool, F)> = pre.dabits.drain(..nbits).collect();
    let sign: Vec<Triple<E>> = pre.triples.drain(..words).collect();
    let prods: Vec<(E, E)> = subs.iter().filter_map(|s| if let Sub::Product(x, y) = s { Some((*x, *y)) } else { None }).collect();
    let prod_t: Vec<Triple<E>> = pre.triples.drain(..prods.len()).collect();
    let one = if b == 0 { F::ONE } else { F::ZERO };
    let r_tp = dabits[nbits - 1].1;
    let rho = E::embed(one.sub(r_tp.add(r_tp)));

    // Round 1: masked bits, c, the sign masks d_i and the product masks.
    let mut bits: Vec<bool> = Vec::with_capacity(nbits);
    for (m, &d) in masks.iter().zip(degs) {
        for w in m {
            bits.extend((0..d * kappa).map(|k| w[k / 128].bit(k % 128)));
        }
    }
    bits.push(t);
    let c_mine: Vec<bool> = bits.iter().zip(&dabits).map(|(&h, &(r, _))| h ^ r).collect();
    let mut msg: Vec<u8> = c_mine.chunks(8).map(|ch8| ch8.iter().enumerate().fold(0u8, |a, (i, &x)| a | ((x as u8) << i))).collect();
    let d_mine: Vec<E> = sign.iter().map(|&(u, _, _)| rho.sub(u)).collect();
    d_mine.iter().for_each(|x| x.put(&mut msg));
    let de_mine: Vec<(E, E)> = prods.iter().zip(&prod_t).map(|(&(x, y), &(u, v, _))| (x.sub(u), y.sub(v))).collect();
    de_mine.iter().for_each(|(d, e)| {
        d.put(&mut msg);
        e.put(&mut msg);
    });
    let theirs = swap(ch, msg);
    let nb = nbits.div_ceil(8);
    let c: Vec<bool> = (0..nbits).map(|i| c_mine[i] ^ ((theirs[i / 8] >> (i % 8)) & 1 == 1)).collect();
    let rest = elems::<E>(&theirs[nb..]);
    let d: Vec<E> = d_mine.iter().zip(&rest[..words]).map(|(a, x)| a.add(*x)).collect();
    // Products by Beaver: ⟦xy⟧ = w + e·u + d·v (+ d·e at party 0).
    let mut prod_vals = Vec::with_capacity(prods.len());
    for (i, ((dm, em), &(u, v, w))) in de_mine.iter().zip(&prod_t).enumerate() {
        let (dd, ee) = (dm.add(rest[words + 2 * i]), em.add(rest[words + 2 * i + 1]));
        let mut s = w.add(ee.mul(u)).add(dd.mul(v));
        if b == 0 {
            s = s.add(dd.mul(ee));
        }
        prod_vals.push(s);
    }
    // B2A: ⟦h⟧ = c + ⟦r⟧ − 2c⟦r⟧, then each coordinate Σ 2^k ⟦h_k⟧.
    let b2a = |i: usize| {
        let (ci, (_, r)) = (c[i], dabits[i]);
        if ci {
            one.sub(r)
        } else {
            r
        }
    };
    let pow2: Vec<F> = (0..kappa).map(F::pow2).collect();
    let coord = |off: usize| (0..kappa).fold(F::ZERO, |a, k| a.add(pow2[k].mul(b2a(off + k))));
    let mut off = 0;
    let mut mask_val = |d: usize| {
        let cs: Vec<F> = (0..E::DEG).map(|i| if i < d { coord(off + i * kappa) } else { F::ZERO }).collect();
        off += d * kappa;
        E::from_coords(&cs)
    };
    let mut pi = 0;
    let v: Vec<E> = (0..words)
        .map(|i| {
            let s = match subs[i] {
                Sub::Share(s) => s,
                Sub::Product(..) => {
                    pi += 1;
                    prod_vals[pi - 1]
                }
            };
            let (w0, w1) = (mask_val(degs[i]), mask_val(degs[i]));
            w0.sub(w1).sub(s)
        })
        .collect();

    // Round 2: e_i = V_i − v_i.
    let e_mine: Vec<E> = v.iter().zip(&sign).map(|(x, &(_, vv, _))| x.sub(vv)).collect();
    let mut msg = Vec::with_capacity(words * E::BYTES);
    e_mine.iter().for_each(|x| x.put(&mut msg));
    let theirs = elems::<E>(&swap(ch, msg));
    let e: Vec<E> = e_mine.iter().zip(&theirs).map(|(a, x)| a.add(*x)).collect();

    // Round 3: X_i = ρ·V_i, opened with the tail; W_CW = (1 − 2c)·X.
    let x_mine: Vec<E> = (0..words)
        .map(|i| {
            let (u, vv, w) = sign[i];
            let mut s = w.add(e[i].mul(u)).add(d[i].mul(vv));
            if b == 0 {
                s = s.add(d[i].mul(e[i]));
            }
            s.add(err[i])
        })
        .collect();
    let mut msg = Vec::with_capacity(words * E::BYTES + tail.len());
    x_mine.iter().for_each(|x| x.put(&mut msg));
    msg.extend_from_slice(tail);
    let mut theirs = swap(ch, msg);
    let their_tail = theirs.split_off(words * E::BYTES);
    let theirs = elems::<E>(&theirs);
    let c_t = c[nbits - 1];
    let ws = x_mine
        .iter()
        .zip(&theirs)
        .map(|(a, x)| {
            let xv = a.add(*x);
            if c_t {
                xv.neg()
            } else {
                xv
            }
        })
        .collect();
    (ws, their_tail)
}
