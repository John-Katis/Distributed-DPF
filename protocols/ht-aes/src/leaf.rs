//! The arithmetic leaf and the malicious additions over fields, shared by the
//! semi-honest and the malicious arithmetic variants: payload words in the
//! payload field F (Babybear in the paper) and MAC words in the MAC field `E ⊇
//! F` ([`Ext`], `F_{q^4}` in the paper; E = F in the semi-honest variant).
//!
//! **Preprocessing** ([`fp_pre`], input-independent): daBits `(⟨r⟩, ⟦r⟧)`
//! over F and Beaver triples `(⟦u⟧, ⟦v⟧, ⟦uv⟧)` over E, from COT-based OLEs
//! ([`ole`]): one batch (two rounds) if E = F, one per field otherwise. A
//! daBit is two random bits `r_0, r_1` with `⟦r⟧ = r_0 + r_1 − 2r_0r_1`, the
//! cross term from one OLE per direction; a triple's cross terms `u_0v_1 +
//! u_1v_0` are Gilboa products, one OLE per bit of `u_b`. A triple may take a
//! given v (`fixed`), which gives `⟦u·v⟧` for a random u and a shared v: the
//! mask `(⟦ρ⟧, ⟦δρ⟧)` of Π_Verify. [`vec_triple`] is the triple of the malicious
//! leaf's vector product.
//!
//! **Online**: the semi-honest leaf [`pair_leaf`] (the payload word indexed
//! by server, with one sign product, three rounds); the leaf [`tag_leaf`] of
//! the GGM instance (the payload word indexed by tag, linear in the B2A
//! outputs, two rounds); the malicious leaf [`mal_pair_leaf`] (the payload and
//! the MAC word, both indexed by server, from one vector product, three rounds);
//! and the malicious glue residual [`glue_residual`] (addition (B), two rounds).
//! Every leaf mask coordinate is the integer of κ mask bits, within `2^−40` of
//! uniform (`κ = `[`Field::KAPPA`] of F in the semi-honest leaves and
//! `κ = `[`Field::MAL_KAPPA`] in the malicious one), converted bit by bit by
//! daBits: open `c = h ⊕ r`, then `⟦h⟧ = c + ⟦r⟧ − 2c⟦r⟧`.

use crate::field::{ole, ole_pair, Ext, Field, M127};
use dpf_common::block::{pack_bits, unpack_bits, Block};
use dpf_common::net::{Channel, Lane};
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

/// daBits needed by a leaf for words of `degs[i]` coordinates: κ
/// bits per coordinate, two masks per word, one for the tag.
pub fn leaf_dabits<F: Field>(degs: &[usize]) -> usize {
    2 * degs.iter().sum::<usize>() * F::KAPPA + 1
}

/// daBits of the malicious leaf for a MAC of `deg` coordinates:
/// `2(1 + deg)·κ + 1`, κ = [`Field::MAL_KAPPA`].
pub fn mal_leaf_dabits<F: Field>(deg: usize) -> usize {
    2 * (1 + deg) * F::MAL_KAPPA + 1
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

/// Exchanges `mine` on `lane` and returns the other party's message (lengths equal).
fn swap(ch: &mut Channel, lane: &mut Lane, mine: Vec<u8>) -> Vec<u8> {
    let n = mine.len();
    let theirs = ch.exchange_on(lane, mine);
    assert_eq!(theirs.len(), n, "malformed leaf message");
    theirs
}

/// Reads field elements written with [`Field::put`].
fn elems<E: Field>(b: &[u8]) -> Vec<E> {
    b.chunks(E::BYTES).map(E::get).collect()
}

/// B2A by daBits: opens `c = x ⊕ r` for the bits `x` with the daBits
/// `(r, ⟦r⟧)` and returns the opened c; `⟦x⟧ = c + ⟦r⟧ − 2c⟦r⟧` is [`b2a`].
/// `extra` is appended to the message and the peer's is returned with c.
fn open_masked(ch: &mut Channel, lane: &mut Lane, x: &[bool], dabits: &[(bool, impl Field)], extra: Vec<u8>) -> (Vec<bool>, Vec<u8>) {
    let c_mine: Vec<bool> = x.iter().zip(dabits).map(|(&h, &(r, _))| h ^ r).collect();
    let mut msg = pack_bits(&c_mine);
    let nb = msg.len();
    msg.extend(extra);
    let theirs = swap(ch, lane, msg);
    let c = unpack_bits(&theirs[..nb], x.len()).iter().zip(&c_mine).map(|(&a, &b)| a ^ b).collect();
    (c, theirs[nb..].to_vec())
}

/// `⟦x⟧` from the opened `c = x ⊕ r` and the daBit's `⟦r⟧` (`one` is this
/// party's share of 1).
#[inline]
fn b2a<F: Field>(c: bool, r: F, one: F) -> F {
    if c {
        one.sub(r)
    } else {
        r
    }
}

/// Beaver products `⟦x_i·y_i⟧` over E on `lane`, one round: opens `d = x − u`,
/// `e = y − v`.
fn beaver<E: Field>(ch: &mut Channel, lane: &mut Lane, xy: &[(E, E)], t: &[Triple<E>]) -> Vec<E> {
    let b = ch.party();
    let mut msg = Vec::with_capacity(2 * xy.len() * E::BYTES);
    for (&(x, y), &(u, v, _)) in xy.iter().zip(t) {
        x.sub(u).put(&mut msg);
        y.sub(v).put(&mut msg);
    }
    let theirs = elems::<E>(&swap(ch, lane, msg.clone()));
    let mine = elems::<E>(&msg);
    (0..xy.len())
        .map(|i| {
            let (u, v, w) = t[i];
            let (d, e) = (mine[2 * i].add(theirs[2 * i]), mine[2 * i + 1].add(theirs[2 * i + 1]));
            let s = w.add(e.mul(u)).add(d.mul(v));
            if b == 0 {
                s.add(d.mul(e))
            } else {
                s
            }
        })
        .collect()
}

/// The integer of `kappa` bits read from the opened B2A values starting at
/// `off`, in F (one coordinate of a leaf mask).
fn coord<F: Field>(vals: &[F], off: usize, kappa: usize) -> F {
    (0..kappa).fold(F::ZERO, |a, k| a.add(F::pow2_wide(k).mul(vals[off + k])))
}

/// One call of the vector `𝓕_Mul`: Beaver shares `(u, v_0, v_1, w_0, w_1)` with
/// `w_i = u·v_i` across the parties, `u, v_0, w_0 ∈ F` and `v_1, w_1 ∈ E`.
#[derive(Clone, Copy, Debug)]
pub struct VecTriple<F, E> {
    pub u: F,
    pub v0: F,
    pub v1: E,
    pub w0: F,
    pub w1: E,
}

/// COTs per direction that [`vec_triple`] consumes: one per bit of u.
pub fn vec_triple_cots<F: Field>() -> usize {
    F::P_BITS
}

/// One [`VecTriple`]: Gilboa products of the bits of `u_b` with `(v_0, v_1)`,
/// both components on the same COTs ([`ole_pair`]). Two rounds.
pub fn vec_triple<F: Field, E: Ext<F>, R: RngCore + CryptoRng>(ch: &mut Channel, cot: &mut CotPair, rng: &mut R) -> VecTriple<F, E> {
    let (u, v0, v1) = (F::random(rng), F::random(rng), E::random(rng));
    let ui = u.to_u128();
    let g: Vec<bool> = (0..F::P_BITS).map(|k| (ui >> k) & 1 == 1).collect();
    let cf: Vec<F> = (0..F::P_BITS).map(|k| v0.mul(F::pow2(k))).collect();
    let ce: Vec<E> = (0..F::P_BITS).map(|k| v1.mul(E::embed(F::pow2(k)))).collect();
    let (zf, ze) = ole_pair(ch, cot, &g, &cf, &ce, rng);
    let w0 = zf.iter().fold(u.mul(v0), |a, &x| a.add(x));
    let w1 = ze.iter().fold(E::embed(u).mul(v1), |a, &x| a.add(x));
    VecTriple { u, v0, v1, w0, w1 }
}

/// Addition (A) of Figure `Π_GenMal`, the leaf words: `(W_CW, W^MAC_CW) =
/// 𝓕_Mul(1 − 2⟦σ⟧, (W_0 − W_1 − β, W̃_0 − W̃_1 − β·⟦δ⟧))`, one vector product,
/// for the τ-block leaf hashes `h = [h^(0), h^(1)]` of the two servers (XOR
/// shares), this party's share `t` of `σ = r_n`, the public β and this party's
/// share of δ. As [`pair_leaf`], on `lane`, three rounds: the masked bits of the
/// [`mal_leaf_dabits`]`(E::DEG)` daBits with `d = ρ − u` (`ρ = 1 − 2r`, r the
/// tag's daBit); `e_i = V_i − v_i`; then `X = ρ·V`, and `(W_CW, W^MAC_CW) = (1 −
/// 2c)·X`. `err` is added to this party's shares of X (a deliberate deviation).
#[allow(clippy::too_many_arguments)]
pub fn mal_pair_leaf<F: Field, E: Ext<F>>(
    ch: &mut Channel,
    lane: &mut Lane,
    h: [&[Block]; 2],
    t: bool,
    beta: F,
    delta_mac: E,
    dabits: &[(bool, F)],
    triple: VecTriple<F, E>,
    err: (F, E),
) -> (F, E) {
    let b = ch.party();
    let (kappa, deg) = (F::MAL_KAPPA, E::DEG);
    let nbits = mal_leaf_dabits::<F>(deg);
    assert_eq!(dabits.len(), nbits, "the leaf's daBits");
    let one = if b == 0 { F::ONE } else { F::ZERO };
    let r_t = dabits[nbits - 1].1;
    let bit = |w: &[Block], i: usize| w[i / 128].bit(i % 128);
    let VecTriple { u, v0, v1, w0, w1 } = triple;

    // Round 1: the masked bits [W(h^(0)), W(h^(1)), F^mac(h^(0)), F^mac(h^(1)), t] and d.
    let mut bits: Vec<bool> = h.iter().flat_map(|w| (0..kappa).map(move |k| bit(w, k))).collect();
    bits.extend(h.iter().flat_map(|w| (kappa..(deg + 1) * kappa).map(move |k| bit(w, k))));
    bits.push(t);
    let d_mine = one.sub(r_t.add(r_t)).sub(u);
    let mut extra = Vec::new();
    d_mine.put(&mut extra);
    let (c, theirs) = open_masked(ch, lane, &bits, dabits, extra);
    let d = d_mine.add(F::get(&theirs));
    let vals: Vec<F> = c.iter().zip(dabits).map(|(&ci, &(_, r))| b2a(ci, r, one)).collect();
    let mac_val = |off: usize| E::from_coords(&(0..deg).map(|i| coord(&vals, off + i * kappa, kappa)).collect::<Vec<F>>());
    let v_share = coord(&vals, 0, kappa).sub(coord(&vals, kappa, kappa)).sub(one.mul(beta));
    let v_mac = mac_val(2 * kappa).sub(mac_val(2 * kappa + deg * kappa)).sub(E::embed(beta).mul(delta_mac));

    // Round 2: e = V − v.
    let (e0_mine, e1_mine) = (v_share.sub(v0), v_mac.sub(v1));
    let mut msg = Vec::with_capacity(F::BYTES + E::BYTES);
    e0_mine.put(&mut msg);
    e1_mine.put(&mut msg);
    let theirs = swap(ch, lane, msg);
    let e0 = e0_mine.add(F::get(&theirs));
    let e1 = e1_mine.add(E::get(&theirs[F::BYTES..]));

    // Round 3: X = ρ·V; (W_CW, W^MAC_CW) = (1 − 2c)·X.
    let (ue, de) = (E::embed(u), E::embed(d));
    let (mut x0, mut x1) = (w0.add(e0.mul(u)).add(d.mul(v0)), w1.add(e1.mul(ue)).add(de.mul(v1)));
    if b == 0 {
        x0 = x0.add(d.mul(e0));
        x1 = x1.add(de.mul(e1));
    }
    x0 = x0.add(err.0);
    x1 = x1.add(err.1);
    let mut msg = Vec::with_capacity(F::BYTES + E::BYTES);
    x0.put(&mut msg);
    x1.put(&mut msg);
    let theirs = swap(ch, lane, msg);
    let (x0, x1) = (x0.add(F::get(&theirs)), x1.add(E::get(&theirs[F::BYTES..])));
    if c[nbits - 1] {
        (x0.neg(), x1.neg())
    } else {
        (x0, x1)
    }
}

/// daBits of the glue residual: `2(λ − 2)`, the bits of I in `a` and in `a ⊕ Δ`.
pub const RESIDUAL_DABITS: usize = 2 * RESIDUAL_BITS;

/// `|I|`: the bit positions read by `int`.
const RESIDUAL_BITS: usize = 126;

/// `int(x) = Σ_{k∈I} 2^{j_k}·x_k` for `I = {1, …, 126}`: the state's bits as
/// they are, without the tag (bit 0) and bit 127.
#[inline]
fn int_of(x: Block) -> M127 {
    M127((x.0 >> 1) & ((1u128 << RESIDUAL_BITS) - 1))
}

/// Addition (B) of Figure `Π_GenMal`, the glue residual over `𝔽' = F_{2^127−1}`:
/// from this party's share `a` of the glue output `st_{ν,0}`, its share of Δ and
/// its level-ν frontier, on `lane`, two rounds: B2A of the bits of I in `a` and
/// `a ⊕ Δ` with the [`RESIDUAL_DABITS`] daBits, then `𝓕_Mul(v, v)` and `𝓕_Mul(v',
/// v')` with `t`. Returns this party's share of `ω = (G_0 − G_1) − v² + v'²`,
/// `G_b = Σ_x ψ(st_b(x))`, `ψ = int²`, which is zero in an honest run and is
/// checked by Π_Verify, not opened.
pub fn glue_residual(ch: &mut Channel, lane: &mut Lane, a: Block, delta: Block, frontier: &[Block], dabits: &[(bool, M127)], t: &[Triple<M127>]) -> M127 {
    let b = ch.party();
    assert!(dabits.len() == RESIDUAL_DABITS && t.len() == 2, "the residual's correlations");
    let one = if b == 0 { M127::ONE } else { M127::ZERO };
    let bits: Vec<bool> = [a, a ^ delta].iter().flat_map(|x| (1..=RESIDUAL_BITS).map(move |k| x.bit(k))).collect();
    let (c, _) = open_masked(ch, lane, &bits, dabits, Vec::new());
    let vals: Vec<M127> = c.iter().zip(dabits).map(|(&ci, &(_, r))| b2a(ci, r, one)).collect();
    let weigh = |off: usize| (0..RESIDUAL_BITS).fold(M127::ZERO, |acc, k| acc.add(M127::pow2(k).mul(vals[off + k])));
    let (v, v2) = (weigh(0), weigh(RESIDUAL_BITS));
    let sq = beaver(ch, lane, &[(v, v), (v2, v2)], t);
    let g = frontier.iter().fold(M127::ZERO, |acc, &x| {
        let i = int_of(x);
        acc.add(i.mul(i))
    });
    let g = if b == 0 { g } else { g.neg() };
    g.sub(sq[0]).add(sq[1])
}

/// The leaf of the semi-honest Gen (Figure `Π_Bottom`), indexed by server:
/// `W_CW = 𝓕_Mul(1 − 2⟦σ⟧, ⟦W_0⟧ − ⟦W_1⟧ − β)` for the XOR-shared hashes `h =
/// [h^(0), h^(1)]` of `X^0_n`, `X^1_n`, this party's share `t` of `σ = r_n` and
/// the public β. On `lane`, three rounds: the masked bits of the
/// [`leaf_dabits`]`(&[1])` daBits with the Beaver mask `d = ρ − u` of the sign
/// (`ρ = 1 − 2r`, r the tag's daBit); `e = V − v` for `V = W_0 − W_1 − β`; then
/// `X = ρ·V`, and `W_CW = (1 − 2c)·X` since `1 − 2σ = (1 − 2c)(1 − 2r)`.
/// Consumes the daBits and one triple of `pre`.
pub fn pair_leaf<F: Field>(ch: &mut Channel, lane: &mut Lane, h: [Block; 2], t: bool, pre: &mut FpPre<F, F>, beta: F) -> F {
    let b = ch.party();
    let kappa = F::KAPPA;
    let nbits = leaf_dabits::<F>(&[1]);
    let dabits: Vec<(bool, F)> = pre.dabits.drain(..nbits).collect();
    let (u, v, w) = pre.triples.remove(0);
    let one = if b == 0 { F::ONE } else { F::ZERO };
    let r_t = dabits[nbits - 1].1;

    // Round 1: the masked bits [h^(0), h^(1), t] and d = ρ − u.
    let mut bits: Vec<bool> = h.iter().flat_map(|w| (0..kappa).map(move |k| w.bit(k))).collect();
    bits.push(t);
    let d_mine = one.sub(r_t.add(r_t)).sub(u);
    let mut extra = Vec::new();
    d_mine.put(&mut extra);
    let (c, theirs) = open_masked(ch, lane, &bits, &dabits, extra);
    let d = d_mine.add(F::get(&theirs));
    let vals: Vec<F> = c.iter().zip(&dabits).map(|(&ci, &(_, r))| b2a(ci, r, one)).collect();
    let v_share = coord(&vals, 0, kappa).sub(coord(&vals, kappa, kappa)).sub(one.mul(beta));

    // Round 2: e = V − v.
    let e_mine = v_share.sub(v);
    let mut msg = Vec::with_capacity(F::BYTES);
    e_mine.put(&mut msg);
    let e = e_mine.add(F::get(&swap(ch, lane, msg)));

    // Round 3: X = ρ·V; W_CW = (1 − 2c)·X.
    let mut x_mine = w.add(e.mul(u)).add(d.mul(v));
    if b == 0 {
        x_mine = x_mine.add(d.mul(e));
    }
    let mut msg = Vec::with_capacity(F::BYTES);
    x_mine.put(&mut msg);
    let x = x_mine.add(F::get(&swap(ch, lane, msg)));
    if c[nbits - 1] {
        x.neg()
    } else {
        x
    }
}

/// The leaf of the GGM instance's Gen (`protocols/ggm-lpn`), indexed by tag: for
/// the XOR-shared mask blocks `h = [h^(0), h^(1)]` of the on-path leaf states
/// with tags 0 and 1, this party's share `t` of `t_{n,0}` and the public β,
/// `W_CW = W^(0) − W^(1) − (1 − 2σ)·β` with `W^(c)` the integer of the low κ
/// bits of `h^(c)` and `σ = t_{n,0}` over F, which is linear in the B2A
/// outputs. On `lane`, two rounds: the masked bits `c = h ⊕ r` of the 2κ + 1
/// daBits ([`leaf_dabits`]`(&[1])`), then the shares of `W_CW`.
pub fn tag_leaf<F: Field>(ch: &mut Channel, lane: &mut Lane, h: [Block; 2], t: bool, dabits: &[(bool, F)], beta: F) -> F {
    let b = ch.party();
    let kappa = F::KAPPA;
    let nbits = 2 * kappa + 1;
    assert_eq!(dabits.len(), nbits, "2κ + 1 daBits");
    let bits: Vec<bool> = h.iter().flat_map(|w| (0..kappa).map(move |k| w.bit(k))).chain([t]).collect();
    let c_mine: Vec<bool> = bits.iter().zip(dabits).map(|(&x, &(r, _))| x ^ r).collect();
    let theirs = ch.exchange_on(lane, dpf_common::block::pack_bits(&c_mine));
    let c = dpf_common::block::unpack_bits(&theirs, nbits);
    let one = if b == 0 { F::ONE } else { F::ZERO };
    // B2A: ⟦x⟧ = c + ⟦r⟧ − 2c⟦r⟧.
    let b2a = |i: usize| if c_mine[i] ^ c[i] { one.sub(dabits[i].1) } else { dabits[i].1 };
    let word = |off: usize| (0..kappa).fold(F::ZERO, |a, k| a.add(F::pow2(k).mul(b2a(off + k))));
    let sigma = b2a(2 * kappa);
    let share = word(0).sub(word(kappa)).sub(one.sub(sigma.add(sigma)).mul(beta));
    let mut msg = Vec::with_capacity(F::BYTES);
    share.put(&mut msg);
    let theirs = ch.exchange_on(lane, msg);
    assert_eq!(theirs.len(), F::BYTES, "malformed leaf message");
    share.add(F::get(&theirs))
}
