//! The authenticated triple PCG over `R = F4[X_1..X_N]/(X_i³ − 1)`, dealer
//! seeded.
//!
//! Each party σ has two regular noise vectors, `e_σ` (for `x_σ = ⟨a, ê_σ⟩`) and
//! `f_σ` (for `y_σ = ⟨a, f̂_σ⟩`), and the triple at coordinate k is
//!
//! ```text
//! a = x_0 + x_1,  b = y_0 + y_1,  c = a·b = x_0y_0 + x_1y_1 + x_0y_1 + x_1y_0.
//! ```
//!
//! `x_σ y_σ` is local; the cross terms come from `2c²t²` F4-valued DPFs, as two
//! FOLEAGE OLE instances. On top, with MAC key `Δ = Δ_0 ⊕ Δ_1` and `Γ = √Δ`
//! ([`crate::gf`]):
//!
//! * **linear MACs** (both modes): shares of `ι(a)K`, `ι(b)K` for `K ∈ {Δ, Γ}`.
//!   `ι(x_σ)K_σ` is local; the cross part `ι(x_σ)K_{1−σ}` is a subfield VOLE on
//!   σ's own sparse noise: `c·t` GF-valued DPFs per vector and owner with
//!   payload `ι(v)·K_{1−σ}` at σ's own positions (`4ct` in all), FFT'd and
//!   combined with `ι(a_i)`.
//! * **product MACs** (mode A only): shares of `ι(c)K`, from `4c²t²` GF-valued
//!   DPFs, one per nonzero term of `u_{ij} = (e_{0,i} + e_{1,i})(f_{0,j} + f_{1,j})`
//!   with payload `ι(v_e v_f)·K`, FFT'd and combined with `ι(a_i a_j)`.
//!
//! The dealer here is trusted; it is the stand-in for a malicious seed
//! generation (see the crate docs).

use crate::gf::{bit_macs, fft_gf, scale, sqrt};
use crate::wide::{self, WideKey, LANES};
use dpf_common::aes_tower::F4Sh;
use dpf_common::block::Block;
use dpf_common::f4::{self, Packed};
use dpf_common::foleage::tdpf::{self, leaf_len, TdpfKey, LEAF_BLOCKS};
use dpf_common::foleage::{fft::fft, sample_a, sample_noise, trit_add, NoiseEntry, Params, C, T, T_TRITS};
use dpf_common::mac::af4::{ABit, AuthTriple};
use rand::{CryptoRng, RngCore};

/// Which MACs the PCG produces.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// MACs on a, b and c (approach (a)).
    Full,
    /// MACs on a and b only (approach (b)); c is authenticated afterwards.
    Linear,
}

/// Leaf trits of the GF-valued DPFs: a leaf holds 3 positions × 2 lanes.
pub const GF_LEAF_TRITS: usize = 1;

fn gf_leaf_blocks() -> usize {
    3usize.pow(GF_LEAF_TRITS as u32) * LANES
}

/// One party's seed.
pub struct Seed {
    pub party: usize,
    pub params: Params,
    pub mode: Mode,
    pub a_seed: Block,
    pub e: Vec<NoiseEntry>,
    pub f: Vec<NoiseEntry>,
    /// `Δ_σ` and `Γ_σ = √Δ_σ`.
    pub keys: [Block; LANES],
    /// Cross value terms `e_0 × f_1` and `e_1 × f_0`, index [`val_index`].
    pub val: Vec<TdpfKey>,
    /// Linear MACs, index [`vole_index`].
    pub vole: Vec<WideKey>,
    /// Product MACs (mode A), index [`cmac_index`].
    pub cmac: Vec<WideKey>,
}

pub fn val_index(term: usize, i: usize, j: usize, ja: usize, jb: usize) -> usize {
    (((term * C + i) * C + j) * T + ja) * T + jb
}

/// `vec` 0 = e (x), 1 = f (y); `owner` the party whose noise it is.
pub fn vole_index(owner: usize, vec: usize, i: usize, j: usize) -> usize {
    (((owner * 2 + vec) * C + i) * T) + j
}

/// `term = 2p + q` for `e_p × f_q`.
pub fn cmac_index(term: usize, i: usize, j: usize, ja: usize, jb: usize) -> usize {
    val_index(term, i, j, ja, jb)
}

impl Seed {
    /// Bytes of the seed (noise and keys).
    pub fn size_bytes(&self) -> usize {
        32 + 16 * (self.e.len() + self.f.len())
            + self.val.iter().map(|k| k.size_bytes()).sum::<usize>()
            + self.vole.iter().map(|k| k.size_bytes()).sum::<usize>()
            + self.cmac.iter().map(|k| k.size_bytes()).sum::<usize>()
    }
}

/// GF leaf for the value `payload` (two lanes) at `slot`.
fn gf_leaf(slot: usize, payload: [Block; LANES]) -> Vec<Block> {
    let mut v = vec![Block::ZERO; gf_leaf_blocks()];
    v[slot * LANES] = payload[0];
    v[slot * LANES + 1] = payload[1];
    v
}

/// Trusted-dealer seeds for the MAC-key shares `deltas` (`Δ_b` of each party).
pub fn deal<R: RngCore + CryptoRng>(p: Params, mode: Mode, deltas: [Block; 2], rng: &mut R) -> [Seed; 2] {
    let a_seed = Block::random(rng);
    let e = [sample_noise(&p, rng), sample_noise(&p, rng)];
    let f = [sample_noise(&p, rng), sample_noise(&p, rng)];
    let ks: [[Block; LANES]; 2] = [0, 1].map(|b| [deltas[b], sqrt(deltas[b])]);
    let full = [ks[0][0] ^ ks[1][0], ks[0][1] ^ ks[1][1]];
    let (leaf, bt) = (leaf_len(p.leaf_trits), p.block_trits());
    let gl = 3usize.pow(GF_LEAF_TRITS as u32);
    let gdepth = bt - GF_LEAF_TRITS;
    let mut val = [Vec::new(), Vec::new()];
    let mut cmac = [Vec::new(), Vec::new()];
    for term in 0..4 {
        let (pp, q) = (term / 2, term % 2);
        for i in 0..C {
            for j in 0..C {
                for ja in 0..T {
                    for jb in 0..T {
                        let (ea, fb) = (e[pp][i * T + ja], f[q][j * T + jb]);
                        let off = trit_add(ea.offset, fb.offset, bt);
                        let v = f4::mul(ea.value, fb.value);
                        // Value DPFs for the two cross terms (01 and 10).
                        if term == 1 || term == 2 {
                            let k = tdpf::deal(p.depth(), off / leaf, tdpf::unit_leaf(off % leaf, v), rng);
                            for (b, kk) in k.into_iter().enumerate() {
                                val[b].push(kk);
                            }
                        }
                        if mode == Mode::Full {
                            let k = wide::deal(gdepth, off / gl, &gf_leaf(off % gl, [scale(v, full[0]), scale(v, full[1])]), rng);
                            for (b, kk) in k.into_iter().enumerate() {
                                cmac[b].push(kk);
                            }
                        }
                    }
                }
            }
        }
    }
    // The value DPFs were pushed for terms 1, 2 in order: re-index as 0, 1.
    let mut vole = [Vec::new(), Vec::new()];
    for owner in 0..2 {
        for vec in 0..2 {
            let noise = if vec == 0 { &e[owner] } else { &f[owner] };
            for i in 0..C {
                for j in 0..T {
                    let ne = noise[i * T + j];
                    let pay = [scale(ne.value, ks[1 - owner][0]), scale(ne.value, ks[1 - owner][1])];
                    let k = wide::deal(gdepth, ne.offset / gl, &gf_leaf(ne.offset % gl, pay), rng);
                    for (b, kk) in k.into_iter().enumerate() {
                        vole[b].push(kk);
                    }
                }
            }
        }
    }
    let [v0, v1] = val;
    let [c0, c1] = cmac;
    let [o0, o1] = vole;
    let [e0, e1] = e;
    let [f0, f1] = f;
    [
        Seed { party: 0, params: p, mode, a_seed, e: e0, f: f0, keys: ks[0], val: v0, vole: o0, cmac: c0 },
        Seed { party: 1, params: p, mode, a_seed, e: e1, f: f1, keys: ks[1], val: v1, vole: o1, cmac: c1 },
    ]
}

/// One party's expanded shares at all `3^N` coordinates.
pub struct Raw {
    pub party: usize,
    pub a: Vec<u8>,
    pub b: Vec<u8>,
    pub c: Vec<u8>,
    /// Shares of `ι(a)K`, `ι(b)K` (and `ι(c)K` in mode A), lane-major.
    pub ma: [Vec<Block>; LANES],
    pub mb: [Vec<Block>; LANES],
    pub mc: Option<[Vec<Block>; LANES]>,
}

/// `⟨a, ê⟩` for this party's noise vector.
fn lin_value(p: &Params, a: &[u8], noise: &[NoiseEntry]) -> Vec<u8> {
    let (n, bs) = (p.oles(), p.block_size());
    let mut e = vec![0u8; n];
    for i in 0..C {
        for j in 0..T {
            let ne = noise[i * T + j];
            e[j * bs + ne.offset] ^= ne.value << (2 * i);
        }
    }
    fft(&mut e);
    (0..n).map(|k| (0..C).fold(0u8, |acc, l| acc ^ f4::mul_packed(a[k], e[k]).lane(l))).collect()
}

/// Shares of the GF-valued polynomial given by the DPFs `keys[(j, key)]`
/// placed in blocks j, one vector per lane, FFT'd.
fn gf_poly(p: &Params, keys: &[(usize, &WideKey)]) -> [Vec<Block>; LANES] {
    let (n, bs) = (p.oles(), p.block_size());
    let gl = 3usize.pow(GF_LEAF_TRITS as u32);
    let mut out = [vec![Block::ZERO; n], vec![Block::ZERO; n]];
    let mut acc = vec![Block::ZERO; bs * LANES];
    let mut blocks: Vec<usize> = keys.iter().map(|k| k.0).collect();
    blocks.sort_unstable();
    blocks.dedup();
    for blk in blocks {
        acc.iter_mut().for_each(|x| *x = Block::ZERO);
        for (_, k) in keys.iter().filter(|k| k.0 == blk) {
            k.eval_into(&mut acc);
        }
        for pos in 0..bs {
            let (leafi, slot) = (pos / gl, pos % gl);
            let base = (leafi * gl + slot) * LANES;
            for (l, o) in out.iter_mut().enumerate() {
                o[blk * bs + pos] = acc[base + l];
            }
        }
    }
    for o in out.iter_mut() {
        fft_gf(o);
    }
    out
}

impl Seed {
    /// PCG.Expand.
    pub fn expand(&self) -> Raw {
        let p = &self.params;
        let n = p.oles();
        let bs = p.block_size();
        let av = sample_a(p, self.a_seed);
        let (x, y) = (lin_value(p, &av, &self.e), lin_value(p, &av, &self.f));

        // c = x y + cross terms.
        let leaf = leaf_len(p.leaf_trits);
        let leaves = 3usize.pow(p.depth() as u32);
        let mut u = vec![0u32; n];
        let mut acc = vec![Block::ZERO; leaves * LEAF_BLOCKS];
        for i in 0..C {
            for j in 0..C {
                let lane = i * C + j;
                for blk in 0..T {
                    acc.iter_mut().for_each(|b| *b = Block::ZERO);
                    for term in 0..2 {
                        for ja in 0..T {
                            let jb = (0..T).find(|&jb| trit_add(ja, jb, T_TRITS) == blk).unwrap();
                            for (a, b) in acc.iter_mut().zip(self.val[val_index(term, i, j, ja, jb)].full_eval()) {
                                *a ^= b;
                            }
                        }
                    }
                    for l in 0..leaves {
                        for s in 0..leaf {
                            let v = acc[l * LEAF_BLOCKS + s / 64].0.lane(s % 64);
                            u[blk * bs + l * leaf + s] |= (v as u32) << (2 * lane);
                        }
                    }
                }
            }
        }
        fft(&mut u);
        let c: Vec<u8> = (0..n)
            .map(|k| {
                let a2 = (0..C * C).fold(0u32, |w, l| w.xor_lane(l, f4::mul(av[k].lane(l / C), av[k].lane(l % C))));
                let cross = (0..C * C).fold(0u8, |acc, l| acc ^ f4::mul_packed(a2, u[k]).lane(l));
                f4::mul(x[k], y[k]) ^ cross
            })
            .collect();

        // Linear MACs: local ι(x_σ)K_σ plus the VOLE shares of both owners.
        let lin_mac = |vec: usize, own: &[u8]| -> [Vec<Block>; LANES] {
            let mut m = [vec![Block::ZERO; n], vec![Block::ZERO; n]];
            for k in 0..n {
                for l in 0..LANES {
                    m[l][k] = scale(own[k], self.keys[l]);
                }
            }
            for i in 0..C {
                let keys: Vec<(usize, &WideKey)> = (0..2).flat_map(|o| (0..T).map(move |j| (o, j))).map(|(o, j)| (j, &self.vole[vole_index(o, vec, i, j)])).collect();
                let poly = gf_poly(p, &keys);
                for k in 0..n {
                    let ai = av[k].lane(i);
                    for l in 0..LANES {
                        m[l][k] ^= scale(ai, poly[l][k]);
                    }
                }
            }
            m
        };
        let ma = lin_mac(0, &x);
        let mb = lin_mac(1, &y);

        // Product MACs (mode A).
        let mc = (self.mode == Mode::Full).then(|| {
            let mut m = [vec![Block::ZERO; n], vec![Block::ZERO; n]];
            for i in 0..C {
                for j in 0..C {
                    let mut keys = Vec::with_capacity(4 * T * T);
                    for term in 0..4 {
                        for ja in 0..T {
                            for jb in 0..T {
                                keys.push((trit_add(ja, jb, T_TRITS), &self.cmac[cmac_index(term, i, j, ja, jb)]));
                            }
                        }
                    }
                    let poly = gf_poly(p, &keys);
                    for k in 0..n {
                        let aij = f4::mul(av[k].lane(i), av[k].lane(j));
                        for l in 0..LANES {
                            m[l][k] ^= scale(aij, poly[l][k]);
                        }
                    }
                }
            }
            m
        });
        Raw { party: self.party, a: x, b: y, c, ma, mb, mc }
    }
}

impl Raw {
    pub fn len(&self) -> usize {
        self.a.len()
    }

    pub fn is_empty(&self) -> bool {
        self.a.is_empty()
    }

    /// The authenticated share of the value `v` with MAC lanes `m` at k.
    pub fn auth(v: &[u8], m: &[Vec<Block>; LANES], k: usize) -> F4Sh<ABit> {
        let (h, l) = bit_macs(v[k], m[0][k], m[1][k]);
        F4Sh { h, l }
    }

    /// Mode A: the authenticated triples, no interaction.
    pub fn full_triples(&self) -> Vec<AuthTriple> {
        let mc = self.mc.as_ref().expect("mode A expansion");
        (0..self.len()).map(|k| AuthTriple { a: Self::auth(&self.a, &self.ma, k), b: Self::auth(&self.b, &self.mb, k), c: Self::auth(&self.c, mc, k) }).collect()
    }
}
