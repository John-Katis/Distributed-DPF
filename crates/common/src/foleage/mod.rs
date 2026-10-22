//! FOLEAGE: the F4-OLE PCG of Bombar, Bui, Couteau, Couvreur, Ducros and
//! Servan-Schreiber (ASIACRYPT'24, ePrint 2024/429), ported from the reference
//! code (`github.com/sachaservan/FOLEAGE-PCG`, `src/test.c` = Fig. 1) and
//! completed with the distributed seed generation of §5, which the reference
//! code leaves out (it deals the seeds).
//!
//! Over the group algebra `R = F4[X_1, …, X_N]/(X_i³ − 1)` (`3^N` OLEs) with
//! public `a = (1, a_1, …, a_{c−1})` sampled in the FFT domain:
//!
//! * party σ samples `c` regular `t`-sparse polynomials `e_σ,i` (one nonzero
//!   coefficient in each of the `t` blocks of `3^N/t`) and sets
//!   `x_σ = Σ_i a_i·FFT(e_σ,i)`;
//! * the cross products `u_{i,j} = e_0,i·e_1,j` are `t²`-sparse. Their nonzero
//!   positions are trit-wise sums `p_0 + p_1 mod 3` of the parties' positions,
//!   so the parties already hold additive Z_3 shares of every trit, and each
//!   nonzero coefficient is shared by one ternary DPF ([`tdpf`]): `c²t²` DPFs.
//!   With `t = 27 = 3³` the block of a cross term is the trit-wise sum of the two
//!   block indices, public, and each DPF covers one block (`3^{N−3}` positions);
//! * `z_σ = Σ_{i,j} a_i a_j·FFT(⟨u_{i,j}⟩_σ)`.
//!
//! Then `z_0 + z_1 = x_0 ⊙ x_1`: `3^N` random F4-OLEs. Two OLEs give one F4
//! Beaver triple ([`triples`]).
//!
//! Parameters `c = 4`, `t = 27` are the paper's conservative choice (Table 2 /
//! Fig. 1; its script estimates 203 bits for its sizes). The paper sets them for
//! large instances; this crate uses them unchanged for every `N`, so for small
//! `N` the security estimate is the paper's, not re-derived.
//!
//! * [`fft`]: the packed FFT over `R`.
//! * [`tdpf`]: the ternary random DPF and its full-domain evaluation.
//! * [`seedgen`]: dealer-free seed generation (§5: Figs. 7, 9 and 11 on
//!   chosen 1-out-of-3 OT, from COTs).

pub mod fft;
pub mod seedgen;
pub mod tdpf;

use crate::block::Block;
use crate::f4::{self, Packed};
use crate::hash::CtrPrg;
use rand::{CryptoRng, Rng, RngCore};
use tdpf::{leaf_len, TdpfKey, LEAF_BLOCKS};

/// Compression factor `c` (number of noise polynomials per party).
pub const C: usize = 4;
/// Noise weight per polynomial, `t = 3^T_TRITS`.
pub const T_TRITS: usize = 3;
pub const T: usize = 27;

/// Instance size.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Params {
    /// `N`: the instance yields `3^N` OLEs.
    pub log3: usize,
    /// `v`: trits resolved inside a DPF leaf (early termination).
    pub leaf_trits: usize,
}

impl Params {
    /// `3^log3` OLEs, with up to 5 leaf trits.
    pub fn new(log3: usize) -> Params {
        assert!(log3 >= T_TRITS + 2, "need at least two trits per block");
        Params { log3, leaf_trits: (log3 - T_TRITS - 1).min(5) }
    }

    /// The smallest instance (at least `3^12`) with `n` OLEs.
    pub fn for_oles(n: usize) -> Params {
        let mut k = 12;
        while 3usize.pow(k as u32) < n {
            k += 1;
        }
        Params::new(k)
    }

    pub fn oles(&self) -> usize {
        3usize.pow(self.log3 as u32)
    }

    /// Trits of a position inside a block.
    pub fn block_trits(&self) -> usize {
        self.log3 - T_TRITS
    }

    pub fn block_size(&self) -> usize {
        3usize.pow(self.block_trits() as u32)
    }

    /// Levels of each DPF tree.
    pub fn depth(&self) -> usize {
        self.block_trits() - self.leaf_trits
    }

    /// `c²t²`.
    pub fn dpfs(&self) -> usize {
        C * C * T * T
    }

    /// DPF number for the noise entries `(i_A, j_A)` of party 0 and
    /// `(i_B, j_B)` of party 1.
    pub fn dpf_index(ia: usize, ib: usize, ja: usize, jb: usize) -> usize {
        ((ia * C + ib) * T + ja) * T + jb
    }
}

/// Trit-wise sum mod 3 of `a` and `b` over `k` trits.
pub fn trit_add(mut a: usize, mut b: usize, k: usize) -> usize {
    let (mut r, mut w) = (0, 1);
    for _ in 0..k {
        r += (a % 3 + b % 3) % 3 * w;
        a /= 3;
        b /= 3;
        w *= 3;
    }
    r
}

/// Trit `k` (0 = least significant) of `x`.
pub fn trit(x: usize, k: usize) -> usize {
    x / 3usize.pow(k as u32) % 3
}

/// One noise entry: position inside its block and nonzero value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NoiseEntry {
    pub offset: usize,
    pub value: u8,
}

/// `c·t` regular noise entries, entry `i·t + j` in block j of polynomial i.
pub fn sample_noise<R: RngCore + CryptoRng>(p: &Params, rng: &mut R) -> Vec<NoiseEntry> {
    (0..C * T).map(|_| NoiseEntry { offset: rng.gen_range(0..p.block_size()), value: rng.gen_range(1..4) }).collect()
}

/// One party's PCG seed.
#[derive(Clone, Debug)]
pub struct Seed {
    pub party: usize,
    pub params: Params,
    /// Seed of the public `a` (identical for both parties).
    pub a_seed: Block,
    pub noise: Vec<NoiseEntry>,
    /// The `c²t²` DPF keys, indexed by [`Params::dpf_index`].
    pub keys: Vec<TdpfKey>,
}

/// `3^N` OLEs of one party: `z_0 + z_1 = x_0·x_1` pointwise.
pub struct Ole {
    pub x: Vec<u8>,
    pub z: Vec<u8>,
}

/// The public `a` in the FFT domain: lane 0 is the constant 1, lanes 1..c
/// uniform (`sample_a_and_a2`).
fn sample_a(p: &Params, seed: Block) -> Vec<u8> {
    let n = p.oles();
    let words = CtrPrg::new(seed).next_words(n.div_ceil(16));
    (0..n).map(|i| ((words[i / 16] >> (8 * (i % 16))) as u8 & !3) | 1).collect()
}

impl Seed {
    /// Seed size in bytes (noise and DPF keys).
    pub fn size_bytes(&self) -> usize {
        16 + self.noise.len() * 8 + self.keys.iter().map(|k| k.size_bytes()).sum::<usize>()
    }

    /// PCG.Expand: the `3^N` OLEs.
    pub fn expand(&self) -> Ole {
        let p = &self.params;
        let n = p.oles();
        let bs = p.block_size();
        let a = sample_a(p, self.a_seed);

        // x = Σ a_i·FFT(e_i), the c FFTs packed in a u8.
        let mut e = vec![0u8; n];
        for i in 0..C {
            for j in 0..T {
                let ne = self.noise[i * T + j];
                e[j * bs + ne.offset] ^= ne.value << (2 * i);
            }
        }
        fft::fft(&mut e);
        let fold = |w: u32, lanes: usize| (0..lanes).fold(0u8, |acc, l| acc ^ w.lane(l));
        let x: Vec<u8> = (0..n).map(|k| fold(f4::mul_packed(a[k], e[k]) as u32, C)).collect();
        drop(e);

        // ⟨u_{i,j}⟩: the DPFs of each block summed, then packed lane i·c + j.
        let leaf = leaf_len(p.leaf_trits);
        let leaves = 3usize.pow(p.depth() as u32);
        let mut u = vec![0u32; n];
        let mut acc = vec![Block::ZERO; leaves * LEAF_BLOCKS];
        for ia in 0..C {
            for ib in 0..C {
                let lane = ia * C + ib;
                for blk in 0..T {
                    acc.iter_mut().for_each(|b| *b = Block::ZERO);
                    for ja in 0..T {
                        let jb = (0..T).find(|&jb| trit_add(ja, jb, T_TRITS) == blk).unwrap();
                        let y = self.keys[Params::dpf_index(ia, ib, ja, jb)].full_eval();
                        for (a, b) in acc.iter_mut().zip(&y) {
                            *a ^= *b;
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
        fft::fft(&mut u);
        let z: Vec<u8> = (0..n)
            .map(|k| {
                let a2 = (0..C * C).fold(0u32, |w, l| w.xor_lane(l, f4::mul(a[k].lane(l / C), a[k].lane(l % C))));
                fold(f4::mul_packed(a2, u[k]), C * C)
            })
            .collect();
        Ole { x, z }
    }
}

/// F4 Beaver triples from pairs of OLEs. OLE `2i` gives the cross term
/// `a_0·b_1` (party 0's `x` is `a_0`, party 1's is `b_1`), OLE `2i + 1` gives
/// `b_0·a_1`; then `c_σ = a_σ b_σ + z_σ[2i] + z_σ[2i + 1]`.
pub fn triples(ole: &Ole, party: usize, count: usize) -> Vec<(u8, u8, u8)> {
    assert!(2 * count <= ole.x.len(), "instance too small for {count} triples");
    (0..count)
        .map(|i| {
            let (x0, x1) = (ole.x[2 * i], ole.x[2 * i + 1]);
            let (a, b) = if party == 0 { (x0, x1) } else { (x1, x0) };
            (a, b, f4::mul(a, b) ^ ole.z[2 * i] ^ ole.z[2 * i + 1])
        })
        .collect()
}

/// Trusted-dealer seeds (the reference code's PCG.Gen), for tests.
pub fn deal<R: RngCore + CryptoRng>(p: Params, rng: &mut R) -> [Seed; 2] {
    let a_seed = Block::random(rng);
    let noise = [sample_noise(&p, rng), sample_noise(&p, rng)];
    let leaf = leaf_len(p.leaf_trits);
    let mut keys = [Vec::with_capacity(p.dpfs()), Vec::with_capacity(p.dpfs())];
    for ia in 0..C {
        for ib in 0..C {
            for ja in 0..T {
                for jb in 0..T {
                    let (ea, eb) = (noise[0][ia * T + ja], noise[1][ib * T + jb]);
                    let off = trit_add(ea.offset, eb.offset, p.block_trits());
                    let k = tdpf::deal(p.depth(), off / leaf, tdpf::unit_leaf(off % leaf, f4::mul(ea.value, eb.value)), rng);
                    let [k0, k1] = k;
                    keys[0].push(k0);
                    keys[1].push(k1);
                }
            }
        }
    }
    let [k0, k1] = keys;
    let [n0, n1] = noise;
    [Seed { party: 0, params: p, a_seed, noise: n0, keys: k0 }, Seed { party: 1, params: p, a_seed, noise: n1, keys: k1 }]
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    pub(crate) fn check_oles(s: &[Seed; 2]) -> [Ole; 2] {
        let o = [s[0].expand(), s[1].expand()];
        for k in 0..s[0].params.oles() {
            assert_eq!(o[0].z[k] ^ o[1].z[k], f4::mul(o[0].x[k], o[1].x[k]), "OLE {k}");
        }
        // x is not degenerate.
        assert!(o[0].x.iter().filter(|&&v| v == 0).count() < o[0].x.len() / 2);
        o
    }

    #[test]
    fn dealt_seeds_expand_to_oles_and_triples() {
        let mut rng = ChaCha20Rng::seed_from_u64(11);
        let p = Params::new(7);
        assert_eq!((p.depth(), p.leaf_trits), (1, 3));
        let s = deal(p, &mut rng);
        let o = check_oles(&s);
        let t = [triples(&o[0], 0, 1000), triples(&o[1], 1, 1000)];
        for (x, y) in t[0].iter().zip(&t[1]) {
            assert_eq!(x.2 ^ y.2, f4::mul(x.0 ^ y.0, x.1 ^ y.1));
        }
    }

    #[test]
    fn trit_helpers() {
        assert_eq!(trit_add(5, 7, 3), {
            // 5 = 12₃, 7 = 21₃ → 00₃ (1+2, 2+1 mod 3) with the top trit 0.
            0
        });
        assert_eq!(trit(17, 2), 1);
        assert_eq!(Params::for_oles(600_000).log3, 13);
    }
}
