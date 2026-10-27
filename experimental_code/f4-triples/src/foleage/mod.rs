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
//! Fig. 1). ePrint 2025/892 (Bouillaguet, Delaplace, Hamdad, Vergnaud) breaks
//! the aggressive set in practice and the conservative one for large N; their
//! countermeasure `3^{N−1} < 4^{3(c−1)}` limits `c = 4` to `N ≤ 12`, which
//! [`Params::with_c`] enforces. Larger instances need a larger c
//! ([`Params::max_log3`]: `c = 5` allows `N ≤ 16`, `c = 6` allows `N ≤ 19`) at
//! `(ct)²` DPFs; [`Params::new`] keeps `c = 4`.
//!
//! * [`fft`]: the packed FFT over `R`.
//! * [`tdpf`]: the ternary random DPF and its full-domain evaluation.
//! * [`seedgen`]: dealer-free seed generation (§5: Figs. 7, 9 and 11 on
//!   chosen 1-out-of-3 OT, from COTs).

pub mod seedgen;
pub mod tdpf;

use crate::p16::P16;
use dpf_common::block::Block;
use dpf_common::f4::{self, Packed};
use dpf_common::foleage::fft;
use dpf_common::hash::CtrPrg;
use rand::{CryptoRng, Rng, RngCore};
use tdpf::{leaf_len, TdpfKey, LEAF_BLOCKS};

/// Default compression factor `c` (number of noise polynomials per party).
pub const C: usize = 4;
/// Largest supported `c`: `a` is packed in a `u16`.
pub const MAX_C: usize = 8;
/// Noise weight per polynomial, `t = 3^T_TRITS`.
pub const T_TRITS: usize = 3;
pub const T: usize = 27;

/// Instance size and compression factor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Params {
    /// `N`: the instance yields `3^N` OLEs.
    pub log3: usize,
    /// `v`: trits resolved inside a DPF leaf (early termination).
    pub leaf_trits: usize,
    /// `c`: noise polynomials per party.
    pub c: usize,
}

impl Params {
    /// `3^log3` OLEs with `c = 4`, with up to 5 leaf trits.
    pub fn new(log3: usize) -> Params {
        Self::with_c(log3, C)
    }

    /// `3^log3` OLEs with compression factor `c`.
    pub fn with_c(log3: usize, c: usize) -> Params {
        assert!(log3 >= T_TRITS + 2, "need at least two trits per block");
        assert!((2..=MAX_C).contains(&c), "c = {c} outside 2..={MAX_C}");
        assert!(
            Self::outside_bczv_attack(log3, c),
            "3^{log3} OLEs with c = {c} is in reach of the QA-SD attack of ePrint 2025/892 (needs 3^(N-1) < 4^(3(c-1)), e.g. N <= 12 for c = 4)"
        );
        Params { log3, leaf_trits: (log3 - T_TRITS - 1).min(5), c }
    }

    /// Bouillaguet–Delaplace–Hamdad–Vergnaud (ePrint 2025/892) recover the
    /// noise from the coordinates where all of `a_1, …, a_{c−1}` vanish; their
    /// countermeasure is `(q−1)^{N−1} < q^{(q−1)(c−1)}`, i.e. `3^{N−1} <
    /// 4^{3(c−1)}` over F4, so that no such evaluation point is expected.
    pub fn outside_bczv_attack(log3: usize, c: usize) -> bool {
        3u128.pow(log3 as u32 - 1) < 4u128.pow(3 * (c as u32 - 1))
    }

    /// The largest N that [`Params::with_c`] accepts for `c`.
    pub fn max_log3(c: usize) -> usize {
        (T_TRITS + 2..).take_while(|&k| Self::outside_bczv_attack(k, c)).last().expect("c too small")
    }

    /// The smallest instance (at least `3^12`) with `n` OLEs, `c = 4`.
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
        self.c * self.c * T * T
    }

    /// DPF number for the noise entries `(i_A, j_A)` of party 0 and
    /// `(i_B, j_B)` of party 1.
    pub fn dpf_index(&self, ia: usize, ib: usize, ja: usize, jb: usize) -> usize {
        ((ia * self.c + ib) * T + ja) * T + jb
    }

    /// `(i_A, i_B, j_A, j_B)` of DPF `d`, the inverse of [`Params::dpf_index`].
    pub fn dpf_entries(&self, d: usize) -> (usize, usize, usize, usize) {
        (d / (T * T * self.c), d / (T * T) % self.c, d / T % T, d % T)
    }
}

/// `f(0), …, f(n − 1)`, computed on all cores in contiguous chunks.
pub(crate) fn par_map<X: Send>(n: usize, f: impl Fn(usize) -> X + Sync) -> Vec<X> {
    let threads = std::thread::available_parallelism().map_or(1, |t| t.get());
    let per = n.div_ceil(threads).max(1);
    let f = &f;
    std::thread::scope(|sc| {
        let hs: Vec<_> = (0..n).step_by(per).map(|lo| sc.spawn(move || (lo..(lo + per).min(n)).map(f).collect::<Vec<X>>())).collect();
        hs.into_iter().flat_map(|h| h.join().unwrap()).collect()
    })
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
    (0..p.c * T).map(|_| NoiseEntry { offset: rng.gen_range(0..p.block_size()), value: rng.gen_range(1..4) }).collect()
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
pub fn sample_a(p: &Params, seed: Block) -> Vec<P16> {
    let n = p.oles();
    let mask = ((1u32 << (2 * p.c)) - 1) as u16;
    let words = CtrPrg::new(seed).next_words(n.div_ceil(8));
    (0..n).map(|i| P16(((words[i / 8] >> (16 * (i % 8))) as u16 & mask & !3) | 1)).collect()
}

/// Sum of the first `lanes` lanes of `w`.
fn fold<P: Packed>(w: P, lanes: usize) -> u8 {
    (0..lanes).fold(0u8, |acc, l| acc ^ w.lane(l))
}

/// Lanes of `⟨u⟩` packed per word in [`Seed::expand`] (a `u16`, so that
/// both parties expand `3^19` OLEs in memory).
const U_LANES: usize = 8;

impl Seed {
    /// Seed size in bytes (noise and DPF keys).
    pub fn size_bytes(&self) -> usize {
        16 + self.noise.len() * 8 + self.keys.iter().map(|k| k.size_bytes()).sum::<usize>()
    }

    /// PCG.Expand: the `3^N` OLEs. The DPFs are evaluated on all cores.
    pub fn expand(&self) -> Ole {
        let p = &self.params;
        let (n, bs, c) = (p.oles(), p.block_size(), p.c);
        let a = sample_a(p, self.a_seed);

        // x = Σ a_i·FFT(e_i), the c FFTs packed in a u16.
        let mut e = vec![P16::default(); n];
        for i in 0..c {
            for j in 0..T {
                let ne = self.noise[i * T + j];
                e[j * bs + ne.offset] = e[j * bs + ne.offset].xor_lane(i, ne.value);
            }
        }
        fft::fft(&mut e);
        let x: Vec<u8> = (0..n).map(|k| fold(f4::mul_packed(a[k], e[k]), c)).collect();
        drop(e);

        // ⟨u_{i,j}⟩: the DPFs of each block summed, lane i·c + j, packed
        // U_LANES lanes per u16 (one pass per group of lanes).
        let leaf = leaf_len(p.leaf_trits);
        let leaves = 3usize.pow(p.depth() as u32);
        let threads = std::thread::available_parallelism().map_or(1, |t| t.get()).min(T);
        let mut z = vec![0u8; n];
        for g in (0..c * c).step_by(U_LANES) {
            let lanes = g..(g + U_LANES).min(c * c);
            let mut u = vec![P16::default(); n];
            let blocks: Vec<(usize, &mut [P16])> = u.chunks_mut(bs).enumerate().collect();
            let per = blocks.len().div_ceil(threads);
            let mut blocks = blocks.into_iter();
            std::thread::scope(|sc| loop {
                let mine: Vec<_> = blocks.by_ref().take(per).collect();
                if mine.is_empty() {
                    break;
                }
                let lanes = lanes.clone();
                sc.spawn(move || {
                    let mut acc = vec![Block::ZERO; leaves * LEAF_BLOCKS];
                    for (blk, ub) in mine {
                        for lane in lanes.clone() {
                            let (ia, ib) = (lane / c, lane % c);
                            acc.iter_mut().for_each(|b| *b = Block::ZERO);
                            for ja in 0..T {
                                let jb = (0..T).find(|&jb| trit_add(ja, jb, T_TRITS) == blk).unwrap();
                                let y = self.keys[p.dpf_index(ia, ib, ja, jb)].full_eval();
                                for (a, b) in acc.iter_mut().zip(&y) {
                                    *a ^= *b;
                                }
                            }
                            for l in 0..leaves {
                                for s in 0..leaf {
                                    let v = acc[l * LEAF_BLOCKS + s / 64].0.lane(s % 64);
                                    ub[l * leaf + s] = ub[l * leaf + s].xor_lane(lane - g, v);
                                }
                            }
                        }
                    }
                });
            });
            fft::fft(&mut u);
            for k in 0..n {
                let a2 = lanes.clone().fold(P16::default(), |w, l| w.xor_lane(l - g, f4::mul(a[k].lane(l / c), a[k].lane(l % c))));
                z[k] ^= fold(f4::mul_packed(a2, u[k]), lanes.len());
            }
        }
        Ole { x, z }
    }
}

/// F4 Beaver triples from pairs of OLEs. OLE `2i` gives the cross term
/// `a_0·b_1` (party 0's `x` is `a_0`, party 1's is `b_1`), OLE `2i + 1` gives
/// `b_0·a_1`; then `c_σ = a_σ b_σ + z_σ[2i] + z_σ[2i + 1]`.
pub fn triples(ole: &Ole, party: usize, count: usize) -> Vec<(u8, u8, u8)> {
    triples_at(ole, party, 0, count)
}

/// [`triples`] from triple `start` on, so that the Gens of one session take
/// disjoint OLEs from the same instance.
pub fn triples_at(ole: &Ole, party: usize, start: usize, count: usize) -> Vec<(u8, u8, u8)> {
    assert!(2 * (start + count) <= ole.x.len(), "instance too small for {count} more triples");
    (start..start + count)
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
    for ia in 0..p.c {
        for ib in 0..p.c {
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
    fn dealt_seeds_for_other_c() {
        let mut rng = ChaCha20Rng::seed_from_u64(12);
        for c in [3, 5, 6, 8] {
            check_oles(&deal(Params::with_c(6, c), &mut rng));
        }
        assert_eq!([Params::max_log3(4), Params::max_log3(5), Params::max_log3(6)], [12, 16, 19]);
    }

    #[test]
    fn trit_helpers() {
        assert_eq!(trit_add(5, 7, 3), {
            // 5 = 12₃, 7 = 21₃ → 00₃ (1+2, 2+1 mod 3) with the top trit 0.
            0
        });
        assert_eq!(trit(17, 2), 1);
        assert_eq!(Params::for_oles(500_000).log3, 12);
        // 3^13 with c = 4 is in reach of ePrint 2025/892.
        assert!(std::panic::catch_unwind(|| Params::new(13)).is_err());
    }
}
