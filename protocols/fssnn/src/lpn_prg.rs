//! F_SecPRG of FssNN, instantiated with the LPN-PRG of Dinur et al.,
//! "MPC-Friendly Symmetric Cryptography from Alternating Moduli" (CRYPTO'21,
//! the paper FssNN cites as [9]).
//!
//! **The PRG** (DGH+21 Construction 3.4, Table 3 parameters `(n, m, t) =
//! (128, 512, 256)`): for `x ∈ Z_2^128`,
//!
//! ```text
//! G(x) = B·w,  w = (A·x mod 2) ⊕ ((A·x mod 3) mod 2)
//! ```
//!
//! with public random `A ∈ Z_2^{512×128}` and `B ∈ Z_2^{256×512}`. Row `i` of
//! `A·x` over the integers is `popcount(A_i ∧ x)`, so one popcount gives both
//! the mod-2 and the mod-3 value.
//!
//!
//! The 2PC evaluation of `G` is in [`crate::semi_honest::sec_prg`].

use dpf_common::block::Block;
use dpf_common::hash::CtrPrg;
use std::sync::OnceLock;

/// Input bits.
pub const N_IN: usize = 128;
/// Rows of A, i.e. intermediate Z3 values.
pub const M_MID: usize = 512;
/// Output bits.
pub const T_OUT: usize = 256;
pub(crate) const MW: usize = M_MID / 128;

/// Seed of the public matrices A and B (any fixed value works; they are public).
const MATRIX_SEED: u128 = u128::from_le_bytes(*b"FssNN/DGH21-LPN!");

/// The public matrices of the LPN-PRG. `B` is stored by columns: `B·w` is the
/// XOR of the columns that `w` selects, which costs one masked 256-bit XOR per
/// bit of `w` instead of one 512-bit popcount parity per output bit.
pub struct LpnPrg {
    a: Vec<u128>,
    /// Column `i` of `B` as (bits 0..128, bits 128..256), for `i < 512`.
    b_cols: Vec<[u128; 2]>,
}

/// The LPN-PRG instance used everywhere.
pub fn lpn_prg() -> &'static LpnPrg {
    static P: OnceLock<LpnPrg> = OnceLock::new();
    P.get_or_init(|| {
        let mut prg = CtrPrg::new(Block(MATRIX_SEED));
        let a = prg.next_words(M_MID);
        // B is drawn row by row (row j = words MW·j..MW·(j+1)) and transposed.
        let bw = prg.next_words(T_OUT * MW);
        let mut b_cols = vec![[0u128; 2]; M_MID];
        for j in 0..T_OUT {
            let row = &bw[j * MW..(j + 1) * MW];
            for (i, col) in b_cols.iter_mut().enumerate() {
                col[j / 128] |= (row[i / 128] >> (i % 128) & 1) << (j % 128);
            }
        }
        LpnPrg { a, b_cols }
    })
}

impl LpnPrg {
    /// `A·x mod 2` as 512 bits.
    pub(crate) fn lin2_a(&self, x: u128) -> [u128; MW] {
        let mut u = [0u128; MW];
        for (i, row) in self.a.iter().enumerate() {
            u[i / 128] |= ((row & x).count_ones() as u128 & 1) << (i % 128);
        }
        u
    }

    /// `A·x mod 3` for `x ∈ Z_3^128` given as the masks of its 1- and 2-entries.
    pub(crate) fn lin3_a(&self, one: u128, two: u128) -> Vec<u8> {
        self.a.iter().map(|row| (((row & one).count_ones() + 2 * (row & two).count_ones()) % 3) as u8).collect()
    }

    /// `B·w mod 2` as (bits 0..128, bits 128..256).
    pub(crate) fn lin2_b(&self, w: &[u128; MW]) -> [u128; 2] {
        let mut y = [0u128; 2];
        for (i, col) in self.b_cols.iter().enumerate() {
            let m = (w[i / 128] >> (i % 128) & 1).wrapping_neg();
            y[0] ^= col[0] & m;
            y[1] ^= col[1] & m;
        }
        y
    }

    /// `G(x)` in the clear.
    pub fn eval(&self, x: u128) -> [u128; 2] {
        #[cfg(target_arch = "x86_64")]
        if has_popcnt() {
            // SAFETY: the CPU supports POPCNT.
            return unsafe { eval_popcnt(self, x) };
        }
        eval_generic(self, x)
    }

    /// One half of `G(x)` (bits 128·side..128·side + 128), for point evaluation.
    pub fn eval_side(&self, x: u128, side: usize) -> u128 {
        #[cfg(target_arch = "x86_64")]
        if has_popcnt() {
            // SAFETY: the CPU supports POPCNT.
            return unsafe { eval_side_popcnt(self, x, side) };
        }
        eval_side_generic(self, x, side)
    }
}

// The local evaluation is popcount-bound. The workspace builds for baseline
// x86-64, which has no POPCNT, so the hot loops are compiled twice and picked
// at run time (as `dpf_common::gf128` does for PCLMULQDQ).

/// All-ones iff `w_i = (c mod 2) ⊕ ((c mod 3) mod 2)` is 1, for `c = popcount(A_i ∧ x)`.
#[inline(always)]
fn w_mask(row: u128, x: u128) -> u128 {
    let c = (row & x).count_ones();
    (((c & 1) ^ ((c % 3) & 1)) as u128).wrapping_neg()
}

/// `G(x)`: row `i` of `A` gives `w_i`, which selects column `i` of `B`.
#[inline(always)]
fn eval_generic(p: &LpnPrg, x: u128) -> [u128; 2] {
    let mut y = [0u128; 2];
    for (row, col) in p.a.iter().zip(&p.b_cols) {
        let m = w_mask(*row, x);
        y[0] ^= col[0] & m;
        y[1] ^= col[1] & m;
    }
    y
}

#[inline(always)]
fn eval_side_generic(p: &LpnPrg, x: u128, side: usize) -> u128 {
    p.a.iter().zip(&p.b_cols).fold(0, |y, (row, col)| y ^ (col[side] & w_mask(*row, x)))
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "popcnt")]
unsafe fn eval_popcnt(p: &LpnPrg, x: u128) -> [u128; 2] {
    eval_generic(p, x)
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "popcnt")]
unsafe fn eval_side_popcnt(p: &LpnPrg, x: u128, side: usize) -> u128 {
    eval_side_generic(p, x, side)
}

#[cfg(target_arch = "x86_64")]
fn has_popcnt() -> bool {
    static HW: OnceLock<bool> = OnceLock::new();
    *HW.get_or_init(|| is_x86_feature_detected!("popcnt"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha20Rng;

    /// `B·w`, bit by bit, with `B` drawn by rows as in `lpn_prg`.
    fn reference_b(w: &[u32]) -> [u128; 2] {
        let mut prg = CtrPrg::new(Block(MATRIX_SEED));
        prg.next_words(M_MID);
        let b = prg.next_words(T_OUT * MW);
        let mut y = [0u128; 2];
        for j in 0..T_OUT {
            let bit = (0..M_MID).fold(0, |acc, i| acc ^ ((b[j * MW + i / 128] >> (i % 128) & 1) as u32 & w[i]));
            y[j / 128] |= (bit as u128) << (j % 128);
        }
        y
    }

    /// The definition, bit by bit.
    fn reference(x: u128) -> [u128; 2] {
        let a = CtrPrg::new(Block(MATRIX_SEED)).next_words(M_MID);
        let w: Vec<u32> = a.iter().map(|r| { let c = (r & x).count_ones(); (c % 2) ^ ((c % 3) % 2) }).collect();
        reference_b(&w)
    }

    #[test]
    fn matches_bitwise_reference() {
        let p = lpn_prg();
        let mut rng = ChaCha20Rng::seed_from_u64(5);
        for _ in 0..50 {
            let x: u128 = rng.gen();
            let want = reference(x);
            assert_eq!(p.eval(x), want);
            assert_eq!([p.eval_side(x, 0), p.eval_side(x, 1)], want);
            // lin2_b on an arbitrary w (in 2PC, w is a share).
            let w: [u128; MW] = std::array::from_fn(|_| rng.gen());
            let wb: Vec<u32> = (0..M_MID).map(|i| (w[i / 128] >> (i % 128) & 1) as u32).collect();
            assert_eq!(p.lin2_b(&w), reference_b(&wb));
        }
    }

    #[test]
    fn prg_is_not_trivial() {
        // Inputs of weight ≤ 1 map to 0 (every row sum c ≤ 1 has c mod 2 =
        // (c mod 3) mod 2); random seeds have weight ≈ 64.
        let p = lpn_prg();
        assert_eq!(p.eval(1 << 5), [0, 0]);
        let mut rng = ChaCha20Rng::seed_from_u64(4);
        for _ in 0..20 {
            let y = p.eval(rng.gen());
            assert!((90..=166).contains(&(y[0].count_ones() + y[1].count_ones())), "unbalanced output");
        }
    }
}
