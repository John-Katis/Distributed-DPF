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

/// The public matrices of the LPN-PRG.
pub struct LpnPrg {
    a: Vec<u128>,
    b: Vec<[u128; MW]>,
}

/// The LPN-PRG instance used everywhere.
pub fn lpn_prg() -> &'static LpnPrg {
    static P: OnceLock<LpnPrg> = OnceLock::new();
    P.get_or_init(|| {
        let mut prg = CtrPrg::new(Block(MATRIX_SEED));
        let a = prg.next_words(M_MID);
        let bw = prg.next_words(T_OUT * MW);
        let b = bw.chunks(MW).map(|c| c.try_into().unwrap()).collect();
        LpnPrg { a, b }
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
        [parity_rows(&self.b[..128], w), parity_rows(&self.b[128..], w)]
    }

    /// `G(x)` in the clear.
    pub fn eval(&self, x: u128) -> [u128; 2] {
        self.lin2_b(&mid(&self.a, x))
    }

    /// One half of `G(x)` (bits 128·side..128·side + 128), for point evaluation.
    pub fn eval_side(&self, x: u128, side: usize) -> u128 {
        parity_rows(&self.b[128 * side..128 * (side + 1)], &mid(&self.a, x))
    }
}

// The local evaluation is popcount-bound. The workspace builds for baseline
// x86-64, which has no POPCNT, so the hot loops are compiled twice and picked
// at run time (as `dpf_common::gf128` does for PCLMULQDQ).

/// `w = (A·x mod 2) ⊕ ((A·x mod 3) mod 2)`.
#[inline(always)]
fn mid_generic(a: &[u128], x: u128) -> [u128; MW] {
    let mut w = [0u128; MW];
    for (i, row) in a.iter().enumerate() {
        let c = (row & x).count_ones();
        w[i / 128] |= (((c & 1) ^ ((c % 3) & 1)) as u128) << (i % 128);
    }
    w
}

/// Bit j is the parity of `rows[j] ∧ w` (at most 128 rows).
#[inline(always)]
fn parity_rows_generic(rows: &[[u128; MW]], w: &[u128; MW]) -> u128 {
    rows.iter().enumerate().fold(0, |y, (j, row)| {
        let x = row.iter().zip(w).fold(0, |acc, (r, x)| acc ^ (r & x));
        y | ((x.count_ones() & 1) as u128) << j
    })
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "popcnt")]
unsafe fn mid_popcnt(a: &[u128], x: u128) -> [u128; MW] {
    mid_generic(a, x)
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "popcnt")]
unsafe fn parity_rows_popcnt(rows: &[[u128; MW]], w: &[u128; MW]) -> u128 {
    parity_rows_generic(rows, w)
}

#[cfg(target_arch = "x86_64")]
fn has_popcnt() -> bool {
    static HW: OnceLock<bool> = OnceLock::new();
    *HW.get_or_init(|| is_x86_feature_detected!("popcnt"))
}

fn mid(a: &[u128], x: u128) -> [u128; MW] {
    #[cfg(target_arch = "x86_64")]
    if has_popcnt() {
        // SAFETY: the CPU supports POPCNT.
        return unsafe { mid_popcnt(a, x) };
    }
    mid_generic(a, x)
}

fn parity_rows(rows: &[[u128; MW]], w: &[u128; MW]) -> u128 {
    #[cfg(target_arch = "x86_64")]
    if has_popcnt() {
        // SAFETY: the CPU supports POPCNT.
        return unsafe { parity_rows_popcnt(rows, w) };
    }
    parity_rows_generic(rows, w)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha20Rng;

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
