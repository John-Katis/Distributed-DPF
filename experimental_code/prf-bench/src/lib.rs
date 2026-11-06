//! PRF microbenchmarks (experiment; `crates/` and `protocols/` are unchanged).
//!
//! Two copies of the DGH+21 LPN-PRG of `fssnn::lpn_prg`, which differ only in
//! how they apply the output map `B`: [`RowLpn`] row-wise (one popcount
//! parity per output bit, what `fssnn` did before 2026-11-05) and [`ColLpn`]
//! column-wise (the XOR of the columns of `B` that `w` selects, what `fssnn`
//! does since). Both rebuild the public matrices from the same seed, and the
//! tests check both against `fssnn::lpn_prg` bit for bit.

pub mod maestro;
pub mod triples;

use dpf_common::block::Block;
use dpf_common::hash::CtrPrg;

const M_MID: usize = 512;
const T_OUT: usize = 256;
const MW: usize = M_MID / 128;
/// The seed of `fssnn::lpn_prg` (its matrices are public).
const MATRIX_SEED: u128 = u128::from_le_bytes(*b"FssNN/DGH21-LPN!");

/// The DGH+21 LPN-PRG with `B` stored by columns.
pub struct ColLpn {
    a: Vec<u128>,
    /// Column i of B (256 bits), for each of the 512 intermediate bits.
    cols: Vec<[u128; 2]>,
}

impl Default for ColLpn {
    fn default() -> Self {
        Self::new()
    }
}

impl ColLpn {
    pub fn new() -> Self {
        let mut prg = CtrPrg::new(Block(MATRIX_SEED));
        let a = prg.next_words(M_MID);
        let bw = prg.next_words(T_OUT * MW);
        let mut cols = vec![[0u128; 2]; M_MID];
        for j in 0..T_OUT {
            let row = &bw[j * MW..(j + 1) * MW];
            for (i, col) in cols.iter_mut().enumerate() {
                if row[i / 128] >> (i % 128) & 1 == 1 {
                    col[j / 128] |= 1 << (j % 128);
                }
            }
        }
        ColLpn { a, cols }
    }

    /// `G(x)` as (bits 0..128, bits 128..256).
    #[inline]
    pub fn eval(&self, x: u128) -> [u128; 2] {
        #[cfg(target_arch = "x86_64")]
        if std::is_x86_feature_detected!("popcnt") {
            // SAFETY: the CPU supports POPCNT.
            return unsafe { eval_popcnt(self, x) };
        }
        eval_generic(self, x)
    }
}

#[inline(always)]
fn eval_generic(p: &ColLpn, x: u128) -> [u128; 2] {
    let mut y = [0u128; 2];
    for (row, col) in p.a.iter().zip(&p.cols) {
        let c = (row & x).count_ones();
        // w_i = (c mod 2) ⊕ ((c mod 3) mod 2); select column i if set.
        let m = (((c & 1) ^ ((c % 3) & 1)) as u128).wrapping_neg();
        y[0] ^= col[0] & m;
        y[1] ^= col[1] & m;
    }
    y
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "popcnt")]
unsafe fn eval_popcnt(p: &ColLpn, x: u128) -> [u128; 2] {
    eval_generic(p, x)
}

/// The DGH+21 LPN-PRG with `B` stored by rows (the pre-2026-11-05 `fssnn` code).
pub struct RowLpn {
    a: Vec<u128>,
    b: Vec<[u128; MW]>,
}

impl Default for RowLpn {
    fn default() -> Self {
        Self::new()
    }
}

impl RowLpn {
    pub fn new() -> Self {
        let mut prg = CtrPrg::new(Block(MATRIX_SEED));
        let a = prg.next_words(M_MID);
        let bw = prg.next_words(T_OUT * MW);
        RowLpn { a, b: bw.chunks(MW).map(|c| c.try_into().unwrap()).collect() }
    }

    /// `G(x)` as (bits 0..128, bits 128..256).
    #[inline]
    pub fn eval(&self, x: u128) -> [u128; 2] {
        let w = self.mid(x);
        [self.parity(&self.b[..128], &w), self.parity(&self.b[128..], &w)]
    }

    /// One half of `G(x)`, as in point evaluation.
    #[inline]
    pub fn eval_side(&self, x: u128, side: usize) -> u128 {
        self.parity(&self.b[128 * side..128 * (side + 1)], &self.mid(x))
    }

    fn mid(&self, x: u128) -> [u128; MW] {
        #[cfg(target_arch = "x86_64")]
        if std::is_x86_feature_detected!("popcnt") {
            // SAFETY: the CPU supports POPCNT.
            return unsafe { mid_popcnt(&self.a, x) };
        }
        mid_generic(&self.a, x)
    }

    fn parity(&self, rows: &[[u128; MW]], w: &[u128; MW]) -> u128 {
        #[cfg(target_arch = "x86_64")]
        if std::is_x86_feature_detected!("popcnt") {
            // SAFETY: the CPU supports POPCNT.
            return unsafe { parity_popcnt(rows, w) };
        }
        parity_generic(rows, w)
    }
}

#[inline(always)]
fn mid_generic(a: &[u128], x: u128) -> [u128; MW] {
    let mut w = [0u128; MW];
    for (i, row) in a.iter().enumerate() {
        let c = (row & x).count_ones();
        w[i / 128] |= (((c & 1) ^ ((c % 3) & 1)) as u128) << (i % 128);
    }
    w
}

#[inline(always)]
fn parity_generic(rows: &[[u128; MW]], w: &[u128; MW]) -> u128 {
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
unsafe fn parity_popcnt(rows: &[[u128; MW]], w: &[u128; MW]) -> u128 {
    parity_generic(rows, w)
}

#[cfg(test)]
mod tests {
    use super::*;
    use dpf_common::aes_tower::Mmo;
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn column_xor_matches_fssnn() {
        let (c, r) = (ColLpn::new(), fssnn::lpn_prg::lpn_prg());
        let mut rng = ChaCha20Rng::seed_from_u64(1);
        for _ in 0..200 {
            let x: u128 = rng.gen();
            assert_eq!(c.eval(x), r.eval(x));
        }
    }

    #[test]
    fn row_wise_matches_fssnn() {
        let (c, r) = (RowLpn::new(), fssnn::lpn_prg::lpn_prg());
        let mut rng = ChaCha20Rng::seed_from_u64(2);
        for _ in 0..200 {
            let x: u128 = rng.gen();
            assert_eq!(c.eval(x), r.eval(x));
            for side in 0..2 {
                assert_eq!(c.eval_side(x, side), r.eval_side(x, side));
            }
        }
    }

    #[test]
    fn aes_fips197() {
        let k: [u8; 16] = std::array::from_fn(|i| i as u8);
        let p: [u8; 16] = std::array::from_fn(|i| (0x11 * i) as u8);
        let y = Mmo::new(k).pi(Block::from_bytes(&p)).to_bytes();
        assert_eq!(y, [0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a]);
    }
}

#[cfg(test)]
mod sbox_tests {
    use crate::maestro::{self, Maestro};
    use crate::triples::{self, TripleCircuit};
    use dpf_common::aes_tower::{sbox, TowerBackend};
    use dpf_common::block::Block;
    use dpf_common::net::run_two_party;
    use dpf_common::ot::CotPair;
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha20Rng;

    fn byte_bits(x: u8) -> [bool; 8] {
        std::array::from_fn(|i| x >> i & 1 == 1)
    }

    fn to_u8(b: &[bool; 8]) -> u8 {
        b.iter().enumerate().fold(0, |a, (i, &x)| a | (x as u8) << i)
    }

    #[test]
    fn maestro_tower_in_the_clear() {
        for a in 0..=255u8 {
            assert_eq!(maestro::sbox_clear(a), sbox(a), "S-box({a})");
        }
    }

    #[test]
    fn bp_circuit_in_the_clear() {
        let c = exp_bp_sbox::boyar_peralta();
        assert_eq!(c.ands(), triples::ANDS_PER_SBOX);
        for a in 0..=255u8 {
            assert_eq!(c.eval(a), sbox(a));
        }
    }

    /// Both backends on all 256 inputs, shared with random masks, in one batch.
    fn check<F, B>(make: F)
    where
        F: Fn(&mut dpf_common::net::Channel, &mut CotPair, &mut ChaCha20Rng) -> B + Send + Sync + Copy + 'static,
        B: TowerBackend<Bit = bool>,
    {
        let mut rng = ChaCha20Rng::seed_from_u64(7);
        let mask: Vec<u8> = (0..256).map(|_| rng.gen()).collect();
        let party = |p: usize, mask: Vec<u8>| {
            move |ch: &mut dpf_common::net::Channel| {
                let mut r = ChaCha20Rng::seed_from_u64(40 + p as u64);
                let delta = Block::random(&mut r).with_lsb(p == 1);
                let mut cot = CotPair::setup(ch, &mut r, delta, false).unwrap();
                let mut be = make(ch, &mut cot, &mut r);
                let bytes: Vec<[bool; 8]> = (0..256).map(|a| byte_bits(if p == 0 { mask[a] } else { a as u8 ^ mask[a] })).collect();
                be.sbox(ch, &bytes).iter().map(to_u8).collect::<Vec<u8>>()
            }
        };
        let (y0, y1) = run_two_party(party(0, mask.clone()), party(1, mask));
        for a in 0..256 {
            assert_eq!(y0[a] ^ y1[a], sbox(a as u8), "S-box({a})");
        }
    }

    #[test]
    fn maestro_2pc_all_inputs() {
        check(|ch, cot, r| {
            let cots = cot.random_cots(ch, 0, 256 * maestro::COTS_PER_SBOX, r).unwrap();
            let mut m = Maestro::new(ch.party(), cots, cot.delta());
            m.preprocess(ch, 256, r);
            m
        });
    }

    #[test]
    fn triples_2pc_all_inputs() {
        check(|ch, cot, r| {
            let k = 256 * triples::ANDS_PER_SBOX;
            let me = ch.party();
            let (a, b) = (cot.random_cots(ch, 0, k, r).unwrap(), cot.random_cots(ch, 1, k, r).unwrap());
            let (sent, recv) = if me == 0 { (a, b) } else { (b, a) };
            TripleCircuit::new(me, exp_bp_sbox::boyar_peralta(), sent, recv, cot.delta())
        });
    }
}
