//! A MAESTRO-style S-box in 2PC: our two-party adaptation of the
//! `F_{2^4}`-tower lookup of MAESTRO (USENIX Sec '25, a three-party protocol).
//!
//! The byte `a` is mapped by a linear isomorphism φ into `F_16[Y]/(Y² + Y + λ)`,
//! `φ(a) = hY + l`, and inverted there as
//! `(hY + l)^{-1} = (h·w)Y + (h + l)·w` with `w = d^{-1}`, `d = λh² + hl + l²`.
//! Squares, scalings, φ and the affine map are linear, so per S-box the
//! interaction is three `F_16` products and one inversion in `F_16`, done as a
//! 16-entry lookup: open `d ⊕ r` against a preprocessed sharing of the
//! one-hot vector `e_r`, then `w = Σ_k e_r[k]·inv(k ⊕ d ⊕ r)` locally.
//!
//! Products use the corrected-COT technique of our OT tower
//! (`dpf_common::aes_tower::OtTower`): party 1 corrects one random COT per
//! bit of its share of each operand, and a cross term `b·s` (b party 1's
//! share, s party 0's) is `Σ_j b_j·(s·x^j)`, one 4-bit message from party 0 per
//! bit of b. Per S-box, three rounds:
//!
//! 1. party 1 corrects `h, l` (8 bits), party 0 sends the cross terms of `h·l`
//!    (2·4·4 = 32 bits);
//! 2. both open `d ⊕ r` (2·4 bits);
//! 3. party 1 corrects `w` (4 bits), party 0 sends the cross terms of `h·w`
//!    and `(h + l)·w` (64 bits),
//!
//! 116 bits and 12 COTs online. Preprocessing builds `e_r` from the shared
//! bits of `r` with the same ANDs-from-COTs: its 11 monomials of degree ≥ 2 in
//! two layers (6 + 5 ANDs at 2 bits each, 4 + 2 corrections), 28 bits and 6
//! COTs, all S-boxes of a batch in the same two rounds.

use dpf_common::aes_tower::TowerBackend;
use dpf_common::block::Block;
use dpf_common::hash::FixedKeyHash;
use dpf_common::net::Channel;
use dpf_common::ot::RandomCots;
use rand::Rng;
use std::sync::OnceLock;

/// COTs per S-box: 0–7 the bits of φ(a) (l in 0–3, h in 4–7), 8–11 w, 12–15
/// the bits of r, 16–17 the monomials r₀r₁ and r₂r₃.
pub const COTS_PER_SBOX: usize = 18;
/// Bits per S-box online and in preprocessing (both parties).
pub const ONLINE_BITS_PER_SBOX: usize = 116;
pub const PRE_BITS_PER_SBOX: usize = 28;
/// Rounds of one AES–MMO call (three per S-box layer).
pub const ROUNDS_PER_CALL: usize = 30;

/// `a·b` in `F_16 = F_2[x]/(x⁴ + x + 1)`.
pub fn mul16(a: u8, b: u8) -> u8 {
    let (mut a, mut b, mut r) = (a & 15, b & 15, 0u8);
    while b != 0 {
        if b & 1 == 1 {
            r ^= a;
        }
        b >>= 1;
        a <<= 1;
        if a & 16 != 0 {
            a ^= 0b1_0011;
        }
    }
    r
}

pub fn inv16(a: u8) -> u8 {
    (0..16u8).find(|&b| mul16(a, b) == 1).unwrap_or(0)
}

struct Tower {
    lambda: u8,
    /// φ on bytes, and φ⁻¹ followed by the linear part of the AES affine map.
    phi: [u8; 256],
    out: [u8; 256],
    inv: [u8; 16],
}

/// `(h₁Y + l₁)(h₂Y + l₂)` with `Y² = Y + λ`, bytes as `h << 4 | l`.
fn tmul(lambda: u8, x: u8, y: u8) -> u8 {
    let (h1, l1, h2, l2) = (x >> 4, x & 15, y >> 4, y & 15);
    let hh = mul16(h1, h2);
    let h = hh ^ mul16(h1, l2) ^ mul16(l1, h2);
    let l = mul16(lambda, hh) ^ mul16(l1, l2);
    h << 4 | l
}

fn affine_lin(x: u8) -> u8 {
    x ^ x.rotate_left(1) ^ x.rotate_left(2) ^ x.rotate_left(3) ^ x.rotate_left(4)
}

fn tower() -> &'static Tower {
    static T: OnceLock<Tower> = OnceLock::new();
    T.get_or_init(|| {
        // Y² + Y + λ is irreducible iff t² + t ≠ λ for every t.
        let lambda = (1..16u8).find(|&l| (0..16u8).all(|t| mul16(t, t) ^ t != l)).unwrap();
        // β: a root of the AES polynomial x⁸ + x⁴ + x³ + x + 1 in the tower.
        let pow = |b: u8, e: u32| (0..e).fold(1u8, |acc, _| tmul(lambda, acc, b));
        let beta = (2..=255u8).find(|&b| pow(b, 8) ^ pow(b, 4) ^ pow(b, 3) ^ b ^ 1 == 0).unwrap();
        let cols: [u8; 8] = std::array::from_fn(|i| pow(beta, i as u32));
        let mut phi = [0u8; 256];
        let mut phi_inv = [0u8; 256];
        for a in 0..256usize {
            let t = (0..8).filter(|&i| a >> i & 1 == 1).fold(0u8, |acc, i| acc ^ cols[i]);
            phi[a] = t;
            phi_inv[t as usize] = a as u8;
        }
        let out = std::array::from_fn(|y| affine_lin(phi_inv[y]));
        Tower { lambda, phi, out, inv: std::array::from_fn(|k| inv16(k as u8)) }
    })
}

fn sq16(x: u8) -> u8 {
    mul16(x, x)
}

/// The S-box by the tower inversion, in the clear.
pub fn sbox_clear(a: u8) -> u8 {
    let tw = tower();
    let t = tw.phi[a as usize];
    let (h, l) = (t >> 4, t & 15);
    let d = mul16(tw.lambda, sq16(h)) ^ mul16(h, l) ^ sq16(l);
    let w = tw.inv[d as usize];
    tw.out[(mul16(h, w) << 4 | mul16(h ^ l, w)) as usize] ^ 0x63
}

fn hash() -> &'static FixedKeyHash {
    static H: OnceLock<FixedKeyHash> = OnceLock::new();
    H.get_or_init(|| FixedKeyHash::new(b"prf-bench/maestr"))
}

/// One cross term `b·s`: S-box, party 1's form ℓ (bit j: COT j of the S-box),
/// party 1's bit b, party 0's payload s. Each party gets a share of `b·s`.
type Cross = (usize, u32, bool, u8);

/// The bits of `x` at `off..off + 4` as forms of single COTs.
fn forms4(off: usize) -> [u32; 4] {
    std::array::from_fn(|j| 1 << (off + j))
}

pub struct Maestro {
    party: usize,
    /// Party 0's COT key Γ (zero at party 1).
    gamma: Block,
    /// Party 0: COT keys q. Party 1: `q ⊕ c·Γ`.
    blocks: Vec<Block>,
    /// Party 1: COT choices c.
    choices: Vec<bool>,
    /// Party 0: party 1's corrections ε so far, per S-box.
    eps: Vec<u32>,
    /// Preprocessed shares `(r, e_r)` per S-box.
    pre: Vec<(u8, u16)>,
    next: usize,
    tweak: u64,
}

impl Maestro {
    /// From random COTs with party 0 as the sender, [`COTS_PER_SBOX`] per S-box.
    pub fn new(party: usize, cots: RandomCots, gamma: Block) -> Self {
        let (blocks, choices, gamma) = match cots {
            RandomCots::Sender(k) => (k, vec![], gamma),
            RandomCots::Receiver(c, m) => (m, c, Block::ZERO),
        };
        assert_eq!(party == 0, choices.is_empty(), "party 0 is the COT sender");
        let n = blocks.len() / COTS_PER_SBOX;
        Maestro { party, gamma, blocks, choices, eps: vec![0; n], pre: vec![], next: 0, tweak: 0 }
    }

    fn form(&self, sbox: usize, l: u32) -> Block {
        let base = COTS_PER_SBOX * sbox;
        let (mut x, mut l) = (Block::ZERO, l);
        while l != 0 {
            x ^= self.blocks[base + l.trailing_zeros() as usize];
            l &= l - 1;
        }
        x
    }

    /// One round: party 1 sends its corrections (`bits[k·n + j]` for the n-th
    /// S-box of `sboxes`, COT `off + j`), party 0 sends ζ for every cross
    /// term (`width` bits each). Returns this party's share of each term.
    fn layer(&mut self, ch: &mut Channel, sboxes: &[usize], off: usize, bits: &[bool], crosses: &[Cross], width: usize) -> Vec<u8> {
        let k = if sboxes.is_empty() { 0 } else { bits.len() / sboxes.len() };
        let tw = self.tweak;
        self.tweak += crosses.len() as u64;
        let mask = ((1u16 << width) - 1) as u8;
        let h = hash();
        let hm = |q: Block, t: usize| (h.h(q, tw + t as u64).0 as u8) & mask;
        if self.party == 0 {
            let m: Vec<(u8, u8)> = crosses
                .iter()
                .enumerate()
                .map(|(t, &(i, l, _, _))| {
                    let q = self.form(i, l);
                    (hm(q, t), hm(q ^ self.gamma, t))
                })
                .collect();
            let zeta: Vec<bool> = crosses
                .iter()
                .zip(&m)
                .flat_map(|(&(_, _, _, s), &(m0, m1))| {
                    let z = m0 ^ m1 ^ s;
                    (0..width).map(move |j| z >> j & 1 == 1)
                })
                .collect();
            ch.send_bits(&zeta);
            let e = ch.recv_bits(bits.len());
            for (n, &i) in sboxes.iter().enumerate() {
                for j in 0..k {
                    self.eps[i] |= (e[k * n + j] as u32) << (off + j);
                }
            }
            crosses.iter().zip(&m).map(|(&(i, l, _, _), &(m0, m1))| if (self.eps[i] & l).count_ones() & 1 == 1 { m1 } else { m0 }).collect()
        } else {
            let e: Vec<bool> = (0..bits.len()).map(|t| bits[t] ^ self.choices[COTS_PER_SBOX * sboxes[t / k] + off + t % k]).collect();
            ch.send_bits(&e);
            let z = ch.recv_bits(crosses.len() * width);
            crosses
                .iter()
                .enumerate()
                .map(|(t, &(i, l, b, _))| {
                    let zt = (0..width).fold(0u8, |acc, j| acc | (z[width * t + j] as u8) << j);
                    hm(self.form(i, l), t) ^ if b { zt } else { 0 }
                })
                .collect()
        }
    }

    /// Shares of `x·y` for `F_16` operands: party 1's share of each is the
    /// value of the forms `fx`, `fy` (one per bit) of its corrected COTs.
    /// Returns the cross terms to put into one [`layer`](Self::layer) and
    /// how to combine them: share = `x_me·y_me ⊕ ⊕ crosses`.
    fn product_crosses(&self, i: usize, x: u8, fx: [u32; 4], y: u8, fy: [u32; 4]) -> [Cross; 8] {
        // Cross(y₁; x₀) = Σ_j y₁_j·(x₀ xʲ) and Cross(x₁; y₀) = Σ_j x₁_j·(y₀ xʲ).
        std::array::from_fn(|t| {
            let (j, first) = (t % 4, t < 4);
            let (b, s, f) = if first { (y, x, fy) } else { (x, y, fx) };
            let s0 = if self.party == 0 { mul16(s, 1 << j) } else { 0 };
            (i, f[j], b >> j & 1 == 1, s0)
        })
    }

    /// Preprocessing for the next `count` S-boxes: shares of a random `r` and of
    /// `e_r`, in two rounds.
    pub fn preprocess<R: Rng>(&mut self, ch: &mut Channel, count: usize, rng: &mut R) {
        let ids: Vec<usize> = (self.pre.len()..self.pre.len() + count).collect();
        assert!(ids.last().map_or(true, |&i| i < self.eps.len()), "COT pool exhausted");
        let r: Vec<u8> = ids.iter().map(|_| rng.gen::<u8>() & 15).collect();
        let me = |b: bool| b; // share bit
        let and_crosses = |i: usize, u: (bool, u32), v: (bool, u32), p: usize| -> [Cross; 2] {
            // u·v = u₀v₀ ⊕ u₁v₁ ⊕ Cross(v₁; u₀) ⊕ Cross(u₁; v₀).
            let s = |b: bool| (p == 0 && b) as u8;
            [(i, v.1, v.0, s(u.0)), (i, u.1, u.0, s(v.0))]
        };
        let p = self.party;
        // Layer A: r₁ corrected (COTs 12–15), the six products r_a r_b.
        let pairs = [(0, 1), (0, 2), (0, 3), (1, 2), (1, 3), (2, 3)];
        let bit = |ri: u8, a: usize| (me(ri >> a & 1 == 1), 1u32 << (12 + a));
        let bits: Vec<bool> = r.iter().flat_map(|&ri| (0..4).map(move |a| ri >> a & 1 == 1)).collect();
        let crosses: Vec<Cross> = ids.iter().zip(&r).flat_map(|(&i, &ri)| pairs.iter().flat_map(move |&(a, b)| and_crosses(i, bit(ri, a), bit(ri, b), p))).collect();
        let c = self.layer(ch, &ids, 12, &bits, &crosses, 1);
        let m2: Vec<[bool; 6]> = r
            .iter()
            .enumerate()
            .map(|(n, &ri)| std::array::from_fn(|q| {
                let (a, b) = pairs[q];
                ((ri >> a & 1) & (ri >> b & 1) == 1) ^ (c[12 * n + 2 * q] ^ c[12 * n + 2 * q + 1] == 1)
            }))
            .collect();
        // Layer B: r₀r₁, r₂r₃ corrected (COTs 16, 17); degree 3 and 4.
        let bits: Vec<bool> = m2.iter().flat_map(|m| [m[0], m[5]]).collect();
        let crosses: Vec<Cross> = ids
            .iter()
            .zip(&r)
            .zip(&m2)
            .flat_map(|((&i, &ri), m)| {
                let (m01, m23) = ((m[0], 1u32 << 16), (m[5], 1u32 << 17));
                [(m01, bit(ri, 2)), (m01, bit(ri, 3)), (bit(ri, 0), m23), (bit(ri, 1), m23), (m01, m23)]
                    .into_iter()
                    .flat_map(move |(u, v)| and_crosses(i, u, v, p))
            })
            .collect();
        let c = self.layer(ch, &ids, 16, &bits, &crosses, 1);
        for (n, (&ri, m)) in r.iter().zip(&m2).enumerate() {
            let rb = |a: usize| ri >> a & 1 == 1;
            let and3 = |q: usize, u: bool, v: bool| (u & v) ^ (c[10 * n + 2 * q] ^ c[10 * n + 2 * q + 1] == 1);
            let (m012, m013, m023, m123, m0123) =
                (and3(0, m[0], rb(2)), and3(1, m[0], rb(3)), and3(2, rb(0), m[5]), and3(3, rb(1), m[5]), and3(4, m[0], m[5]));
            // Monomial m_T for every T ⊆ {0,1,2,3} (m_∅ = 1, party 0's).
            let mono = |t: usize| -> bool {
                match t {
                    0 => p == 0,
                    1 | 2 | 4 | 8 => rb(t.trailing_zeros() as usize),
                    0b0011 => m[0],
                    0b0101 => m[1],
                    0b1001 => m[2],
                    0b0110 => m[3],
                    0b1010 => m[4],
                    0b1100 => m[5],
                    0b0111 => m012,
                    0b1011 => m013,
                    0b1101 => m023,
                    0b1110 => m123,
                    _ => m0123,
                }
            };
            // e_r[k] = Π_a (r_a ⊕ k̄_a) = Σ_T m_T·Π_{a∉T} k̄_a.
            let e = (0..16u16).fold(0u16, |acc, k| {
                let v = (0..16usize).filter(|&t| (0..4).all(|a| t >> a & 1 == 1 || k >> a & 1 == 0)).fold(false, |x, t| x ^ mono(t));
                acc | (v as u16) << k
            });
            self.pre.push((ri, e));
        }
    }
}

impl TowerBackend for Maestro {
    type Bit = bool;

    fn constant(&self, c: bool) -> bool {
        c && self.party == 0
    }

    fn sbox(&mut self, ch: &mut Channel, bytes: &[[bool; 8]]) -> Vec<[bool; 8]> {
        let tw = tower();
        let n = bytes.len();
        let ids: Vec<usize> = (self.next..self.next + n).collect();
        assert!(self.next + n <= self.pre.len(), "preprocess first");
        self.next += n;
        let p = self.party;
        let to_u8 = |b: &[bool; 8]| b.iter().enumerate().fold(0u8, |acc, (i, &x)| acc | (x as u8) << i);
        // Round 1: φ(a) = hY + l corrected (COTs 0–7), the product h·l.
        let t: Vec<u8> = bytes.iter().map(|b| tw.phi[to_u8(b) as usize]).collect();
        let bits: Vec<bool> = t.iter().flat_map(|&x| (0..8).map(move |j| x >> j & 1 == 1)).collect();
        let crosses: Vec<Cross> = ids.iter().zip(&t).flat_map(|(&i, &x)| self.product_crosses(i, x >> 4, forms4(4), x & 15, forms4(0))).collect();
        let c = self.layer(ch, &ids, 0, &bits, &crosses, 4);
        let xor8 = |c: &[u8]| c.iter().fold(0u8, |a, &b| a ^ b);
        let d: Vec<u8> = t
            .iter()
            .enumerate()
            .map(|(k, &x)| {
                let (h, l) = (x >> 4, x & 15);
                mul16(tw.lambda, sq16(h)) ^ mul16(h, l) ^ xor8(&c[8 * k..8 * k + 8]) ^ sq16(l)
            })
            .collect();
        // Round 2: open d ⊕ r; w = Σ_k e_r[k]·inv(k ⊕ d ⊕ r) locally.
        let mine: Vec<bool> = d.iter().zip(&ids).flat_map(|(&dk, &i)| {
            let v = dk ^ self.pre[i].0;
            (0..4).map(move |j| v >> j & 1 == 1)
        }).collect();
        ch.send_bits(&mine);
        let theirs = ch.recv_bits(4 * n);
        let w: Vec<u8> = ids
            .iter()
            .enumerate()
            .map(|(k, &i)| {
                let o = (0..4).fold(0u8, |acc, j| acc | ((mine[4 * k + j] ^ theirs[4 * k + j]) as u8) << j);
                let e = self.pre[i].1;
                (0..16u8).filter(|&q| e >> q & 1 == 1).fold(0u8, |acc, q| acc ^ tw.inv[(q ^ o) as usize])
            })
            .collect();
        // Round 3: w corrected (COTs 8–11), the products h·w and (h + l)·w.
        let bits: Vec<bool> = w.iter().flat_map(|&x| (0..4).map(move |j| x >> j & 1 == 1)).collect();
        let hl: [u32; 4] = std::array::from_fn(|j| 1 << j | 1 << (4 + j));
        let crosses: Vec<Cross> = ids
            .iter()
            .zip(t.iter().zip(&w))
            .flat_map(|(&i, (&x, &wk))| {
                let (h, l) = (x >> 4, x & 15);
                let mut v = self.product_crosses(i, h, forms4(4), wk, forms4(8)).to_vec();
                v.extend(self.product_crosses(i, h ^ l, hl, wk, forms4(8)));
                v
            })
            .collect();
        let c = self.layer(ch, &ids, 8, &bits, &crosses, 4);
        (0..n)
            .map(|k| {
                let (h, l, wk) = (t[k] >> 4, t[k] & 15, w[k]);
                let bh = mul16(h, wk) ^ xor8(&c[16 * k..16 * k + 8]);
                let bl = mul16(h ^ l, wk) ^ xor8(&c[16 * k + 8..16 * k + 16]);
                let o = tw.out[(bh << 4 | bl) as usize] ^ if p == 0 { 0x63 } else { 0 };
                std::array::from_fn(|j| o >> j & 1 == 1)
            })
            .collect()
    }
}
