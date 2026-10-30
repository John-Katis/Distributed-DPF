//! Fixed-key AES–MMO, in the clear and in 2PC on XOR-shared bits, with the
//! S-box in the tower field `F_{2^8} ≅ F_{2^4}[Z]/(Z² + Z + η)`,
//! `F_{2^4} ≅ F_{2^2}[Y]/(Y² + Y + θ)` (Canright, CHES'05).
//!
//! With a public AES key every operation but the S-box inversion is
//! F2-affine, so it is applied to each party's share locally (a public
//! constant XORed in by party 0). The inversion in `F_{2^8}` reduces to three
//! products and one inversion in `F_{2^4}`, and each of those to three products
//! in `F_{2^2} = F4` (Karatsuba; the innermost inversion `d^{-1} = d²` is free):
//!
//! ```text
//! S-box:  (a_h, a_l) = φ(a)          local
//!         p = a_h·a_l                  Mul16: 3 products   (depth 1)
//!         d = η a_h² + p + a_l²        local
//!         w = d^{-1}                   Inv16: 1 + 2 products (depth 2, 3)
//!         b_h = a_h·w, b' = a_l·w      Mul16 ×2: 6 products (depth 4)
//!         S(a) = M·φ^{-1}(b_h, b_h + b') ⊕ 0x63
//! ```
//!
//! That is 12 F4 products at depth 4 per S-box, 160 S-boxes per AES-128 call:
//! [`PRODUCTS_PER_CALL`] = 1,920 products in [`ROUNDS_PER_CALL`] = 40 rounds.
//! The S-boxes are the only interaction; [`TowerBackend`] computes them, four
//! rounds per batch. Its implementation is [`OtTower`], the paper's OT tower
//! (Figures "Π_SBox" and "ANDs from COTs"), semi-honest on XOR shares: each
//! F4 product is three ANDs over F2 (Karatsuba), 36 per S-box, and every AND
//! is computed from Ferret COTs under party 0's key Γ. Every AND input is an
//! F2-linear form of party 1's share of one of four values, `φ(a)`, `d`, `e`
//! and `w`; party 1 corrects one random COT per bit of those (18 bits and
//! COTs per S-box) and the COT of any linear form is the XOR of the COTs it
//! selects. A cross term costs one bit from party 0: 90 bits per S-box,
//! [`COTS_PER_CALL`] = 2,880 COTs per call.
//!
//! The constants are those of the paper's appendix: `θ = 0xbc`, `Y = 0x5c`,
//! `η = θY = 0xb0`, `ζ = 0xf2` in `F_2[X]/(X⁸ + X⁴ + X³ + X + 1)`, and the F4
//! element `h·θ + l` is the bit pair of [`crate::f4`] (`θ = ω`).
//!
//! The hash is `H_K(x) = π_K(σ(x)) ⊕ σ(x)` with `π_K` AES-128 under a public key
//! and σ the orthomorphism of GKWY20 ([`crate::hash::sigma`]).

// `aes` 0.8 re-exports generic-array 0.14, whose newest patch release marks it deprecated.
#![allow(deprecated)]

use crate::block::Block;
use crate::f4;
use crate::hash::{sigma, FixedKeyHash};
use crate::net::Channel;
use crate::ot::RandomCots;
use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockEncrypt, KeyInit};
use aes::Aes128;
use std::ops::BitXor;
use std::sync::OnceLock;

/// F4 products per AES-128 call (160 S-boxes × 12).
pub const PRODUCTS_PER_CALL: usize = 160 * 12;
/// COTs per S-box of [`OtTower`]: one per bit of `φ(a)`, `d`, `e` and `w`.
pub const COTS_PER_SBOX: usize = 18;
/// COTs per AES-128 call of [`OtTower`].
pub const COTS_PER_CALL: usize = 160 * COTS_PER_SBOX;
/// ANDs per AES-128 call of [`OtTower`] (three per F4 product).
pub const ANDS_PER_CALL: usize = 3 * PRODUCTS_PER_CALL;
/// Rounds per AES-128 call (10 AES rounds × multiplicative depth 4).
pub const ROUNDS_PER_CALL: usize = 40;

/// θ, a root of `X² + X + 1` in `F_{2^8}` (the F4 generator ω).
pub const THETA: u8 = 0xbc;
/// Y, a root of `X² + X + θ`.
pub const Y: u8 = 0x5c;
/// ζ, a root of `X² + X + η` with `η = θY`.
pub const ZETA: u8 = 0xf2;

/// Multiplication in `F_2[X]/(X⁸ + X⁴ + X³ + X + 1)`.
pub fn gf256_mul(mut a: u8, mut b: u8) -> u8 {
    let mut r = 0u8;
    while b != 0 {
        if b & 1 == 1 {
            r ^= a;
        }
        let hi = a & 0x80 != 0;
        a <<= 1;
        if hi {
            a ^= 0x1b;
        }
        b >>= 1;
    }
    r
}

/// The AES S-box, from its definition.
pub fn sbox(a: u8) -> u8 {
    let inv = (1..=255u8).find(|&x| gf256_mul(a, x) == 1).unwrap_or(0);
    affine(inv)
}

/// `M·a ⊕ 0x63`.
fn affine(a: u8) -> u8 {
    let mut r = 0x63u8;
    for i in 0..8 {
        let bit = (a >> i ^ a >> ((i + 4) % 8) ^ a >> ((i + 5) % 8) ^ a >> ((i + 6) % 8) ^ a >> ((i + 7) % 8)) & 1;
        r ^= bit << i;
    }
    r
}

/// An 8×8 matrix over F2: `rows[i]` has bit j set if output bit i depends on
/// input bit j.
type Mat8 = [u8; 8];

fn mat_apply(m: &Mat8, x: u8) -> u8 {
    (0..8).fold(0, |acc, i| acc | (((m[i] & x).count_ones() & 1) as u8) << i)
}

/// The matrix of a linear map given by its images of the unit vectors.
fn mat_from_columns(cols: [u8; 8]) -> Mat8 {
    let mut m = [0u8; 8];
    for (j, c) in cols.iter().enumerate() {
        for (i, row) in m.iter_mut().enumerate() {
            *row |= (c >> i & 1) << j;
        }
    }
    m
}

fn mat_mul(a: &Mat8, b: &Mat8) -> Mat8 {
    // Columns of a·b are a applied to the columns of b.
    let cols: [u8; 8] = std::array::from_fn(|j| mat_apply(a, mat_apply(b, 1 << j)));
    mat_from_columns(cols)
}

fn mat_inv(m: &Mat8) -> Mat8 {
    // The inverse of a bijection on bytes, read off its table.
    let mut inv = [0u8; 256];
    for x in 0..=255u8 {
        inv[mat_apply(m, x) as usize] = x;
    }
    mat_from_columns(std::array::from_fn(|j| inv[1 << j]))
}

/// The linear maps of the tower S-box.
struct Tower {
    /// φ: byte → (t_0 … t_7), t_0..t_3 = a_l, t_4..t_7 = a_h.
    phi: Mat8,
    /// M·φ^{-1}, the output map before `⊕ 0x63`.
    out: Mat8,
}

fn tower() -> &'static Tower {
    static T: OnceLock<Tower> = OnceLock::new();
    T.get_or_init(|| {
        let ty = gf256_mul(THETA, Y);
        let basis = [1, THETA, Y, ty, ZETA, gf256_mul(THETA, ZETA), gf256_mul(Y, ZETA), gf256_mul(ty, ZETA)];
        let phi_inv = mat_from_columns(basis);
        let m = mat_from_columns(std::array::from_fn(|j| affine(1 << j) ^ 0x63));
        Tower { phi: mat_inv(&phi_inv), out: mat_mul(&m, &phi_inv) }
    })
}

/// A share of one bit. `^` is the local XOR of two sharings.
pub trait ShareBit: Copy + Default + Send + Sync + BitXor<Output = Self> {}

impl ShareBit for bool {}

/// A shared F4 element `h·ω + l`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct F4Sh<B> {
    pub h: B,
    pub l: B,
}

impl<B: ShareBit> F4Sh<B> {
    #[inline]
    pub fn add(self, o: Self) -> Self {
        F4Sh { h: self.h ^ o.h, l: self.l ^ o.l }
    }

    /// `c·x` for a public `c ∈ F4` (F2-linear on the bits).
    #[inline]
    pub fn scale(self, c: u8) -> Self {
        match c & 3 {
            0 => F4Sh::default(),
            1 => self,
            // ω(hω + l) = (h + l)ω + h.
            2 => F4Sh { h: self.h ^ self.l, l: self.h },
            // ω²(hω + l) = lω + (h + l).
            _ => F4Sh { h: self.l, l: self.h ^ self.l },
        }
    }

    /// `x²`.
    #[inline]
    pub fn sq(self) -> Self {
        F4Sh { h: self.h, l: self.h ^ self.l }
    }
}

impl F4Sh<bool> {
    #[inline]
    pub fn to_u8(self) -> u8 {
        (self.h as u8) << 1 | self.l as u8
    }

    #[inline]
    pub fn from_u8(x: u8) -> Self {
        F4Sh { h: x & 2 != 0, l: x & 1 != 0 }
    }
}

/// The interactive part of the circuit: the S-boxes.
pub trait TowerBackend {
    type Bit: ShareBit;

    /// This party's share of the public bit `c`.
    fn constant(&self, c: bool) -> Self::Bit;

    /// S-boxes of a batch of shared bytes, in four rounds.
    fn sbox(&mut self, ch: &mut Channel, bytes: &[[Self::Bit; 8]]) -> Vec<[Self::Bit; 8]>;
}

/// An element of `F_{2^4}` as `x_1·Y + x_0`.
#[derive(Clone, Copy, Default)]
struct F16<B> {
    x1: F4Sh<B>,
    x0: F4Sh<B>,
}

impl<B: ShareBit> F16<B> {
    fn add(self, o: Self) -> Self {
        F16 { x1: self.x1.add(o.x1), x0: self.x0.add(o.x0) }
    }

    /// `(x_1 Y + x_0)² = x_1² Y + (θ x_1² + x_0²)`.
    fn sq(self) -> Self {
        let s1 = self.x1.sq();
        F16 { x1: s1, x0: s1.scale(f4::OMEGA).add(self.x0.sq()) }
    }

    /// `η·x` with `η = θY`: `(θ(x_1 + x_0), θ² x_1)`.
    fn mul_eta(self) -> Self {
        F16 { x1: self.x1.add(self.x0).scale(f4::OMEGA), x0: self.x1.scale(f4::OMEGA2) }
    }
}

/// Byte bits `(b_0, …, b_7)` → the pair `(a_h, a_l)` after φ.
fn split<B: ShareBit>(t: &[B; 8]) -> (F16<B>, F16<B>) {
    let f = |h: B, l: B| F4Sh { h, l };
    (F16 { x1: f(t[7], t[6]), x0: f(t[5], t[4]) }, F16 { x1: f(t[3], t[2]), x0: f(t[1], t[0]) })
}

fn join<B: ShareBit>(hi: F16<B>, lo: F16<B>) -> [B; 8] {
    [lo.x0.l, lo.x0.h, lo.x1.l, lo.x1.h, hi.x0.l, hi.x0.h, hi.x1.l, hi.x1.h]
}

fn lin8<B: ShareBit>(m: &Mat8, x: &[B; 8]) -> [B; 8] {
    std::array::from_fn(|i| (0..8).filter(|&j| m[i] >> j & 1 == 1).fold(B::default(), |acc, j| acc ^ x[j]))
}

#[cfg(test)]
/// The tower S-box in the clear: the same steps on plain F4 elements.
pub fn sbox_tower(a: u8) -> u8 {
    let tw = tower();
    let bits: [bool; 8] = std::array::from_fn(|i| mat_apply(&tw.phi, a) >> i & 1 == 1);
    let (ah, al) = split(&bits);
    let m16 = |x: F16<bool>, y: F16<bool>| {
        let mul = |u: F4Sh<bool>, v: F4Sh<bool>| F4Sh::from_u8(f4::mul(u.to_u8(), v.to_u8()));
        let (m1, m0, m2) = (mul(x.x1, y.x1), mul(x.x0, y.x0), mul(x.x1.add(x.x0), y.x1.add(y.x0)));
        F16 { x1: m2.add(m0), x0: m1.scale(f4::OMEGA).add(m0) }
    };
    let d = ah.sq().mul_eta().add(m16(ah, al)).add(al.sq());
    let mul = |u: F4Sh<bool>, v: F4Sh<bool>| F4Sh::from_u8(f4::mul(u.to_u8(), v.to_u8()));
    let e = d.x1.sq().scale(f4::OMEGA).add(mul(d.x1, d.x0)).add(d.x0.sq()).sq();
    let w = F16 { x1: mul(d.x1, e), x0: mul(d.x1.add(d.x0), e) };
    let (bh, b2) = (m16(ah, w), m16(al, w));
    let o = join(bh, bh.add(b2));
    let byte = o.iter().enumerate().fold(0u8, |acc, (i, &b)| acc | (b as u8) << i);
    mat_apply(&tw.out, byte) ^ 0x63
}

/// AES-128 round keys for `key`.
pub fn key_schedule(key: [u8; 16]) -> [[u8; 16]; 11] {
    let mut rk = [[0u8; 16]; 11];
    rk[0] = key;
    let mut rcon = 1u8;
    for r in 1..11 {
        let p = rk[r - 1];
        let mut t = [p[13], p[14], p[15], p[12]];
        for b in t.iter_mut() {
            *b = sbox(*b);
        }
        t[0] ^= rcon;
        rcon = gf256_mul(rcon, 2);
        for c in 0..4 {
            for i in 0..4 {
                let prev = if c == 0 { t[i] } else { rk[r][4 * (c - 1) + i] };
                rk[r][4 * c + i] = p[4 * c + i] ^ prev;
            }
        }
    }
    rk
}

/// `xtime` (multiplication by X in `F_{2^8}`) on the bits of a shared byte.
fn xtime<B: ShareBit>(a: &[B; 8]) -> [B; 8] {
    [a[7], a[0] ^ a[7], a[1], a[2] ^ a[7], a[3] ^ a[7], a[4], a[5], a[6]]
}

fn xor8<B: ShareBit>(a: &[B; 8], b: &[B; 8]) -> [B; 8] {
    std::array::from_fn(|i| a[i] ^ b[i])
}

/// A fixed public AES-128 key and its MMO hash `H(x) = π(σ(x)) ⊕ σ(x)`.
#[derive(Clone)]
pub struct Mmo {
    aes: Aes128,
    rk: [[u8; 16]; 11],
}

/// A shared 128-bit value, bit i of the block in position i.
pub type Shared128<B> = [B; 128];

impl Mmo {
    pub fn new(key: [u8; 16]) -> Self {
        Mmo { aes: Aes128::new(GenericArray::from_slice(&key)), rk: key_schedule(key) }
    }

    /// `π_K(x)`.
    pub fn pi(&self, x: Block) -> Block {
        let mut g = GenericArray::from(x.to_bytes());
        self.aes.encrypt_block(&mut g);
        Block::from_bytes(g.as_slice())
    }

    /// `H(x) = π(σ(x)) ⊕ σ(x)`.
    #[inline]
    pub fn h(&self, x: Block) -> Block {
        let s = sigma(x);
        self.pi(s) ^ s
    }

    /// `out[i] = H(xs[i])`, batched.
    pub fn h_many(&self, xs: &[Block], out: &mut [Block]) {
        assert_eq!(xs.len(), out.len());
        const BATCH: usize = 64;
        let mut buf = [GenericArray::default(); BATCH];
        let mut sig = [Block::ZERO; BATCH];
        for (s, d) in xs.chunks(BATCH).zip(out.chunks_mut(BATCH)) {
            for (i, &x) in s.iter().enumerate() {
                sig[i] = sigma(x);
                buf[i] = GenericArray::from(sig[i].to_bytes());
            }
            self.aes.encrypt_blocks(&mut buf[..s.len()]);
            for i in 0..s.len() {
                d[i] = Block::from_bytes(buf[i].as_slice()) ^ sig[i];
            }
        }
    }

    #[cfg(test)]
    /// The round keys (public).
    pub fn round_keys(&self) -> &[[u8; 16]; 11] {
        &self.rk
    }
}

/// XOR shares of a public block: party 0's share is the block.
pub fn share_const<K: TowerBackend>(be: &K, c: Block) -> Shared128<K::Bit> {
    std::array::from_fn(|i| be.constant(c.bit(i)))
}

/// Bits of this party's XOR share `x` (semi-honest sharing).
pub fn bits_of(x: Block) -> Shared128<bool> {
    std::array::from_fn(|i| x.bit(i))
}

/// The block of a [`Shared128<bool>`].
pub fn block_of(x: &Shared128<bool>) -> Block {
    Block::from_bits(x)
}

/// `⟨H_{K_j}(x_j)⟩` for every job `(mmo_j, ⟨x_j⟩)`, all jobs in the same
/// [`ROUNDS_PER_CALL`] rounds (each job may use its own key).
pub fn mmo_shared<K: TowerBackend>(be: &mut K, ch: &mut Channel, jobs: &[(&Mmo, Shared128<K::Bit>)]) -> Vec<Shared128<K::Bit>> {
    let sig = |x: &Shared128<K::Bit>| -> Shared128<K::Bit> { std::array::from_fn(|i| if i < 64 { x[i] ^ x[64 + i] } else { x[i - 64] }) };
    let us: Vec<Shared128<K::Bit>> = jobs.iter().map(|(_, x)| sig(x)).collect();
    let rk: Vec<Vec<Shared128<K::Bit>>> = jobs
        .iter()
        .map(|(m, _)| m.rk.iter().map(|k| share_const(be, Block::from_bytes(k))).collect())
        .collect();
    let xor = |a: &Shared128<K::Bit>, b: &Shared128<K::Bit>| -> Shared128<K::Bit> { std::array::from_fn(|i| a[i] ^ b[i]) };
    let mut v: Vec<Shared128<K::Bit>> = us.iter().zip(&rk).map(|(u, k)| xor(u, &k[0])).collect();
    for r in 1..=10 {
        // SubBytes on all 16·jobs bytes at once.
        let bytes: Vec<[K::Bit; 8]> = v.iter().flat_map(|s| (0..16).map(move |j| std::array::from_fn(|i| s[8 * j + i]))).collect();
        let sb = be.sbox(ch, &bytes);
        for (job, s) in v.iter_mut().enumerate() {
            // ShiftRows: state byte r + 4c takes byte r + 4((c + r) mod 4).
            let mut st: [[K::Bit; 8]; 16] = std::array::from_fn(|j| sb[16 * job + (j % 4 + 4 * ((j / 4 + j % 4) % 4))]);
            if r < 10 {
                for c in 0..4 {
                    let a: [[K::Bit; 8]; 4] = std::array::from_fn(|i| st[4 * c + i]);
                    let t: [[K::Bit; 8]; 4] = std::array::from_fn(|i| xtime(&a[i]));
                    for i in 0..4 {
                        // b_i = 2a_i ⊕ 3a_{i+1} ⊕ a_{i+2} ⊕ a_{i+3}.
                        let (a1, a2, a3) = (&a[(i + 1) % 4], &a[(i + 2) % 4], &a[(i + 3) % 4]);
                        st[4 * c + i] = xor8(&xor8(&t[i], &xor8(&t[(i + 1) % 4], a1)), &xor8(a2, a3));
                    }
                }
            }
            let k = &rk[job][r];
            *s = std::array::from_fn(|i| st[i / 8][i % 8] ^ k[i]);
        }
    }
    v.iter().zip(&us).map(|(x, u)| xor(x, u)).collect()
}

/// A share bit of the OT tower together with the F2-linear form of party 1's
/// share that it is: bit j of `l` is set if it depends on bit j of the
/// S-box's corrected values (`φ(a)` in bits 0–7, `d` in 8–11, `e` in 12–13,
/// `w` in 14–17). Constants are party 0's alone, so `l` tracks party 1's bit
/// exactly; AND outputs, which are no linear form, have `l = 0` and are never
/// an AND input before they are corrected.
#[derive(Clone, Copy, Default)]
struct Sym {
    s: bool,
    l: u32,
}

impl BitXor for Sym {
    type Output = Sym;

    #[inline]
    fn bitxor(self, o: Sym) -> Sym {
        Sym { s: self.s ^ o.s, l: self.l ^ o.l }
    }
}

impl ShareBit for Sym {}

impl Sym {
    /// A bit corrected as COT `j` of its S-box.
    #[inline]
    fn fresh(self, j: usize) -> Sym {
        Sym { s: self.s, l: 1 << j }
    }
}

/// The hash `H(τ, x)` that turns a COT into a random OT, one bit per tweak τ.
fn tower_hash() -> &'static FixedKeyHash {
    static H: OnceLock<FixedKeyHash> = OnceLock::new();
    H.get_or_init(|| FixedKeyHash::new(b"dpf-common/otTwr"))
}

/// The paper's OT tower: semi-honest S-boxes on XOR shares, every AND from
/// random COTs under party 0's key Γ (party 0 the sender, party 1 the
/// receiver), [`COTS_PER_SBOX`] per S-box, consumed front to back.
///
/// An AND `u·v` is `u_0v_0 ⊕ u_1v_1 ⊕ Cross(v_1; u_0) ⊕ Cross(u_1; v_0)`. In
/// `Cross(b; s)` party 1 holds b, a linear form ℓ of its corrected bits, and
/// party 0 holds s; the COT of ℓ is the XOR of the COTs ℓ selects, `q` at
/// party 0 and `(c, q ⊕ c·Γ)` at party 1, and hashing it under a fresh tweak τ
/// gives `m_0 = H(τ, q)`, `m_1 = H(τ, q ⊕ Γ)` and `m_c`. Party 1 has sent the
/// corrections `ε = v_1 ⊕ c` of its bits, so `b ⊕ c = ℓ(ε)`; party 0 sends `ζ
/// = m_0 ⊕ m_1 ⊕ s` and outputs `m_{ℓ(ε)}`, party 1 outputs `m_c ⊕ b·ζ`. ζ
/// does not depend on ε, so in each of the four layers party 1's corrections
/// and party 0's ζ travel in the same round.
pub struct OtTower {
    party: usize,
    /// Γ at party 0, zero at party 1.
    gamma: Block,
    /// Party 0: the COT keys `q_j`. Party 1: `q_j ⊕ c_j·Γ`.
    blocks: Vec<Block>,
    /// Party 1: the choices `c_j`; empty at party 0.
    choices: Vec<bool>,
    next: usize,
    tweak: u64,
    /// ANDs computed so far.
    pub ands: usize,
}

impl OtTower {
    /// From random COTs with party 0 as the sender (`CotPair::random_cots(ch,
    /// 0, m)`); `gamma` is party 0's COT key (ignored at party 1).
    pub fn new(party: usize, cots: RandomCots, gamma: Block) -> Self {
        let (blocks, choices, gamma) = match cots {
            RandomCots::Sender(k) => {
                assert_eq!(party, 0, "party 0 is the sender");
                (k, vec![], gamma)
            }
            RandomCots::Receiver(c, m) => {
                assert_eq!(party, 1, "party 1 is the receiver");
                (m, c, Block::ZERO)
            }
        };
        OtTower { party, gamma, blocks, choices, next: 0, tweak: 0, ands: 0 }
    }

    /// COTs left.
    pub fn remaining(&self) -> usize {
        self.blocks.len() - self.next
    }

    /// The COT block of the linear form `l` of the S-box whose COTs start at `base`.
    #[inline]
    fn form(&self, base: usize, l: u32) -> Block {
        let mut x = Block::ZERO;
        let mut l = l;
        while l != 0 {
            x ^= self.blocks[base + l.trailing_zeros() as usize];
            l &= l - 1;
        }
        x
    }

    /// One layer of every S-box of a batch: party 1 corrects the `bits` of
    /// each S-box (its `bits.len() / n` bits, as COTs `off..` of that S-box),
    /// and both parties compute the F4 products `prods` (S-box index, x, y),
    /// in one round. `eps` keeps party 0's corrections per S-box.
    fn layer(&mut self, ch: &mut Channel, base: usize, eps: &mut [u32], off: usize, bits: &[bool], prods: &[(usize, F4Sh<Sym>, F4Sh<Sym>)]) -> Vec<F4Sh<Sym>> {
        let n = eps.len();
        let k = bits.len() / n;
        // Three ANDs per product (Karatsuba), two cross terms per AND: (S-box,
        // ℓ = party 1's form, party 1's bit, party 0's bit).
        let mut ands = Vec::with_capacity(3 * prods.len());
        for &(i, x, y) in prods {
            ands.push((i, x.h, y.h));
            ands.push((i, x.l, y.l));
            ands.push((i, x.h ^ x.l, y.h ^ y.l));
        }
        self.ands += ands.len();
        let crosses: Vec<(usize, u32, bool, bool)> = ands.iter().flat_map(|&(i, u, v)| [(i, v.l, v.s, u.s), (i, u.l, u.s, v.s)]).collect();
        let tw = self.tweak;
        self.tweak += crosses.len() as u64;
        let h = tower_hash();
        let at = |i: usize| base + COTS_PER_SBOX * i;
        let out: Vec<bool> = if self.party == 0 {
            let m: Vec<(bool, bool)> = crosses
                .iter()
                .enumerate()
                .map(|(t, &(i, l, _, _))| {
                    let q = self.form(at(i), l);
                    (h.h(q, tw + t as u64).lsb(), h.h(q ^ self.gamma, tw + t as u64).lsb())
                })
                .collect();
            let zeta: Vec<bool> = crosses.iter().zip(&m).map(|(&(_, _, _, s), &(m0, m1))| m0 ^ m1 ^ s).collect();
            ch.send_bits(&zeta);
            let e = ch.recv_bits(bits.len());
            for (i, ei) in eps.iter_mut().enumerate() {
                for j in 0..k {
                    *ei |= (e[k * i + j] as u32) << (off + j);
                }
            }
            crosses.iter().zip(&m).map(|(&(i, l, _, _), &(m0, m1))| if (eps[i] & l).count_ones() & 1 == 1 { m1 } else { m0 }).collect()
        } else {
            let e: Vec<bool> = bits.iter().enumerate().map(|(t, &v)| v ^ self.choices[at(t / k) + off + t % k]).collect();
            ch.send_bits(&e);
            let zeta = ch.recv_bits(crosses.len());
            crosses
                .iter()
                .enumerate()
                .map(|(t, &(i, l, b, _))| h.h(self.form(at(i), l), tw + t as u64).lsb() ^ (b && zeta[t]))
                .collect()
        };
        let and: Vec<bool> = ands.iter().zip(out.chunks(2)).map(|(&(_, u, v), c)| (u.s && v.s) ^ c[0] ^ c[1]).collect();
        let sym = |s: bool| Sym { s, l: 0 };
        // (x_h y_h, x_l y_l, (x_h + x_l)(y_h + y_l)) = (n_1, n_0, n_2) → (n_2 + n_0)ω + (n_1 + n_0).
        and.chunks(3).map(|z| F4Sh { h: sym(z[2] ^ z[1]), l: sym(z[0] ^ z[1]) }).collect()
    }
}

/// The products of Karatsuba in `F_{2^4}` for each `(S-box, x, y)`: three F4
/// products each, combined by [`karatsuba16`].
fn mul16_prods(xy: &[(usize, F16<Sym>, F16<Sym>)]) -> Vec<(usize, F4Sh<Sym>, F4Sh<Sym>)> {
    xy.iter().flat_map(|&(i, u, v)| [(i, u.x1, v.x1), (i, u.x0, v.x0), (i, u.x1.add(u.x0), v.x1.add(v.x0))]).collect()
}

fn karatsuba16(m: &[F4Sh<Sym>]) -> Vec<F16<Sym>> {
    m.chunks(3).map(|m| F16 { x1: m[2].add(m[1]), x0: m[0].scale(f4::OMEGA).add(m[1]) }).collect()
}

impl TowerBackend for OtTower {
    type Bit = bool;

    fn constant(&self, c: bool) -> bool {
        c && self.party == 0
    }

    fn sbox(&mut self, ch: &mut Channel, bytes: &[[bool; 8]]) -> Vec<[bool; 8]> {
        let n = bytes.len();
        assert!(self.remaining() >= COTS_PER_SBOX * n, "COT pool exhausted");
        let base = self.next;
        self.next += COTS_PER_SBOX * n;
        let tw = tower();
        let mut eps = vec![0u32; n];
        // Layer 1: φ(a) corrected (COTs 0–7), p = a_h·a_l, then the norm d.
        let t: Vec<[Sym; 8]> = bytes
            .iter()
            .map(|b| {
                let t = lin8(&tw.phi, b);
                std::array::from_fn(|j| Sym { s: t[j], l: 1 << j })
            })
            .collect();
        let (ah, al): (Vec<_>, Vec<_>) = t.iter().map(split).unzip();
        let bits: Vec<bool> = t.iter().flat_map(|t| t.map(|v| v.s)).collect();
        let xy: Vec<_> = (0..n).map(|i| (i, ah[i], al[i])).collect();
        let p = karatsuba16(&self.layer(ch, base, &mut eps, 0, &bits, &mul16_prods(&xy)));
        // Layer 2: d corrected (COTs 8–11), the product x_1·x_0 of its F4 norm.
        let d: Vec<F16<Sym>> = (0..n)
            .map(|i| {
                let d = ah[i].sq().mul_eta().add(p[i]).add(al[i].sq());
                F16 { x1: F4Sh { h: d.x1.h.fresh(8), l: d.x1.l.fresh(9) }, x0: F4Sh { h: d.x0.h.fresh(10), l: d.x0.l.fresh(11) } }
            })
            .collect();
        let bits: Vec<bool> = d.iter().flat_map(|d| [d.x1.h.s, d.x1.l.s, d.x0.h.s, d.x0.l.s]).collect();
        let prods: Vec<_> = (0..n).map(|i| (i, d[i].x1, d[i].x0)).collect();
        let m = self.layer(ch, base, &mut eps, 8, &bits, &prods);
        // Layer 3: e = N(d)^{-1} = N(d)² corrected (COTs 12–13), w = (x_1 e, (x_1 + x_0) e).
        let e: Vec<F4Sh<Sym>> = (0..n)
            .map(|i| {
                let (x1, x0) = (d[i].x1, d[i].x0);
                let e = x1.sq().scale(f4::OMEGA).add(m[i]).add(x0.sq()).sq();
                F4Sh { h: e.h.fresh(12), l: e.l.fresh(13) }
            })
            .collect();
        let bits: Vec<bool> = e.iter().flat_map(|e| [e.h.s, e.l.s]).collect();
        let prods: Vec<_> = (0..n).flat_map(|i| [(i, d[i].x1, e[i]), (i, d[i].x1.add(d[i].x0), e[i])]).collect();
        let we = self.layer(ch, base, &mut eps, 12, &bits, &prods);
        // Layer 4: w corrected (COTs 14–17), b_h = a_h·w and b' = a_l·w.
        let w: Vec<F16<Sym>> = we
            .chunks(2)
            .map(|c| F16 { x1: F4Sh { h: c[0].h.fresh(14), l: c[0].l.fresh(15) }, x0: F4Sh { h: c[1].h.fresh(16), l: c[1].l.fresh(17) } })
            .collect();
        let bits: Vec<bool> = w.iter().flat_map(|w| [w.x1.h.s, w.x1.l.s, w.x0.h.s, w.x0.l.s]).collect();
        let xy: Vec<_> = (0..n).flat_map(|i| [(i, ah[i], w[i]), (i, al[i], w[i])]).collect();
        let bb = karatsuba16(&self.layer(ch, base, &mut eps, 14, &bits, &mul16_prods(&xy)));
        let c63 = std::array::from_fn::<_, 8, _>(|i| self.constant(0x63 >> i & 1 == 1));
        (0..n)
            .map(|i| {
                let (bh, b2) = (bb[2 * i], bb[2 * i + 1]);
                let o = lin8(&tw.out, &join(bh, bh.add(b2)));
                std::array::from_fn(|k| o[k].s ^ c63[k])
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::run_two_party;
    use crate::ot::CotPair;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn constants_satisfy_the_tower() {
        assert_eq!(gf256_mul(THETA, THETA) ^ THETA, 1);
        assert_eq!(gf256_mul(Y, Y) ^ Y, THETA);
        assert_eq!(gf256_mul(ZETA, ZETA) ^ ZETA, gf256_mul(THETA, Y));
        assert_eq!(gf256_mul(THETA, Y), 0xb0);
        // φ as printed in the appendix (row i = output bit i, column j = input bit j).
        let rows = ["11001110", "00011100", "01000010", "00010011", "00001110", "00110000", "01111011", "00000101"];
        for (i, r) in rows.iter().enumerate() {
            let want = r.bytes().enumerate().fold(0u8, |acc, (j, c)| acc | ((c - b'0') << j));
            assert_eq!(tower().phi[i], want, "row {i} of φ");
        }
    }

    #[test]
    fn tower_sbox_is_the_aes_sbox() {
        for a in 0..=255u8 {
            assert_eq!(sbox_tower(a), sbox(a), "S({a:#04x})");
        }
        assert_eq!(sbox(0x53), 0xed);
    }

    #[test]
    fn mmo_matches_aes_and_the_key_schedule() {
        // FIPS-197 C.1.
        let key: [u8; 16] = std::array::from_fn(|i| i as u8);
        let m = Mmo::new(key);
        let pt: [u8; 16] = std::array::from_fn(|i| (i * 0x11) as u8);
        assert_eq!(m.pi(Block::from_bytes(&pt)).to_bytes(), [0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a]);
        assert_eq!(m.round_keys()[10], [0x13, 0x11, 0x1d, 0x7f, 0xe3, 0x94, 0x4a, 0x17, 0xf3, 0x07, 0xa7, 0x8b, 0x4d, 0x2b, 0x30, 0xc5]);
        let xs: Vec<Block> = (0..100u128).map(|i| Block(i * 0x9e37_79b9_7f4a_7c15)).collect();
        let mut out = vec![Block::ZERO; 100];
        m.h_many(&xs, &mut out);
        for (x, o) in xs.iter().zip(&out) {
            assert_eq!(*o, m.h(*x));
        }
    }

    #[test]
    fn ot_tower_mmo_matches_cleartext() {
        let mut rng = ChaCha20Rng::seed_from_u64(7);
        let keys = [Mmo::new(*b"aes-tower/test-1"), Mmo::new(*b"aes-tower/test-2")];
        let xs: Vec<Block> = (0..3).map(|_| Block::random(&mut rng)).collect();
        let s0: Vec<Block> = (0..3).map(|_| Block::random(&mut rng)).collect();
        let s1: Vec<Block> = xs.iter().zip(&s0).map(|(x, s)| *x ^ *s).collect();
        let party = |b: usize, shares: Vec<Block>| {
            let keys = keys.clone();
            move |ch: &mut Channel| {
                let mut r = ChaCha20Rng::seed_from_u64(10 + b as u64);
                let delta = Block::random(&mut r).with_lsb(b == 1);
                let mut cot = CotPair::setup(ch, &mut r, delta, false).unwrap();
                let pool = cot.random_cots(ch, 0, 3 * COTS_PER_CALL, &mut r).unwrap();
                let mut be = OtTower::new(b, pool, cot.delta());
                let jobs: Vec<(&Mmo, Shared128<bool>)> = shares.iter().enumerate().map(|(i, &x)| (&keys[i % 2], bits_of(x))).collect();
                let before = ch.stats();
                let out = mmo_shared(&mut be, ch, &jobs);
                let s = ch.stats().since(&before);
                (out.iter().map(block_of).collect::<Vec<_>>(), s, be.ands, be.remaining())
            }
        };
        let ((y0, st0, ands, left), (y1, st1, _, _)) = run_two_party(party(0, s0), party(1, s1));
        for i in 0..3 {
            assert_eq!(y0[i] ^ y1[i], keys[i % 2].h(xs[i]), "job {i}");
        }
        assert_eq!((ands, left), (3 * ANDS_PER_CALL, 0));
        assert_eq!(st0.rounds, ROUNDS_PER_CALL);
        // Per layer, party 0 sends one bit per cross term (two per AND) and
        // party 1 one per corrected bit, each packed into bytes per layer.
        // 3 jobs × 16 S-boxes per AES round.
        let per_round = |bits_per_sbox: usize| (48 * bits_per_sbox).div_ceil(8);
        assert_eq!(st0.bytes_sent, 10 * [9, 3, 6, 18].iter().map(|&a| per_round(2 * a)).sum::<usize>());
        assert_eq!(st1.bytes_sent, 10 * [8, 4, 2, 4].iter().map(|&k| per_round(k)).sum::<usize>());
    }
}
