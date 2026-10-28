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
//! The F4 products are the only interaction; [`TowerBackend`] supplies them (one
//! call, one round, per layer), so the same circuit runs semi-honest on XOR
//! shares with Beaver triples ([`BeaverF4`]) and maliciously on authenticated
//! bits.
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
use crate::hash::sigma;
use crate::net::Channel;
use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockEncrypt, KeyInit};
use aes::Aes128;
use std::ops::BitXor;
use std::sync::OnceLock;

/// F4 products per AES-128 call (160 S-boxes × 12).
pub const PRODUCTS_PER_CALL: usize = 160 * 12;
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

/// The interactive part of the circuit: products of shared F4 elements.
pub trait TowerBackend {
    type Bit: ShareBit;

    /// This party's share of the public bit `c`.
    fn constant(&self, c: bool) -> Self::Bit;

    /// Shares of `x_i·y_i` for all i, in one round.
    fn mul_f4(&mut self, ch: &mut Channel, x: &[F4Sh<Self::Bit>], y: &[F4Sh<Self::Bit>]) -> Vec<F4Sh<Self::Bit>>;
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

/// Karatsuba products `x_i·y_i` in `F_{2^4}`, all in one round (3 F4 products
/// each): `(m_2 + m_0, θ m_1 + m_0)` with `m_1 = x_1y_1`, `m_0 = x_0y_0`,
/// `m_2 = (x_1 + x_0)(y_1 + y_0)`.
fn mul16<K: TowerBackend>(be: &mut K, ch: &mut Channel, x: &[F16<K::Bit>], y: &[F16<K::Bit>]) -> Vec<F16<K::Bit>> {
    let n = x.len();
    let mut a = Vec::with_capacity(3 * n);
    let mut b = Vec::with_capacity(3 * n);
    for (u, v) in x.iter().zip(y) {
        a.extend([u.x1, u.x0, u.x1.add(u.x0)]);
        b.extend([v.x1, v.x0, v.x1.add(v.x0)]);
    }
    let m = be.mul_f4(ch, &a, &b);
    m.chunks(3).map(|m| F16 { x1: m[2].add(m[1]), x0: m[0].scale(f4::OMEGA).add(m[1]) }).collect()
}

/// S-boxes of a batch of shared bytes, in four rounds.
pub fn sbox_shared<K: TowerBackend>(be: &mut K, ch: &mut Channel, bytes: &[[K::Bit; 8]]) -> Vec<[K::Bit; 8]> {
    let tw = tower();
    let (ah, al): (Vec<_>, Vec<_>) = bytes.iter().map(|b| split(&lin8(&tw.phi, b))).unzip();
    // Depth 1: p = a_h·a_l, then the norm d.
    let p = mul16(be, ch, &ah, &al);
    let d: Vec<F16<K::Bit>> = (0..bytes.len()).map(|i| ah[i].sq().mul_eta().add(p[i]).add(al[i].sq())).collect();
    // Depth 2: Inv16, the product x_1·x_0 of the F4 norm θx_1² + x_1x_0 + x_0².
    let x1: Vec<_> = d.iter().map(|v| v.x1).collect();
    let x0: Vec<_> = d.iter().map(|v| v.x0).collect();
    let m = be.mul_f4(ch, &x1, &x0);
    let e: Vec<F4Sh<K::Bit>> = (0..d.len()).map(|i| x1[i].sq().scale(f4::OMEGA).add(m[i]).add(x0[i].sq()).sq()).collect();
    // Depth 3: w = (x_1 e, (x_1 + x_0) e).
    let mut a = Vec::with_capacity(2 * d.len());
    let mut b = Vec::with_capacity(2 * d.len());
    for i in 0..d.len() {
        a.extend([x1[i], x1[i].add(x0[i])]);
        b.extend([e[i], e[i]]);
    }
    let we = be.mul_f4(ch, &a, &b);
    let w: Vec<F16<K::Bit>> = we.chunks(2).map(|c| F16 { x1: c[0], x0: c[1] }).collect();
    // Depth 4: b_h = a_h·w and b' = a_l·w in one round.
    let mut xs = ah.clone();
    xs.extend_from_slice(&al);
    let mut ws = w.clone();
    ws.extend_from_slice(&w);
    let bb = mul16(be, ch, &xs, &ws);
    let n = bytes.len();
    let c63 = std::array::from_fn::<_, 8, _>(|i| be.constant(0x63 >> i & 1 == 1));
    (0..n)
        .map(|i| {
            let (bh, b2) = (bb[i], bb[n + i]);
            let o = lin8(&tw.out, &join(bh, bh.add(b2)));
            std::array::from_fn(|k| o[k] ^ c63[k])
        })
        .collect()
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
        let sb = sbox_shared(be, ch, &bytes);
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

/// Semi-honest F4 products from Beaver triples `(a, b, c = ab)`, XOR-shared,
/// consumed front to back. Each product opens `x ⊕ a` and `y ⊕ b`: four bits
/// per party, packed two products per byte.
pub struct BeaverF4 {
    party: usize,
    triples: Vec<(u8, u8, u8)>,
    next: usize,
    /// Products computed so far.
    pub products: usize,
}

impl BeaverF4 {
    pub fn new(party: usize, triples: Vec<(u8, u8, u8)>) -> Self {
        BeaverF4 { party, triples, next: 0, products: 0 }
    }

    /// Triples left.
    pub fn remaining(&self) -> usize {
        self.triples.len() - self.next
    }

    /// Shares of `x_i·y_i` for plain F4 shares (bytes), one round.
    pub fn mul_bytes(&mut self, ch: &mut Channel, x: &[u8], y: &[u8]) -> Vec<u8> {
        let n = x.len();
        assert!(self.remaining() >= n, "F4 triple pool exhausted");
        let t = &self.triples[self.next..self.next + n];
        self.next += n;
        self.products += n;
        let de: Vec<u8> = (0..n).map(|i| (x[i] ^ t[i].0) | (y[i] ^ t[i].1) << 2).collect();
        ch.send(de.chunks(2).map(|c| c[0] | c.get(1).map_or(0, |v| v << 4)).collect());
        let theirs = ch.recv();
        assert_eq!(theirs.len(), n.div_ceil(2), "malformed Beaver opening");
        (0..n)
            .map(|i| {
                let both = de[i] ^ (theirs[i / 2] >> (4 * (i % 2)) & 15);
                let (d, e) = (both & 3, both >> 2);
                let (a, b, c) = t[i];
                let mut z = c ^ f4::mul(d, b) ^ f4::mul(e, a);
                if self.party == 0 {
                    z ^= f4::mul(d, e);
                }
                z
            })
            .collect()
    }
}

impl TowerBackend for BeaverF4 {
    type Bit = bool;

    fn constant(&self, c: bool) -> bool {
        c && self.party == 0
    }

    fn mul_f4(&mut self, ch: &mut Channel, x: &[F4Sh<bool>], y: &[F4Sh<bool>]) -> Vec<F4Sh<bool>> {
        let xs: Vec<u8> = x.iter().map(|v| v.to_u8()).collect();
        let ys: Vec<u8> = y.iter().map(|v| v.to_u8()).collect();
        self.mul_bytes(ch, &xs, &ys).into_iter().map(F4Sh::from_u8).collect()
    }
}

#[cfg(test)]
/// Trusted-dealer F4 triples for tests: `n` triples for each party.
pub fn dealer_triples<R: rand::RngCore>(rng: &mut R, n: usize) -> [Vec<(u8, u8, u8)>; 2] {
    let mut t = [Vec::with_capacity(n), Vec::with_capacity(n)];
    for _ in 0..n {
        let r = rng.next_u32();
        let (a, b, a0, b0, c0) = (r as u8 & 3, (r >> 2) as u8 & 3, (r >> 4) as u8 & 3, (r >> 6) as u8 & 3, (r >> 8) as u8 & 3);
        t[0].push((a0, b0, c0));
        t[1].push((a ^ a0, b ^ b0, f4::mul(a, b) ^ c0));
    }
    t
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::run_two_party;
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
    fn shared_mmo_matches_cleartext() {
        let mut rng = ChaCha20Rng::seed_from_u64(7);
        let keys = [Mmo::new(*b"aes-tower/test-1"), Mmo::new(*b"aes-tower/test-2")];
        let xs: Vec<Block> = (0..3).map(|_| Block::random(&mut rng)).collect();
        let s0: Vec<Block> = (0..3).map(|_| Block::random(&mut rng)).collect();
        let triples = dealer_triples(&mut rng, 3 * PRODUCTS_PER_CALL);
        let party = |b: usize, shares: Vec<Block>, t: Vec<(u8, u8, u8)>| {
            let keys = keys.clone();
            move |ch: &mut Channel| {
                let mut be = BeaverF4::new(b, t);
                let jobs: Vec<(&Mmo, Shared128<bool>)> = shares.iter().enumerate().map(|(i, &x)| (&keys[i % 2], bits_of(x))).collect();
                let before = ch.stats();
                let out = mmo_shared(&mut be, ch, &jobs);
                let s = ch.stats().since(&before);
                (out.iter().map(block_of).collect::<Vec<_>>(), s, be.products)
            }
        };
        let s1: Vec<Block> = xs.iter().zip(&s0).map(|(x, s)| *x ^ *s).collect();
        let [t0, t1] = triples;
        let ((y0, st, prods), (y1, _, _)) = run_two_party(party(0, s0, t0), party(1, s1, t1));
        for i in 0..3 {
            assert_eq!(y0[i] ^ y1[i], keys[i % 2].h(xs[i]), "job {i}");
        }
        assert_eq!(prods, 3 * PRODUCTS_PER_CALL);
        assert_eq!(st.rounds, ROUNDS_PER_CALL);
        // Four bits per product and party.
        assert_eq!(st.bytes_sent, 3 * PRODUCTS_PER_CALL / 2);
    }
}
