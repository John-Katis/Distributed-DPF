//! The OT tower's ANDs-from-COTs protocol on any AND/XOR circuit of the AES
//! S-box, to compare the Boyar–Peralta S-box (SEA'10 / "A depth-16 circuit
//! for the AES S-box", 34 ANDs at AND-depth 4) with the F4 tower of
//! `dpf_common::aes_tower` (36 ANDs at depth 4).
//!
//! [`CotCircuit`] is [`dpf_common::aes_tower::OtTower`] with the circuit as a
//! parameter: an AND `u·v` is `u_0v_0 ⊕ u_1v_1 ⊕ Cross(v_1; u_0) ⊕ Cross(u_1;
//! v_0)`, so party 1's share of both operands must be an F2-linear form of
//! bits it has corrected (one random COT and one bit each). [`Schedule`]
//! picks those bits per AND layer: the operands of the layer that are not yet
//! in the span of the corrected bits, a basis of them modulo that span. The
//! count is the rank of each layer's operands over what is already
//! corrected, which no other choice of corrected bits lowers.
//!
//! [`tower`] rebuilds the F4 tower as a circuit (it gives 18 COTs, 36 ANDs,
//! 90 bits per S-box, as `OtTower`), [`boyar_peralta`] is Figures 5, 7, 8 of
//! the paper as printed.

use dpf_common::aes_tower::{gf256_mul, TowerBackend, THETA, Y, ZETA};
use dpf_common::block::Block;
use dpf_common::hash::FixedKeyHash;
use dpf_common::net::Channel;
use dpf_common::ot::RandomCots;
use std::collections::HashMap;
use std::sync::OnceLock;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Op {
    Xor,
    /// `a ⊕ b ⊕ 1` (party 0 adds the 1).
    Xnor,
    And,
}

#[derive(Clone, Copy, Debug)]
pub struct Gate {
    pub op: Op,
    pub a: usize,
    pub b: usize,
    pub out: usize,
}

/// A straight-line program for the S-box, gates in topological order.
#[derive(Clone)]
pub struct Circuit {
    pub name: &'static str,
    pub wires: usize,
    /// Wire of input bit i (bit 0 the LSB of the byte).
    pub inputs: [usize; 8],
    /// Wire of output bit i, before `out_const`.
    pub outputs: [usize; 8],
    /// XORed into the output (by party 0).
    pub out_const: u8,
    pub gates: Vec<Gate>,
}

impl Circuit {
    /// The S-box in the clear.
    pub fn eval(&self, x: u8) -> u8 {
        let mut v = vec![false; self.wires];
        for (i, &w) in self.inputs.iter().enumerate() {
            v[w] = x >> i & 1 == 1;
        }
        for g in &self.gates {
            v[g.out] = match g.op {
                Op::Xor => v[g.a] ^ v[g.b],
                Op::Xnor => !(v[g.a] ^ v[g.b]),
                Op::And => v[g.a] && v[g.b],
            };
        }
        self.outputs.iter().enumerate().fold(self.out_const, |acc, (i, &w)| acc ^ (v[w] as u8) << i)
    }

    pub fn ands(&self) -> usize {
        self.gates.iter().filter(|g| g.op == Op::And).count()
    }
}

#[derive(Default)]
struct Builder {
    wires: usize,
    gates: Vec<Gate>,
}

impl Builder {
    fn fresh(&mut self) -> usize {
        self.wires += 1;
        self.wires - 1
    }

    fn gate(&mut self, op: Op, a: usize, b: usize) -> usize {
        let out = self.fresh();
        self.gates.push(Gate { op, a, b, out });
        out
    }

    fn xor(&mut self, a: usize, b: usize) -> usize {
        self.gate(Op::Xor, a, b)
    }

    fn and(&mut self, a: usize, b: usize) -> usize {
        self.gate(Op::And, a, b)
    }
}

/// Figures 5 (top, forward), 7 (shared middle, D = U7) and 8 (bottom,
/// forward) of Boyar–Peralta, as printed. `+` XOR, `#` XNOR, `x` AND.
const BP_SLP: &str = "
T1 = U0 + U3   T2 = U0 + U5   T3 = U0 + U6   T4 = U3 + U5   T5 = U4 + U6
T6 = T1 + T5   T7 = U1 + U2   T8 = U7 + T6   T9 = U7 + T7   T10 = T6 + T7
T11 = U1 + U5  T12 = U2 + U5  T13 = T3 + T4  T14 = T6 + T11 T15 = T5 + T11
T16 = T5 + T12 T17 = T9 + T16 T18 = U3 + U7  T19 = T7 + T18 T20 = T1 + T19
T21 = U6 + U7  T22 = T7 + T21 T23 = T2 + T22 T24 = T2 + T10 T25 = T20 + T17
T26 = T3 + T16 T27 = T1 + T12
M1 = T13 x T6   M2 = T23 x T8   M3 = T14 + M1   M4 = T19 x D    M5 = M4 + M1
M6 = T3 x T16   M7 = T22 x T9   M8 = T26 + M6   M9 = T20 x T17  M10 = M9 + M6
M11 = T1 x T15  M12 = T4 x T27  M13 = M12 + M11 M14 = T2 x T10  M15 = M14 + M11
M16 = M3 + M2   M17 = M5 + T24  M18 = M8 + M7   M19 = M10 + M15 M20 = M16 + M13
M21 = M17 + M15 M22 = M18 + M13 M23 = M19 + T25 M24 = M22 + M23 M25 = M22 x M20
M26 = M21 + M25 M27 = M20 + M21 M28 = M23 + M25 M29 = M28 x M27 M30 = M26 x M24
M31 = M20 x M23 M32 = M27 x M31 M33 = M27 + M25 M34 = M21 x M22 M35 = M24 x M34
M36 = M24 + M25 M37 = M21 + M29 M38 = M32 + M33 M39 = M23 + M30 M40 = M35 + M36
M41 = M38 + M40 M42 = M37 + M39 M43 = M37 + M38 M44 = M39 + M40 M45 = M42 + M41
M46 = M44 x T6  M47 = M40 x T8  M48 = M39 x D   M49 = M43 x T16 M50 = M38 x T9
M51 = M37 x T17 M52 = M42 x T15 M53 = M45 x T27 M54 = M41 x T10 M55 = M44 x T13
M56 = M40 x T23 M57 = M39 x T19 M58 = M43 x T3  M59 = M38 x T22 M60 = M37 x T20
M61 = M42 x T1  M62 = M45 x T4  M63 = M41 x T2
L0 = M61 + M62  L1 = M50 + M56  L2 = M46 + M48  L3 = M47 + M55  L4 = M54 + M58
L5 = M49 + M61  L6 = M62 + L5   L7 = M46 + L3   L8 = M51 + M59  L9 = M52 + M53
L10 = M53 + L4  L11 = M60 + L2  L12 = M48 + M51 L13 = M50 + L0  L14 = M52 + M61
L15 = M55 + L1  L16 = M56 + L0  L17 = M57 + L1  L18 = M58 + L8  L19 = M63 + L4
L20 = L0 + L1   L21 = L1 + L7   L22 = L3 + L12  L23 = L18 + L2  L24 = L15 + L9
L25 = L6 + L10  L26 = L7 + L9   L27 = L8 + L10  L28 = L11 + L14 L29 = L11 + L17
S0 = L6 + L24   S1 = L16 # L26  S2 = L19 # L28  S3 = L6 + L21   S4 = L20 + L22
S5 = L25 + L29  S6 = L13 # L27  S7 = L6 # L23
";

/// The Boyar–Peralta forward S-box: `U0` is the byte's MSB, as is `S0`.
pub fn boyar_peralta() -> Circuit {
    let mut b = Builder::default();
    let mut names: HashMap<&str, usize> = HashMap::new();
    let u: [usize; 8] = std::array::from_fn(|_| b.fresh());
    for (i, &w) in u.iter().enumerate() {
        names.insert(["U0", "U1", "U2", "U3", "U4", "U5", "U6", "U7"][i], w);
    }
    names.insert("D", u[7]);
    let tok: Vec<&str> = BP_SLP.split_whitespace().collect();
    assert_eq!(tok.len() % 5, 0);
    for s in tok.chunks(5) {
        assert_eq!(s[1], "=", "statement {s:?}");
        let op = match s[3] {
            "+" => Op::Xor,
            "#" => Op::Xnor,
            "x" => Op::And,
            o => panic!("operator {o}"),
        };
        let (a, c) = (names[s[2]], names[s[4]]);
        let out = b.gate(op, a, c);
        assert!(names.insert(s[0], out).is_none(), "{} assigned twice", s[0]);
    }
    let outputs = std::array::from_fn(|i| names[["S7", "S6", "S5", "S4", "S3", "S2", "S1", "S0"][i]]);
    Circuit { name: "boyar-peralta", wires: b.wires, inputs: std::array::from_fn(|i| u[7 - i]), outputs, out_const: 0, gates: b.gates }
}

type Mat8 = [u8; 8];

fn mat_apply(m: &Mat8, x: u8) -> u8 {
    (0..8).fold(0, |acc, i| acc | (((m[i] & x).count_ones() & 1) as u8) << i)
}

fn mat_from_columns(cols: [u8; 8]) -> Mat8 {
    let mut m = [0u8; 8];
    for (j, c) in cols.iter().enumerate() {
        for (i, row) in m.iter_mut().enumerate() {
            *row |= (c >> i & 1) << j;
        }
    }
    m
}

fn mat_inv(m: &Mat8) -> Mat8 {
    let mut inv = [0u8; 256];
    for x in 0..=255u8 {
        inv[mat_apply(m, x) as usize] = x;
    }
    mat_from_columns(std::array::from_fn(|j| inv[1 << j]))
}

fn affine_lin(a: u8) -> u8 {
    (0..8).fold(0, |r, i| r | ((a >> i ^ a >> ((i + 4) % 8) ^ a >> ((i + 5) % 8) ^ a >> ((i + 6) % 8) ^ a >> ((i + 7) % 8)) & 1) << i)
}

/// A wire pair `h·ω + l` in F4.
type F4 = (usize, usize);
/// `x_1·Y + x_0` in `F_{2^4}`.
type F16 = (F4, F4);

impl Builder {
    fn lin8(&mut self, m: &Mat8, x: &[usize; 8]) -> [usize; 8] {
        std::array::from_fn(|i| {
            let mut sel = (0..8).filter(|&j| m[i] >> j & 1 == 1).map(|j| x[j]);
            let first = sel.next().expect("invertible map");
            sel.fold(first, |acc, w| self.xor(acc, w))
        })
    }

    fn add4(&mut self, x: F4, y: F4) -> F4 {
        (self.xor(x.0, y.0), self.xor(x.1, y.1))
    }

    fn sq4(&mut self, x: F4) -> F4 {
        (x.0, self.xor(x.0, x.1))
    }

    /// ω·x = (h + l)ω + h.
    fn om4(&mut self, x: F4) -> F4 {
        (self.xor(x.0, x.1), x.0)
    }

    /// ω²·x = lω + (h + l).
    fn om2_4(&mut self, x: F4) -> F4 {
        (x.1, self.xor(x.0, x.1))
    }

    /// Karatsuba, as in `OtTower::layer`: `(n_1, n_0, n_2) → (n_2 + n_0, n_1 + n_0)`.
    fn mul4(&mut self, x: F4, y: F4) -> F4 {
        let n1 = self.and(x.0, y.0);
        let n0 = self.and(x.1, y.1);
        let (xs, ys) = (self.xor(x.0, x.1), self.xor(y.0, y.1));
        let n2 = self.and(xs, ys);
        (self.xor(n2, n0), self.xor(n1, n0))
    }

    fn add16(&mut self, x: F16, y: F16) -> F16 {
        (self.add4(x.0, y.0), self.add4(x.1, y.1))
    }

    fn sq16(&mut self, x: F16) -> F16 {
        let s1 = self.sq4(x.0);
        let (a, c) = (self.om4(s1), self.sq4(x.1));
        (s1, self.add4(a, c))
    }

    fn eta16(&mut self, x: F16) -> F16 {
        let s = self.add4(x.0, x.1);
        (self.om4(s), self.om2_4(x.0))
    }

    fn mul16(&mut self, x: F16, y: F16) -> F16 {
        let m1 = self.mul4(x.0, y.0);
        let m0 = self.mul4(x.1, y.1);
        let (xs, ys) = (self.add4(x.0, x.1), self.add4(y.0, y.1));
        let m2 = self.mul4(xs, ys);
        let a = self.add4(m2, m0);
        let w = self.om4(m1);
        (a, self.add4(w, m0))
    }
}

/// The F4 tower of `dpf_common::aes_tower` (same basis, same Karatsuba
/// products, same steps), as a circuit.
pub fn tower() -> Circuit {
    let ty = gf256_mul(THETA, Y);
    let phi_inv = mat_from_columns([1, THETA, Y, ty, ZETA, gf256_mul(THETA, ZETA), gf256_mul(Y, ZETA), gf256_mul(ty, ZETA)]);
    let phi = mat_inv(&phi_inv);
    let m = mat_from_columns(std::array::from_fn(|j| affine_lin(1 << j)));
    let out = mat_from_columns(std::array::from_fn(|j| mat_apply(&m, mat_apply(&phi_inv, 1 << j))));
    let mut b = Builder::default();
    let inputs: [usize; 8] = std::array::from_fn(|_| b.fresh());
    let t = b.lin8(&phi, &inputs);
    let ah: F16 = ((t[7], t[6]), (t[5], t[4]));
    let al: F16 = ((t[3], t[2]), (t[1], t[0]));
    let p = b.mul16(ah, al);
    let s = b.sq16(ah);
    let s = b.eta16(s);
    let s = b.add16(s, p);
    let q = b.sq16(al);
    let d = b.add16(s, q);
    let (x1, x0) = d;
    let m = b.mul4(x1, x0);
    let s = b.sq4(x1);
    let s = b.om4(s);
    let s = b.add4(s, m);
    let q = b.sq4(x0);
    let nd = b.add4(s, q);
    let e = b.sq4(nd);
    let x10 = b.add4(x1, x0);
    let w: F16 = (b.mul4(x1, e), b.mul4(x10, e));
    let bh = b.mul16(ah, w);
    let b2 = b.mul16(al, w);
    let lo = b.add16(bh, b2);
    let joined = [lo.1 .1, lo.1 .0, lo.0 .1, lo.0 .0, bh.1 .1, bh.1 .0, bh.0 .1, bh.0 .0];
    let o = b.lin8(&out, &joined);
    Circuit { name: "f4-tower", wires: b.wires, inputs, outputs: o, out_const: 0x63, gates: b.gates }
}

/// The AND layers of a circuit and the bits party 1 corrects before each.
#[derive(Clone, Debug)]
pub struct Schedule {
    /// Linear gates before the first AND layer.
    pre: Vec<usize>,
    pub layers: Vec<Layer>,
    /// COTs (= corrected bits) per S-box.
    pub cots: usize,
}

#[derive(Clone, Debug)]
pub struct Layer {
    /// Wires corrected before this layer, as COTs `first..first + len`.
    pub correct: Vec<usize>,
    pub first: usize,
    /// AND gates and the COT masks of party 1's forms of their operands.
    pub ands: Vec<(usize, u64, u64)>,
    /// Linear gates after this layer.
    after: Vec<usize>,
}

impl Schedule {
    pub fn new(c: &Circuit) -> Self {
        let mut depth = vec![0usize; c.wires];
        // Each wire's F2-linear form over the atoms: inputs 0–7, then the AND outputs.
        let mut form = vec![0u64; c.wires];
        for (i, &w) in c.inputs.iter().enumerate() {
            form[w] = 1 << i;
        }
        let mut atoms = 8;
        for g in &c.gates {
            if g.op == Op::And {
                assert!(atoms < 64, "too many ANDs for a u64 form");
                depth[g.out] = 1 + depth[g.a].max(depth[g.b]);
                form[g.out] = 1 << atoms;
                atoms += 1;
            } else {
                depth[g.out] = depth[g.a].max(depth[g.b]);
                form[g.out] = form[g.a] ^ form[g.b];
            }
        }
        let max = depth.iter().copied().max().unwrap_or(0);
        let linear_at = |d: usize| -> Vec<usize> { (0..c.gates.len()).filter(|&k| c.gates[k].op != Op::And && depth[c.gates[k].out] == d).collect() };
        // Echelon basis of the corrected forms: (reduced form, COT mask).
        let mut basis: Vec<(u64, u64)> = Vec::new();
        let reduce = |basis: &[(u64, u64)], mut f: u64| -> (u64, u64) {
            let mut mask = 0;
            for &(b, m) in basis {
                if f & (1 << (63 - b.leading_zeros())) != 0 {
                    f ^= b;
                    mask ^= m;
                }
            }
            (f, mask)
        };
        let mut layers = Vec::with_capacity(max);
        let mut cots = 0;
        for d in 1..=max {
            let gates: Vec<usize> = (0..c.gates.len()).filter(|&k| c.gates[k].op == Op::And && depth[c.gates[k].out] == d).collect();
            let first = cots;
            let mut correct = Vec::new();
            for &k in &gates {
                for w in [c.gates[k].a, c.gates[k].b] {
                    let (r, m) = reduce(&basis, form[w]);
                    if r != 0 {
                        basis.push((r, m ^ (1 << cots)));
                        correct.push(w);
                        cots += 1;
                    }
                }
            }
            let ands = gates
                .iter()
                .map(|&k| {
                    let (ra, la) = reduce(&basis, form[c.gates[k].a]);
                    let (rb, lb) = reduce(&basis, form[c.gates[k].b]);
                    debug_assert!(ra == 0 && rb == 0);
                    (k, la, lb)
                })
                .collect();
            layers.push(Layer { correct, first, ands, after: linear_at(d) });
        }
        assert!(cots <= 64);
        Schedule { pre: linear_at(0), layers, cots }
    }

    pub fn ands(&self) -> usize {
        self.layers.iter().map(|l| l.ands.len()).sum()
    }

    /// Bits on the wire per S-box: party 1's corrections, two cross bits per AND from party 0.
    pub fn bits(&self) -> usize {
        self.cots + 2 * self.ands()
    }
}

fn cross_hash() -> &'static FixedKeyHash {
    static H: OnceLock<FixedKeyHash> = OnceLock::new();
    H.get_or_init(|| FixedKeyHash::new(b"exp-bp-sbox/otTw"))
}

/// The OT tower's protocol on any circuit: party 0 the COT sender under Γ,
/// party 1 the receiver, [`Schedule::cots`] COTs per S-box, one round per
/// AND layer.
pub struct CotCircuit {
    pub circuit: Circuit,
    pub sched: Schedule,
    party: usize,
    gamma: Block,
    blocks: Vec<Block>,
    choices: Vec<bool>,
    next: usize,
    tweak: u64,
    pub ands: usize,
}

impl CotCircuit {
    pub fn new(circuit: Circuit, party: usize, cots: RandomCots, gamma: Block) -> Self {
        let sched = Schedule::new(&circuit);
        let (blocks, choices, gamma) = match cots {
            RandomCots::Sender(k) => {
                assert_eq!(party, 0);
                (k, vec![], gamma)
            }
            RandomCots::Receiver(c, m) => {
                assert_eq!(party, 1);
                (m, c, Block::ZERO)
            }
        };
        CotCircuit { circuit, sched, party, gamma, blocks, choices, next: 0, tweak: 0, ands: 0 }
    }

    pub fn remaining(&self) -> usize {
        self.blocks.len() - self.next
    }

    #[inline]
    fn form(&self, base: usize, mut l: u64) -> Block {
        let mut x = Block::ZERO;
        while l != 0 {
            x ^= self.blocks[base + l.trailing_zeros() as usize];
            l &= l - 1;
        }
        x
    }

    fn linear(&self, v: &mut [bool], w: usize, n: usize, gates: &[usize]) {
        let one = self.party == 0;
        for &k in gates {
            let g = self.circuit.gates[k];
            let flip = g.op == Op::Xnor && one;
            for i in 0..n {
                v[i * w + g.out] = v[i * w + g.a] ^ v[i * w + g.b] ^ flip;
            }
        }
    }
}

impl TowerBackend for CotCircuit {
    type Bit = bool;

    fn constant(&self, c: bool) -> bool {
        c && self.party == 0
    }

    fn sbox(&mut self, ch: &mut Channel, bytes: &[[bool; 8]]) -> Vec<[bool; 8]> {
        let n = bytes.len();
        let k = self.sched.cots;
        assert!(self.remaining() >= k * n, "COT pool exhausted");
        let base = self.next;
        self.next += k * n;
        let w = self.circuit.wires;
        let mut v = vec![false; n * w];
        for (i, b) in bytes.iter().enumerate() {
            for (j, &x) in b.iter().enumerate() {
                v[i * w + self.circuit.inputs[j]] = x;
            }
        }
        let sched = std::mem::replace(&mut self.sched, Schedule { pre: vec![], layers: vec![], cots: 0 });
        self.linear(&mut v, w, n, &sched.pre);
        let at = |i: usize| base + k * i;
        let h = cross_hash();
        let mut eps = vec![0u64; n];
        for layer in &sched.layers {
            let c = layer.correct.len();
            // (S-box, party 1's form, party 1's bit, party 0's bit), two per AND.
            let mut crosses: Vec<(usize, u64, bool, bool)> = Vec::with_capacity(2 * n * layer.ands.len());
            for i in 0..n {
                for &(g, la, lb) in &layer.ands {
                    let g = self.circuit.gates[g];
                    let (u, x) = (v[i * w + g.a], v[i * w + g.b]);
                    crosses.push((i, lb, x, u));
                    crosses.push((i, la, u, x));
                }
            }
            self.ands += n * layer.ands.len();
            let tw = self.tweak;
            self.tweak += crosses.len() as u64;
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
                let e = ch.recv_bits(n * c);
                for (i, ei) in eps.iter_mut().enumerate() {
                    for j in 0..c {
                        *ei |= (e[c * i + j] as u64) << (layer.first + j);
                    }
                }
                crosses.iter().zip(&m).map(|(&(i, l, _, _), &(m0, m1))| if (eps[i] & l).count_ones() & 1 == 1 { m1 } else { m0 }).collect()
            } else {
                let mut e = Vec::with_capacity(n * c);
                for i in 0..n {
                    for (j, &cw) in layer.correct.iter().enumerate() {
                        e.push(v[i * w + cw] ^ self.choices[at(i) + layer.first + j]);
                    }
                }
                ch.send_bits(&e);
                let zeta = ch.recv_bits(crosses.len());
                crosses.iter().enumerate().map(|(t, &(i, l, b, _))| h.h(self.form(at(i), l), tw + t as u64).lsb() ^ (b && zeta[t])).collect()
            };
            let per = layer.ands.len();
            for i in 0..n {
                for (j, &(g, _, _)) in layer.ands.iter().enumerate() {
                    let g = self.circuit.gates[g];
                    let t = 2 * (i * per + j);
                    v[i * w + g.out] = (v[i * w + g.a] && v[i * w + g.b]) ^ out[t] ^ out[t + 1];
                }
            }
            self.linear(&mut v, w, n, &layer.after);
        }
        self.sched = sched;
        let oc = self.circuit.out_const;
        (0..n).map(|i| std::array::from_fn(|j| v[i * w + self.circuit.outputs[j]] ^ (oc >> j & 1 == 1 && self.party == 0))).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dpf_common::aes_tower::{bits_of, block_of, mmo_shared, sbox, Mmo, Shared128, SharedKey};
    use dpf_common::net::run_two_party;
    use dpf_common::ot::CotPair;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn circuits_are_the_aes_sbox() {
        for c in [tower(), boyar_peralta()] {
            for x in 0..=255u8 {
                assert_eq!(c.eval(x), sbox(x), "{} at {x:#04x}", c.name);
            }
        }
    }

    #[test]
    fn schedules() {
        let t = Schedule::new(&tower());
        assert_eq!((t.ands(), t.cots, t.bits(), t.layers.len()), (36, 18, 90, 4));
        let per: Vec<_> = t.layers.iter().map(|l| (l.ands.len(), l.correct.len())).collect();
        assert_eq!(per, [(9, 8), (3, 4), (6, 2), (18, 4)]);
        let b = Schedule::new(&boyar_peralta());
        assert_eq!((b.ands(), b.cots, b.bits(), b.layers.len()), (34, 19, 87, 4));
        let per: Vec<_> = b.layers.iter().map(|l| (l.ands.len(), l.correct.len())).collect();
        assert_eq!(per, [(9, 8), (3, 4), (4, 3), (18, 4)]);
    }

    #[test]
    fn mmo_matches_cleartext() {
        for circ in [tower(), boyar_peralta()] {
            let mut rng = ChaCha20Rng::seed_from_u64(7);
            let key = Mmo::new(*b"exp-bp-sbox/test");
            let xs: Vec<Block> = (0..3).map(|_| Block::random(&mut rng)).collect();
            let s0: Vec<Block> = (0..3).map(|_| Block::random(&mut rng)).collect();
            let s1: Vec<Block> = xs.iter().zip(&s0).map(|(x, s)| *x ^ *s).collect();
            let k = Schedule::new(&circ).cots;
            let party = |b: usize, shares: Vec<Block>| {
                let (key, circ) = (key.clone(), circ.clone());
                move |ch: &mut Channel| {
                    let mut r = ChaCha20Rng::seed_from_u64(10 + b as u64);
                    let gamma = Block::random(&mut r);
                    let mut cot = CotPair::setup(ch, &mut r, gamma, false).unwrap();
                    let pool = cot.random_cots(ch, 0, 3 * 160 * k, &mut r).unwrap();
                    let mut be = CotCircuit::new(circ, b, pool, cot.delta());
                    let mut sk = vec![SharedKey::public(&be, &key)];
                    let jobs: Vec<(usize, Shared128<bool>)> = shares.iter().map(|&x| (0, bits_of(x))).collect();
                    let before = ch.stats();
                    let out = mmo_shared(&mut be, ch, &mut sk, &jobs);
                    (out.iter().map(block_of).collect::<Vec<_>>(), ch.stats().since(&before).rounds, be.remaining())
                }
            };
            let ((y0, rounds, left), (y1, _, _)) = run_two_party(party(0, s0), party(1, s1));
            for i in 0..3 {
                assert_eq!(y0[i] ^ y1[i], key.h(xs[i]), "{} job {i}", circ.name);
            }
            assert_eq!((rounds, left), (40, 0));
        }
    }
}
