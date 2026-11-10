//! Our distributed half-tree DPF (the paper's `htDPF.Gen`, §"Fully
//! Distributed DPF"), with `F_PRF` instantiated by AES–MMO in 2PC on the OT
//! tower ([`dpf_common::aes_tower::OtTower`]): every AND of the S-boxes from
//! Ferret COTs.
//!
//! The semi-honest Gen ([`semi_honest::gen`]) is the paper's Figure
//! `Π_GenSH` in a [`semi_honest::Session`]: one public AES key K (`F = H_K`)
//! and one secret-shared Δ for all Gens of the session, the roots `k_b = Δ_b ⊕
//! W` re-randomised per Gen by a public W, and `Δ_b` doubling as party b's
//! Ferret key; for the top ν ≥ 1 levels each party expands its own tree
//! locally and the words `CW_ℓ` follow from frontier sums; the glue turns the
//! level-ν frontier into a sharing of the on-path state; below ν every level
//! takes two on-path pairs `(⟨X⟩, ⟨H_K(X)⟩)` sampled in the middle of the
//! cipher ([`dpf_common::aes_tower::mmo_pairs`], 20 rounds), concurrently with
//! the top phase. A level's public words are `CW_ℓ`, the shift `M^0_ℓ`, the
//! offset `C_ℓ` and the two bits `b^τ_ℓ` ([`Bottom`]). Evaluation is the
//! half-tree walk with `L = H_K(s ∥ b^t_{ℓ−1})`, `R = st ⊕ L`, `st' = child ⊕
//! t·CW`, followed by the shift `M^t_ℓ` of the child's tag for `ℓ ≥ ν`
//! ([`expand_level`]).
//!
//! * [`semi_honest`]: payload in `G = F_p` ([`field`]) with a public β, the
//!   leaf indexed by server, with one sign product ([`leaf::pair_leaf`]).
//! * [`semi_honest::bin`]: the same Gen with a binary payload: no B2A, no
//!   sign, no tag count at the glue.
//! * [`malicious_arith`]: the paper's §malicious for an arithmetic payload
//!   in F_p, still on the previous Gen with Δ-correlated on-path states
//!   ([`semi_honest::gen::walk`], 40 rounds for the AES–MMO calls): (A) the
//!   payload-MAC word under a persistent δ and public keys `K^mac_j`
//!   ([`leaf::mal_leaf`]), (B) one product per bottom level, (C) the glue
//!   residual ([`leaf::glue_residual`]), and Π_Verify on the outputs and
//!   residuals.
//! * [`malicious`]: the same for a payload in `{0,1}^ℓ ⊂ GF(2^128)`, without
//!   (C): in characteristic 2 a swap of the servers' states does not change
//!   an output.

pub mod field;
pub mod leaf;
pub mod malicious;
pub mod malicious_arith;
pub mod semi_honest;

use dpf_common::aes_tower::{Mmo, ANDS_PER_CALL};
use dpf_common::block::Block;

/// One half-tree step under `F = f`: the child of `st` in direction `bit`, corrected.
#[inline]
pub fn child(f: &Mmo, st: Block, cw: Block, bit: bool) -> Block {
    let l = f.h(st);
    let c = if bit { st ^ l } else { l };
    c ^ cw.and_bit(st.lsb())
}

/// [`child`] for a whole batch: appends both corrected children of every
/// parent to `out`, interleaved `[L(p0), R(p0), L(p1), …]`.
pub fn children(f: &Mmo, parents: &[Block], cw: Block, out: &mut Vec<Block>) {
    children_masked(f, parents, cw, Block::ZERO, out)
}

/// [`children`] with the level word `m` XORed onto every child (`M_ℓ` of the
/// semi-honest Gen, zero above the glue level).
pub fn children_masked(f: &Mmo, parents: &[Block], cw: Block, m: Block, out: &mut Vec<Block>) {
    let (start, k) = (out.len(), parents.len());
    out.resize(start + 2 * k, Block::ZERO);
    let kids = &mut out[start..];
    // H(parents) into the upper half, then spread in place: slot i is read
    // before slots 2i, 2i + 1 ≤ k + i are written.
    f.h_many(parents, &mut kids[k..]);
    for (i, &st) in parents.iter().enumerate() {
        let lv = kids[k + i] ^ cw.and_bit(st.lsb());
        kids[2 * i] = lv ^ m;
        kids[2 * i + 1] = st ^ lv ^ m;
    }
}

/// The public words of the bottom layer of a key, for `ν ≤ ℓ ≤ n`: the shifts
/// `M^0_ℓ`, the offsets `C_ℓ` (with `C_{ν−1} := 0`) and the bits `(b^0_ℓ,
/// b^1_ℓ)`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bottom {
    /// The glue level ν ≥ 1.
    pub nu: usize,
    pub m0: Vec<Block>,
    pub c: Vec<Block>,
    pub b: Vec<[bool; 2]>,
}

impl Bottom {
    /// `M^0_ℓ` and `C_ℓ` per level, two bits per level.
    pub fn size_bytes(&self) -> usize {
        32 * self.m0.len() + (2 * self.b.len()).div_ceil(8)
    }

    /// `(s ∥ b^t_ℓ)` of a state at level ℓ, with `b^t_ℓ := t` for ℓ < ν.
    #[inline]
    pub fn hash_input(&self, level: usize, st: Block) -> Block {
        if level < self.nu {
            st
        } else {
            st.with_lsb(self.b[level - self.nu][st.lsb() as usize])
        }
    }

    /// `(M^0_ℓ, C_{ℓ−1} ⊕ C_ℓ)`, for ℓ ≥ ν.
    #[inline]
    fn words(&self, level: usize) -> (Block, Block) {
        let j = level - self.nu;
        (self.m0[j], if j == 0 { self.c[0] } else { self.c[j - 1] ^ self.c[j] })
    }

    /// The corrected child of level ℓ after its shift `M^t_ℓ`, t its tag.
    #[inline]
    pub fn shift(&self, level: usize, child: Block) -> Block {
        if level < self.nu {
            return child;
        }
        let (m, d) = self.words(level);
        child ^ m ^ d.and_bit(child.lsb())
    }

    /// The state of the path to x (`n` bits) at level n from the `root`.
    pub fn path(&self, f: &Mmo, root: Block, cws: &[Block], x: u64) -> Block {
        let n = cws.len();
        let mut st = root;
        for (i, &cw) in cws.iter().enumerate() {
            let l = f.h(self.hash_input(i, st));
            let c = if (x >> (n - 1 - i)) & 1 == 1 { st ^ l } else { l };
            st = self.shift(i + 1, c ^ cw.and_bit(st.lsb()));
        }
        st
    }
}

/// Both corrected children of every parent, at level ℓ = `level`, appended to
/// `out` as `[L(p0), R(p0), L(p1), …]`, each with its shift.
pub fn expand_level(f: &Mmo, parents: &[Block], cw: Block, bot: &Bottom, level: usize, out: &mut Vec<Block>) {
    if level < bot.nu {
        return children(f, parents, cw, out);
    }
    let (start, k) = (out.len(), parents.len());
    out.resize(start + 2 * k, Block::ZERO);
    let kids = &mut out[start..];
    for (i, &st) in parents.iter().enumerate() {
        kids[k + i] = bot.hash_input(level - 1, st);
    }
    f.h_many_inplace(&mut kids[k..]);
    let (m, d) = bot.words(level);
    // Slot i is read before slots 2i, 2i + 1 ≤ k + i are written.
    for (i, &st) in parents.iter().enumerate() {
        let c0 = kids[k + i] ^ cw.and_bit(st.lsb());
        let c1 = st ^ c0;
        kids[2 * i] = c0 ^ m ^ d.and_bit(c0.lsb());
        kids[2 * i + 1] = c1 ^ m ^ d.and_bit(c1.lsb());
    }
}

/// The cleartext Gen of Figure `Π_GenSH`: the n level words, the [`Bottom`]
/// words and the two leaf hashes `(H_K(X^0_n), H_K(X^1_n))`, for roots `roots`,
/// α, and the inputs `pairs = [[X^0_ℓ, X^1_ℓ]]` and bits `rs = [r_ℓ]` of levels
/// ν..=n. With `binary`, the glue takes the state of the server with tag 1 as
/// `st_{ν,0}`, as in the paper's paragraph on Boolean payloads.
#[allow(clippy::too_many_arguments)]
pub(crate) fn deal_pairs(f: &Mmo, roots: [Block; 2], n: usize, nu: usize, alpha: u64, pairs: &[[Block; 2]], rs: &[bool], binary: bool) -> (Vec<Block>, Bottom, [Block; 2]) {
    assert!(!roots[0].lsb() && roots[1].lsb(), "lsb(root_b) = b");
    assert!(n >= 64 || alpha >> n == 0, "α ∈ {{0,1}}^n");
    assert!((1..=n).contains(&nu) && pairs.len() == n - nu + 1 && rs.len() == pairs.len(), "1 ≤ ν ≤ n, levels ν..=n");
    let delta = roots[0] ^ roots[1];
    let bit = |i: usize| (alpha >> (n - 1 - i)) & 1 == 1;
    let us: Vec<[Block; 2]> = pairs.iter().zip(rs).map(|(p, &r)| [p[0].with_lsb(r), p[1].with_lsb(!r)]).collect();
    let c: Vec<Block> = us.iter().map(|u| delta ^ u[0] ^ u[1]).collect();
    let b: Vec<[bool; 2]> = pairs
        .iter()
        .zip(rs)
        .map(|(p, &r)| {
            let g = r && (p[0].lsb() ^ p[1].lsb());
            [p[0].lsb() ^ g, p[1].lsb() ^ g]
        })
        .collect();
    let mut st = roots;
    let mut cws = Vec::with_capacity(n);
    for i in 0..nu {
        let a = bit(i);
        let cw = f.h(st[0]) ^ f.h(st[1]) ^ delta.and_bit(!a);
        st = [child(f, st[0], cw, a), child(f, st[1], cw, a)];
        cws.push(cw);
    }
    let mut m0 = Vec::with_capacity(pairs.len());
    m0.push(if binary {
        (if st[0].lsb() { st[0] } else { st[1] }) ^ us[0][0] ^ c[0]
    } else {
        st[0] ^ us[0][0] ^ c[0].and_bit(st[0].lsb())
    });
    for j in 0..n - nu {
        let a = bit(nu + j);
        let (l0, l1) = (f.h(pairs[j][0]), f.h(pairs[j][1]));
        let cw = l0 ^ l1 ^ (delta ^ c[j]).and_bit(!a);
        let k = l0 ^ us[j][0].and_bit(a) ^ cw.and_bit(rs[j]);
        m0.push(k ^ us[j + 1][0] ^ (c[j] ^ c[j + 1]).and_bit(k.lsb()));
        cws.push(cw);
    }
    let last = pairs[n - nu];
    (cws, Bottom { nu, m0, c, b }, [f.h(last[0]), f.h(last[1])])
}

/// The cleartext walk of the Gen with glue level ν ≥ 1: the n level words and
/// the words `M_ν, …, M_n` for the key `f` (K), roots `st` (`st_0 ⊕ st_1 =
/// Δ`), α and the on-path states `us = [u_ν, …, u_n]` of party 0, and the two
/// leaf states (`u_n`, `u_n ⊕ Δ`).
pub(crate) fn deal_walk_nu(f: &Mmo, roots: [Block; 2], n: usize, nu: usize, alpha: u64, us: &[Block]) -> (Vec<Block>, Vec<Block>, [Block; 2]) {
    assert!(!roots[0].lsb() && roots[1].lsb(), "lsb(root_b) = b");
    assert!(n >= 64 || alpha >> n == 0, "α ∈ {{0,1}}^n");
    assert!((1..=n).contains(&nu) && us.len() == n - nu + 1, "1 ≤ ν ≤ n, u_ν, …, u_n");
    let delta = roots[0] ^ roots[1];
    let mut st = roots;
    let (mut cws, mut ms) = (Vec::with_capacity(n), Vec::with_capacity(us.len()));
    for i in 0..n {
        let a = (alpha >> (n - 1 - i)) & 1 == 1;
        let cw = f.h(st[0]) ^ f.h(st[1]) ^ delta.and_bit(!a);
        st = [child(f, st[0], cw, a), child(f, st[1], cw, a)];
        cws.push(cw);
        if i + 1 >= nu {
            let m = st[0] ^ us[i + 1 - nu];
            ms.push(m);
            st = [st[0] ^ m, st[1] ^ m];
        }
    }
    debug_assert_eq!(st[0] ^ st[1], delta);
    (cws, ms, st)
}

/// The leaf input of the payload hashes: the seed with its control bit cleared.
#[inline]
pub fn leaf_seed(st: Block) -> Block {
    st.with_lsb(false)
}

/// The default glue level: ν = 17, or n − 1 below n = 18 (at least 1). Measured (sh,
/// Babybear, 2026-11-02; `other_tex/nu_scan_temp.tex`): each level moved
/// into the top phase saves ~0.76 ms of 2PC compute and 3.55 kB, while the
/// top phase's local cost doubles per level, so the optimum is a fixed level
/// (16–17 at n = 20 and n = 32), not a fraction of n.
pub const BEST_NU: usize = 17;

/// [`BEST_NU`], at most n − 1 and at least 1 (the paper's `1 ≤ ν < n`; ν = n
/// only for n = 1).
pub fn default_nu(n: usize) -> usize {
    clamp_nu(BEST_NU, n)
}

/// The default glue level of `mal-arith`: ν = 15, lower than [`BEST_NU`]
/// because the glue residual evaluates ψ_r on all 2^ν frontier nodes. Scan
/// 2026-11-04, 64-bit payload: ν = 15 is fastest or within noise of it at
/// every n ≥ 20 (n = 32: 15.7 ms vs 16.2 ms at ν = 17 and 19.4 ms at ν = 18).
pub const BEST_NU_MAL_ARITH: usize = 15;

/// [`BEST_NU_MAL_ARITH`], at most n − 1 and at least 1.
pub fn default_nu_mal_arith(n: usize) -> usize {
    clamp_nu(BEST_NU_MAL_ARITH, n)
}

fn clamp_nu(nu: usize, n: usize) -> usize {
    nu.min(n.saturating_sub(1)).max(1)
}

/// Calls of `𝓕_PRFPair` in one semi-honest Gen of depth n with glue level ν:
/// two for each level ν..=n.
pub fn sh_calls(n: usize, nu: usize) -> usize {
    2 * (n - nu + 1)
}

/// ANDs of the OT tower in one semi-honest Gen (K is public: no Π_KeyExp).
pub fn sh_ands(n: usize, nu: usize) -> usize {
    sh_calls(n, nu) * ANDS_PER_CALL
}
