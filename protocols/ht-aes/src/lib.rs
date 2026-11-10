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
//! * [`malicious_arith`]: Figures `Π_GenMal` and `Π_Verify` for an arithmetic
//!   payload in F_p, on the semi-honest Gen: (A) the leaf MAC under a persistent
//!   δ, with the leaf hash extended by further pairs ([`leaf::mal_pair_leaf`]),
//!   (B) the glue residual ([`leaf::glue_residual`]), and Π_Verify ([`verify`])
//!   on the outputs and the residuals, whose openings are masked.
//! * [`malicious`]: the same for a payload in `F_2^ℓ` with the MAC in
//!   `F_{2^k}`, without (B): in characteristic 2 a swap of the servers' states
//!   does not change an output.

pub mod field;
pub mod leaf;
pub mod malicious;
pub mod malicious_arith;
pub mod semi_honest;
pub mod verify;

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
    let (start, k) = (out.len(), parents.len());
    out.resize(start + 2 * k, Block::ZERO);
    let kids = &mut out[start..];
    // H(parents) into the upper half, then spread in place: slot i is read
    // before slots 2i, 2i + 1 ≤ k + i are written.
    f.h_many(parents, &mut kids[k..]);
    for (i, &st) in parents.iter().enumerate() {
        let lv = kids[k + i] ^ cw.and_bit(st.lsb());
        kids[2 * i] = lv;
        kids[2 * i + 1] = st ^ lv;
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

    /// The depth n.
    #[inline]
    pub fn depth(&self) -> usize {
        self.nu + self.m0.len() - 1
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

/// The malicious leaf hash at the leaf state `st`: `h_1 = H_K(st ∥ b^t_n)` and,
/// for the public `words[j] = [C^{j+2}, N^{j+2}]`, `h_{j+2} = H_K(st ⊕ N ⊕
/// t·(C_n ⊕ C))`, t = lsb(st).
pub fn leaf_hash(f: &Mmo, bot: &Bottom, words: &[[Block; 2]], st: Block) -> Vec<Block> {
    let cn = *bot.c.last().unwrap();
    std::iter::once(f.h(bot.hash_input(bot.depth(), st))).chain(words.iter().map(|w| f.h(st ^ w[1] ^ (cn ^ w[0]).and_bit(st.lsb())))).collect()
}

/// [`leaf_hash`] for a batch: block j of leaf i lands at `buf[j·k + i]`, k =
/// `leaves.len()`.
pub fn leaf_hash_many(f: &Mmo, bot: &Bottom, words: &[[Block; 2]], leaves: &[Block], buf: &mut Vec<Block>) {
    let (k, n, cn) = (leaves.len(), bot.depth(), *bot.c.last().unwrap());
    buf.clear();
    buf.resize((words.len() + 1) * k, Block::ZERO);
    let (first, rest) = buf.split_at_mut(k);
    for (x, &st) in first.iter_mut().zip(leaves) {
        *x = bot.hash_input(n, st);
    }
    f.h_many_inplace(first);
    if k == 0 {
        return;
    }
    for (chunk, w) in rest.chunks_mut(k).zip(words) {
        let d = cn ^ w[0];
        for (x, &st) in chunk.iter_mut().zip(leaves) {
            *x = st ^ w[1] ^ d.and_bit(st.lsb());
        }
        f.h_many_inplace(chunk);
    }
}

/// The public words `[C^j, N^j]`, `2 ≤ j ≤ τ`, of the leaf pairs `leaf_pairs =
/// [[X^{j,0}, X^{j,1}]]` in the clear: `C^j = Δ ⊕ X^{j,0} ⊕ X^{j,1}` and `N^j =
/// u^0_n ⊕ X^{j,0} ⊕ r_n·(C_n ⊕ C^j)`.
pub(crate) fn deal_leaf_words(delta: Block, un0: Block, cn: Block, r_n: bool, leaf_pairs: &[[Block; 2]]) -> Vec<[Block; 2]> {
    leaf_pairs
        .iter()
        .map(|p| {
            let c = delta ^ p[0] ^ p[1];
            [c, un0 ^ p[0] ^ (cn ^ c).and_bit(r_n)]
        })
        .collect()
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
/// because the glue residual evaluates ψ on all 2^ν frontier nodes. Scan
/// 2026-11-04 on the previous Gen, 64-bit payload: ν = 15 is fastest or within
/// noise of it at every n ≥ 20.
pub const BEST_NU_MAL_ARITH: usize = 15;

/// [`BEST_NU_MAL_ARITH`], at most n − 1 and at least 1.
pub fn default_nu_mal_arith(n: usize) -> usize {
    clamp_nu(BEST_NU_MAL_ARITH, n)
}

fn clamp_nu(nu: usize, n: usize) -> usize {
    nu.min(n.saturating_sub(1)).max(1)
}

/// Calls of `𝓕_PRFPair` in one malicious Gen with a τ-block leaf hash.
pub fn mal_calls(n: usize, nu: usize, tau: usize) -> usize {
    sh_calls(n, nu) + 2 * (tau - 1)
}

/// ANDs of the OT tower in one malicious Gen.
pub fn mal_ands(n: usize, nu: usize, tau: usize) -> usize {
    mal_calls(n, nu, tau) * ANDS_PER_CALL
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
