//! Ferret COT extension (Yang–Weng–Lan–Zhang–Wang, "Ferret: Fast Extension for
//! coRRElated OT with small communicaTion", CCS'20), the F_COT instantiation of
//! the malicious DPF paper (ZGY+24 §7.1).
//!
//! One iteration of ΠCOT (Fig. 9) turns `consumed(p)` reserved COTs into `n`
//! fresh COTs under the same Δ:
//!
//! 1. The receiver samples a seed for the LPN matrix A and a regular noise
//!    vector, i.e. one point `α_i` per bin of `2^h` leaves (Fig. 9 step 3, with
//!    the regular-index MPCOT of §5).
//! 2. **SPCOT per bin** (Fig. 6). For every tree level the receiver sends
//!    `b = r ⊕ α_l ⊕ 1` for its reserved COT `(r, t = q ⊕ r·Δ)`. The sender
//!    expands a GGM tree, sends the level sums masked as
//!    `M_0 = K_0 ⊕ H(q ⊕ b·Δ, j)` and `M_1 = K_1 ⊕ H(q ⊕ b̄·Δ, j)` with the
//!    tweakable CR hash TMMO, and sends `c = Δ ⊕ Σ v`. The receiver recovers
//!    `K_{ᾱ_l} = M_{ᾱ_l} ⊕ H(t, j)`, rebuilds every leaf except `α_i`, and sets
//!    `w[α] = c ⊕ Σ_{j≠α} w_j`, so `w = v ⊕ e·Δ`.
//! 3. **Consistency check** (malicious; Fig. 6 steps 6–9, once for all bins as
//!    in the regular-index MPCOT). The receiver samples the χ-seed (§4.2,
//!    "Optimization for generating random coefficients") and sends it with
//!    `x' = χ_α ⊕ x*`. The sender sends `H'(Σ χ_j v_j ⊕ Y)` and the receiver
//!    compares with `H'(Σ χ_j w_j ⊕ Z)`. It aborts on mismatch and tells the
//!    sender with one byte, so the in-process peer does not wait forever.
//! 4. **LPN** with a local linear code (d = 10 random rows per column):
//!    `y = v·A + s` and `(x, z) = (u·A + e, w·A + r)` (Fig. 9 step 5).
//!
//! The first `consumed(main)` outputs are reserved for the next iteration and
//! the rest are handed out. The very first iteration uses the smaller `pre`
//! parameters on base COTs from KOS-checked IKNP, as in Ferret's bootstrapping.
//!
//! [`FerretPair`] is one party's two instances (sender with its own Δ, receiver
//! of the peer's). Chosen-choice COTs are derandomised with one bit each.

use crate::block::Block;
use crate::coin::Abort;
use crate::gf128;
use crate::hash::{tccr_hash, CtrPrg};
use crate::net::Channel;
use crate::prg::Prg;
use rand::{CryptoRng, Rng, RngCore};
use sha2::{Digest, Sha256};

/// Nonzero entries per column of the LPN code.
pub const LPN_D: usize = 10;

/// Public keys of the GGM PRG.
const GGM_KEYS: (Block, Block) = (Block(0x6665_7272_6574_2d67_676d_2d6c_6566_7400), Block(0x6665_7272_6574_2d67_676d_2d72_6967_6874));

/// One parameter set: `n = t·2^h` outputs from `k` LPN-secret COTs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LpnParams {
    pub n: usize,
    pub k: usize,
    pub t: usize,
    pub log_bin: usize,
}

impl LpnParams {
    /// Reserved COTs one iteration consumes: LPN secret, one per tree level,
    /// and 128 for the consistency check.
    pub fn consumed(&self, malicious: bool) -> usize {
        self.k + self.t * self.log_bin + if malicious { 128 } else { 0 }
    }

    fn validate(&self, malicious: bool) {
        assert_eq!(self.n, self.t << self.log_bin, "n must equal t·2^log_bin");
        assert!(self.log_bin >= 1);
        assert!(self.consumed(malicious) < self.n, "an iteration must produce more than it consumes");
    }
}

/// Bootstrapping (`pre`) and steady-state (`main`) parameters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FerretConfig {
    pub pre: LpnParams,
    pub main: LpnParams,
}

impl FerretConfig {
    /// The regular-noise parameters of emp-ot's Ferret (`ferret_b13`, 128-bit
    /// security against the attacks considered in YWL+20 §6): main
    /// `n = 10,485,760, k = 452,000, t = 1,280, h = 13`, pre
    /// `n = 470,016, k = 32,768, t = 918, h = 9`.
    pub const B13: FerretConfig = FerretConfig {
        pre: LpnParams { n: 470_016, k: 32_768, t: 918, log_bin: 9 },
        main: LpnParams { n: 10_485_760, k: 452_000, t: 1_280, log_bin: 13 },
    };

    /// Tiny parameters for tests. **Not secure.**
    pub const TOY: FerretConfig = FerretConfig {
        pre: LpnParams { n: 512, k: 100, t: 8, log_bin: 6 },
        main: LpnParams { n: 1024, k: 200, t: 16, log_bin: 6 },
    };

    pub fn validate(&self, malicious: bool) {
        self.pre.validate(malicious);
        self.main.validate(malicious);
        assert!(self.pre.n >= self.main.consumed(malicious), "pre output must cover main's reserve");
    }

    /// COTs needed from the base OT extension to bootstrap.
    pub fn base_cots(&self, malicious: bool) -> usize {
        self.pre.consumed(malicious)
    }

    /// Fresh COTs per main iteration.
    pub fn yield_per_iteration(&self, malicious: bool) -> usize {
        self.main.n - self.main.consumed(malicious)
    }
}

fn ggm_prg() -> Prg {
    Prg::new(GGM_KEYS.0, GGM_KEYS.1)
}

/// `H(x, i∥l)` (TMMO) for derandomising COT number `j` of iteration `iter`.
#[inline]
fn pad(x: Block, iter: u64, j: usize) -> Block {
    tccr_hash().h(x, ((iter as u128) << 64) | j as u128)
}

/// Applies the local linear code `A = C(k, n)` given by `seed`: for every
/// output `j`, calls `f(j, rows)`.
fn for_each_lpn_row(seed: Block, n: usize, k: usize, mut f: impl FnMut(usize, &[usize; LPN_D])) {
    const CHUNK: usize = 4096;
    let mut prg = CtrPrg::new(seed);
    let mut rows = [0usize; LPN_D];
    let mut j = 0;
    while j < n {
        let m = CHUNK.min(n - j);
        // Three 128-bit words give twelve 32-bit indices; ten are used.
        let words = prg.next_words(3 * m);
        for c in 0..m {
            for (r, row) in rows.iter_mut().enumerate() {
                let w = words[3 * c + r / 4];
                *row = ((w >> (32 * (r % 4))) as u32 as usize) % k;
            }
            f(j + c, &rows);
        }
        j += m;
    }
}

/// Full GGM expansion of one bin: leaves into `leaves`, per-level (left, right)
/// sums into `sums`.
fn ggm_expand(prg: &Prg, seed: Block, h: usize, leaves: &mut [Block], scratch: &mut Vec<Block>, sums: &mut Vec<(Block, Block)>) {
    sums.clear();
    scratch.clear();
    scratch.push(seed);
    let mut next = Vec::with_capacity(leaves.len());
    for _ in 0..h {
        next.clear();
        next.resize(2 * scratch.len(), Block::ZERO);
        prg.expand_many(scratch, &mut next);
        let (mut l, mut r) = (Block::ZERO, Block::ZERO);
        for p in next.chunks_exact(2) {
            l ^= p[0];
            r ^= p[1];
        }
        sums.push((l, r));
        std::mem::swap(scratch, &mut next);
    }
    leaves.copy_from_slice(scratch);
}

/// Rebuilds every leaf except the one at `alpha` (MSB-first bits) from the
/// sibling sums `sib[l]` of the off-path side at each level. The punctured
/// leaf is left as zero.
fn ggm_puncture(prg: &Prg, alpha: &[bool], sib: &[Block], leaves: &mut [Block], scratch: &mut Vec<Block>) {
    let h = alpha.len();
    scratch.clear();
    scratch.resize(2, Block::ZERO);
    scratch[!alpha[0] as usize] = sib[0];
    let mut path = alpha[0] as usize;
    let mut next = Vec::with_capacity(leaves.len());
    for l in 1..h {
        next.clear();
        next.resize(2 * scratch.len(), Block::ZERO);
        prg.expand_many(scratch, &mut next);
        let a = alpha[l] as usize;
        let (on, off) = (2 * path + a, 2 * path + (1 - a));
        next[on] = Block::ZERO;
        next[off] = Block::ZERO;
        let mut acc = sib[l];
        for x in next.iter().skip(1 - a).step_by(2) {
            acc ^= *x;
        }
        next[off] = acc;
        path = on;
        std::mem::swap(scratch, &mut next);
    }
    leaves.copy_from_slice(scratch);
}

/// The `h` bits of `a`, MSB first (the GGM path from the root).
fn bits_of(a: usize, h: usize) -> Vec<bool> {
    (0..h).map(|l| (a >> (h - 1 - l)) & 1 == 1).collect()
}

/// χ_j for every position of an iteration.
fn chis(seed: Block, n: usize) -> Vec<Block> {
    CtrPrg::new(seed).next_words(n).into_iter().map(Block).collect()
}

/// Sender side of one iteration on reserved keys `base` (`consumed` of them).
#[allow(clippy::too_many_arguments)]
fn sender_iteration<R: RngCore + CryptoRng>(
    ch: &mut Channel,
    p: &LpnParams,
    delta: Block,
    base: &[Block],
    malicious: bool,
    iter: u64,
    fault: bool,
    rng: &mut R,
) -> Result<Vec<Block>, Abort> {
    assert_eq!(base.len(), p.consumed(malicious));
    let (h, bin) = (p.log_bin, 1usize << p.log_bin);
    let (lpn, rest) = base.split_at(p.k);
    let (tree_ots, check) = rest.split_at(p.t * h);
    let prg = ggm_prg();

    // The receiver's matrix seed and its masked path bits b.
    let lpn_seed = ch.recv_blocks(1)[0];
    let b = ch.recv_bits(p.t * h);

    // 1. GGM trees and the masked level sums.
    let mut v = vec![Block::ZERO; p.n];
    let mut msg = Vec::with_capacity(p.t * (2 * h + 1));
    let (mut scratch, mut sums) = (Vec::with_capacity(bin), Vec::with_capacity(h));
    for i in 0..p.t {
        let leaves = &mut v[i * bin..(i + 1) * bin];
        ggm_expand(&prg, Block::random(rng), h, leaves, &mut scratch, &mut sums);
        for (l, (s0, s1)) in sums.iter().enumerate() {
            let j = i * h + l;
            let q = tree_ots[j];
            msg.push(*s0 ^ pad(q ^ delta.and_bit(b[j]), iter, j));
            msg.push(*s1 ^ pad(q ^ delta.and_bit(!b[j]), iter, j));
        }
        msg.push(leaves.iter().fold(delta, |a, b| a ^ *b));
    }
    if fault {
        // Corrupt both level-1 sums of tree 0, so whichever the receiver uses is wrong.
        msg[0].0 ^= 1;
        msg[1].0 ^= 1;
    }
    ch.send_blocks(&msg);

    // 2. Consistency check.
    if malicious {
        let m = ch.recv_blocks(2);
        let (chi_seed, x) = (m[0], m[1]);
        let y = (0..128).fold(Block::ZERO, |a, b| a ^ gf128::mul(gf128::x_pow(b), check[b] ^ delta.and_bit(x.bit(b))));
        let vsum = gf128::inner(&chis(chi_seed, p.n), &v) ^ y;
        ch.send(Sha256::digest(vsum.to_bytes()).to_vec());
        if ch.recv() != [1] {
            return Err(Abort("Ferret consistency check failed"));
        }
    }

    // 3. LPN.
    for_each_lpn_row(lpn_seed, p.n, p.k, |j, rows| {
        for &r in rows {
            v[j] ^= lpn[r];
        }
    });
    Ok(v)
}

/// Receiver side of one iteration on reserved COTs `(bits, macs)`.
#[allow(clippy::too_many_arguments)]
fn receiver_iteration<R: RngCore + CryptoRng>(
    ch: &mut Channel,
    p: &LpnParams,
    bits: &[bool],
    macs: &[Block],
    malicious: bool,
    iter: u64,
    rng: &mut R,
) -> Result<(Vec<bool>, Vec<Block>), Abort> {
    assert_eq!(bits.len(), p.consumed(malicious));
    let (h, bin) = (p.log_bin, 1usize << p.log_bin);
    let (u, rest_b) = bits.split_at(p.k);
    let (tree_r, check_r) = rest_b.split_at(p.t * h);
    let (m_lpn, rest_m) = macs.split_at(p.k);
    let (tree_m, check_m) = rest_m.split_at(p.t * h);
    let prg = ggm_prg();

    // A ← C(k, n) and regular noise: one uniform point per bin.
    let lpn_seed = Block::random(rng);
    let alphas_local: Vec<usize> = (0..p.t).map(|_| rng.gen_range(0..bin)).collect();
    let alpha_bits: Vec<Vec<bool>> = alphas_local.iter().map(|&a| bits_of(a, h)).collect();
    let b: Vec<bool> = (0..p.t * h).map(|j| tree_r[j] ^ alpha_bits[j / h][j % h] ^ true).collect();
    ch.send_blocks(&[lpn_seed]);
    ch.send_bits(&b);

    // 1. Rebuild every leaf except α_i in each bin.
    let msg = ch.recv_blocks(p.t * (2 * h + 1));
    let mut w = vec![Block::ZERO; p.n];
    let mut alphas = Vec::with_capacity(p.t);
    let mut scratch = Vec::with_capacity(bin);
    let mut sib = vec![Block::ZERO; h];
    for i in 0..p.t {
        let a = &alpha_bits[i];
        for l in 0..h {
            let j = i * h + l;
            // K_{ᾱ_l} = M_{ᾱ_l} ⊕ H(t, j).
            let c = msg[i * (2 * h + 1) + 2 * l + !a[l] as usize];
            sib[l] = c ^ pad(tree_m[j], iter, j);
        }
        let leaves = &mut w[i * bin..(i + 1) * bin];
        ggm_puncture(&prg, a, &sib, leaves, &mut scratch);
        let ai = alphas_local[i];
        let psi = msg[i * (2 * h + 1) + 2 * h];
        leaves[ai] = leaves.iter().fold(psi, |acc, x| acc ^ *x);
        alphas.push(i * bin + ai);
    }

    // 2. Consistency check.
    if malicious {
        let chi_seed = Block::random(rng);
        let chi = chis(chi_seed, p.n);
        let chi_a = alphas.iter().fold(Block::ZERO, |a, &j| a ^ chi[j]);
        let x = Block(chi_a.0 ^ Block::from_bits(check_r).0);
        ch.send_blocks(&[chi_seed, x]);
        let z = (0..128).fold(Block::ZERO, |a, b| a ^ gf128::mul(gf128::x_pow(b), check_m[b]));
        let wsum = gf128::inner(&chi, &w) ^ z;
        let ok = ch.recv() == Sha256::digest(wsum.to_bytes()).to_vec();
        ch.send(vec![ok as u8]);
        if !ok {
            return Err(Abort("Ferret consistency check failed"));
        }
    }

    // 3. LPN.
    let mut e = vec![false; p.n];
    for &j in &alphas {
        e[j] = true;
    }
    for_each_lpn_row(lpn_seed, p.n, p.k, |j, rows| {
        for &r in rows {
            e[j] ^= u[r];
            w[j] ^= m_lpn[r];
        }
    });
    Ok((e, w))
}

/// The Ferret sender of one direction: keys `K` with `M = K ⊕ r·Δ` at the peer.
pub struct FerretSender {
    delta: Block,
    cfg: FerretConfig,
    malicious: bool,
    iter: u64,
    reserve: Vec<Block>,
    buf: Vec<Block>,
    pos: usize,
    /// Main iterations run so far.
    pub iterations: usize,
    #[doc(hidden)]
    pub fault_next: bool,
}

/// The Ferret receiver of one direction.
pub struct FerretReceiver {
    cfg: FerretConfig,
    malicious: bool,
    iter: u64,
    reserve: (Vec<bool>, Vec<Block>),
    buf: (Vec<bool>, Vec<Block>),
    pos: usize,
    pub iterations: usize,
}

impl FerretSender {
    /// Runs the `pre` iteration on `base` keys (from the base OT extension).
    pub fn bootstrap<R: RngCore + CryptoRng>(
        ch: &mut Channel,
        cfg: FerretConfig,
        delta: Block,
        base: &[Block],
        malicious: bool,
        rng: &mut R,
    ) -> Result<Self, Abort> {
        cfg.validate(malicious);
        let out = sender_iteration(ch, &cfg.pre, delta, base, malicious, 0, false, rng)?;
        let c = cfg.main.consumed(malicious);
        Ok(FerretSender {
            delta,
            cfg,
            malicious,
            iter: 1,
            reserve: out[..c].to_vec(),
            buf: out[c..].to_vec(),
            pos: 0,
            iterations: 0,
            fault_next: false,
        })
    }

    pub fn available(&self) -> usize {
        self.buf.len() - self.pos
    }

    /// Runs main iterations until at least `m` COTs are buffered.
    pub fn ensure<R: RngCore + CryptoRng>(&mut self, ch: &mut Channel, m: usize, rng: &mut R) -> Result<(), Abort> {
        while self.available() < m {
            let fault = std::mem::take(&mut self.fault_next);
            let out = sender_iteration(ch, &self.cfg.main, self.delta, &self.reserve, self.malicious, self.iter, fault, rng)?;
            self.iter += 1;
            self.iterations += 1;
            let c = self.reserve.len();
            self.buf.drain(..self.pos);
            self.pos = 0;
            self.buf.extend_from_slice(&out[c..]);
            self.reserve.copy_from_slice(&out[..c]);
        }
        Ok(())
    }

    /// Takes `m` buffered random COT keys. Call [`ensure`](Self::ensure) first.
    pub fn take(&mut self, m: usize) -> Vec<Block> {
        let out = self.buf[self.pos..self.pos + m].to_vec();
        self.pos += m;
        out
    }
}

impl FerretReceiver {
    pub fn bootstrap<R: RngCore + CryptoRng>(
        ch: &mut Channel,
        cfg: FerretConfig,
        bits: &[bool],
        macs: &[Block],
        malicious: bool,
        rng: &mut R,
    ) -> Result<Self, Abort> {
        cfg.validate(malicious);
        let (b, m) = receiver_iteration(ch, &cfg.pre, bits, macs, malicious, 0, rng)?;
        let c = cfg.main.consumed(malicious);
        Ok(FerretReceiver {
            cfg,
            malicious,
            iter: 1,
            reserve: (b[..c].to_vec(), m[..c].to_vec()),
            buf: (b[c..].to_vec(), m[c..].to_vec()),
            pos: 0,
            iterations: 0,
        })
    }

    pub fn available(&self) -> usize {
        self.buf.1.len() - self.pos
    }

    pub fn ensure<R: RngCore + CryptoRng>(&mut self, ch: &mut Channel, m: usize, rng: &mut R) -> Result<(), Abort> {
        while self.available() < m {
            let (b, w) = receiver_iteration(ch, &self.cfg.main, &self.reserve.0, &self.reserve.1, self.malicious, self.iter, rng)?;
            self.iter += 1;
            self.iterations += 1;
            let c = self.reserve.1.len();
            self.buf.0.drain(..self.pos);
            self.buf.1.drain(..self.pos);
            self.pos = 0;
            self.buf.0.extend_from_slice(&b[c..]);
            self.buf.1.extend_from_slice(&w[c..]);
            self.reserve.0.copy_from_slice(&b[..c]);
            self.reserve.1.copy_from_slice(&w[..c]);
        }
        Ok(())
    }

    /// Takes `m` buffered random COTs `(r_j, M_j)`.
    pub fn take(&mut self, m: usize) -> (Vec<bool>, Vec<Block>) {
        let out = (self.buf.0[self.pos..self.pos + m].to_vec(), self.buf.1[self.pos..self.pos + m].to_vec());
        self.pos += m;
        out
    }
}

/// Both Ferret directions of one party, used by `CotPair` once enabled.
pub struct FerretPair {
    party: usize,
    delta: Block,
    pub sender: FerretSender,
    pub receiver: FerretReceiver,
}

impl FerretPair {
    /// Bootstraps both directions from base COTs: `k` are this party's sender
    /// keys, `(bits, macs)` its receiver COTs (both `cfg.base_cots` long), then
    /// runs one main iteration per direction so the buffers are full.
    #[allow(clippy::too_many_arguments)]
    pub fn bootstrap<R: RngCore + CryptoRng>(
        ch: &mut Channel,
        cfg: FerretConfig,
        delta: Block,
        k: &[Block],
        bits: &[bool],
        macs: &[Block],
        malicious: bool,
        rng: &mut R,
    ) -> Result<Self, Abort> {
        let party = ch.party();
        // Direction 0 (party 0 sends) always runs first.
        let (sender, receiver) = if party == 0 {
            let s = FerretSender::bootstrap(ch, cfg, delta, k, malicious, rng)?;
            (s, FerretReceiver::bootstrap(ch, cfg, bits, macs, malicious, rng)?)
        } else {
            let r = FerretReceiver::bootstrap(ch, cfg, bits, macs, malicious, rng)?;
            (FerretSender::bootstrap(ch, cfg, delta, k, malicious, rng)?, r)
        };
        let mut p = FerretPair { party, delta, sender, receiver };
        let full = cfg.yield_per_iteration(malicious);
        p.ensure(ch, full, full, rng)?;
        Ok(p)
    }

    fn ensure<R: RngCore + CryptoRng>(&mut self, ch: &mut Channel, mine: usize, theirs: usize, rng: &mut R) -> Result<(), Abort> {
        if self.party == 0 {
            self.sender.ensure(ch, theirs, rng)?;
            self.receiver.ensure(ch, mine, rng)
        } else {
            self.receiver.ensure(ch, mine, rng)?;
            self.sender.ensure(ch, theirs, rng)
        }
    }

    /// Chosen-choice COTs in both directions, as `CotPair::extend`: refills if
    /// needed, then derandomises with one bit per COT (one flight).
    pub fn extend<R: RngCore + CryptoRng>(
        &mut self,
        ch: &mut Channel,
        mine: &[bool],
        theirs: usize,
        rng: &mut R,
    ) -> Result<(Vec<Block>, Vec<Block>), Abort> {
        self.ensure(ch, mine.len(), theirs, rng)?;
        let (r, m) = self.receiver.take(mine.len());
        let d: Vec<bool> = mine.iter().zip(&r).map(|(c, r)| c ^ r).collect();
        ch.send_bits(&d);
        let mut k = self.sender.take(theirs);
        let dd = ch.recv_bits(theirs);
        for (kj, dj) in k.iter_mut().zip(dd) {
            *kj ^= self.delta.and_bit(dj);
        }
        Ok((k, m))
    }

    /// Random bits for tests.
    #[doc(hidden)]
    pub fn random_choices<R: RngCore>(rng: &mut R, n: usize) -> Vec<bool> {
        (0..n).map(|_| rng.gen()).collect()
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
    fn ggm_puncture_matches_expansion() {
        let prg = ggm_prg();
        let mut rng = ChaCha20Rng::seed_from_u64(1);
        for h in 1..7 {
            let bin = 1 << h;
            let mut leaves = vec![Block::ZERO; bin];
            let (mut sc, mut sums) = (vec![], vec![]);
            ggm_expand(&prg, Block::random(&mut rng), h, &mut leaves, &mut sc, &mut sums);
            for a in 0..bin {
                let bits: Vec<bool> = (0..h).map(|l| (a >> (h - 1 - l)) & 1 == 1).collect();
                let sib: Vec<Block> = sums.iter().zip(&bits).map(|((l, r), &b)| if b { *l } else { *r }).collect();
                let mut got = vec![Block::ZERO; bin];
                ggm_puncture(&prg, &bits, &sib, &mut got, &mut sc);
                for x in 0..bin {
                    if x != a {
                        assert_eq!(got[x], leaves[x], "h={h} a={a} x={x}");
                    }
                }
            }
        }
    }

    /// Runs several extend batches; party 0 receives `a` and party 1 receives
    /// `b` COTs per batch on random chosen bits, and checks `M = K ⊕ c·Δ`.
    fn run(malicious: bool, sizes: &[(usize, usize)]) {
        let mut rng = ChaCha20Rng::seed_from_u64(7);
        let d = [Block::random(&mut rng), Block::random(&mut rng)];
        let c0: Vec<Vec<bool>> = sizes.iter().map(|&(a, _)| (0..a).map(|_| rng.gen()).collect()).collect();
        let c1: Vec<Vec<bool>> = sizes.iter().map(|&(_, b)| (0..b).map(|_| rng.gen()).collect()).collect();
        let party = |me: usize, mine: Vec<Vec<bool>>, theirs: Vec<usize>| {
            move |c: &mut Channel| {
                let mut r = ChaCha20Rng::seed_from_u64(me as u64 + 1);
                let mut p = CotPair::setup(c, &mut r, d[me], malicious).unwrap();
                p.enable_ferret(c, FerretConfig::TOY, &mut r).unwrap();
                mine.iter().zip(&theirs).map(|(m, &t)| p.extend(c, m, t, &mut r).unwrap()).collect::<Vec<_>>()
            }
        };
        let n1: Vec<usize> = sizes.iter().map(|s| s.1).collect();
        let n0: Vec<usize> = sizes.iter().map(|s| s.0).collect();
        let (r0, r1) = run_two_party(party(0, c0.clone(), n1), party(1, c1.clone(), n0));
        for b in 0..sizes.len() {
            let ((k0, m0), (k1, m1)) = (&r0[b], &r1[b]);
            for j in 0..sizes[b].0 {
                assert_eq!(m0[j], k1[j] ^ d[1].and_bit(c0[b][j]), "batch {b}: party 0 COT {j}");
            }
            for j in 0..sizes[b].1 {
                assert_eq!(m1[j], k0[j] ^ d[0].and_bit(c1[b][j]), "batch {b}: party 1 COT {j}");
            }
        }
    }

    #[test]
    fn ferret_cots_are_correlated() {
        // Crosses several refills in both directions (TOY yields ~600 per iteration).
        let sizes = [(10, 3), (700, 50), (1, 1300), (2000, 2000)];
        run(false, &sizes);
        run(true, &sizes);
    }

    #[test]
    fn ferret_chosen_choices() {
        let mut rng = ChaCha20Rng::seed_from_u64(9);
        let d1 = Block::random(&mut rng);
        let choices: Vec<bool> = (0..1500).map(|_| rng.gen()).collect();
        let ch2 = choices.clone();
        let (m, k) = run_two_party(
            move |c| {
                let mut r = ChaCha20Rng::seed_from_u64(1);
                let mut p = CotPair::setup(c, &mut r, Block(2), true).unwrap();
                p.enable_ferret(c, FerretConfig::TOY, &mut r).unwrap();
                p.extend(c, &ch2, 0, &mut r).unwrap().1
            },
            move |c| {
                let mut r = ChaCha20Rng::seed_from_u64(2);
                let mut p = CotPair::setup(c, &mut r, d1, true).unwrap();
                p.enable_ferret(c, FerretConfig::TOY, &mut r).unwrap();
                p.extend(c, &[], 1500, &mut r).unwrap().0
            },
        );
        for j in 0..1500 {
            assert_eq!(m[j], k[j] ^ d1.and_bit(choices[j]));
        }
    }

    #[test]
    fn cheating_sender_is_caught() {
        let (r0, r1) = run_two_party(
            |c| {
                let mut r = ChaCha20Rng::seed_from_u64(1);
                let mut p = CotPair::setup(c, &mut r, Block(4), true).unwrap();
                p.enable_ferret(c, FerretConfig::TOY, &mut r).unwrap();
                p.ferret.as_mut().unwrap().sender.fault_next = true;
                p.extend(c, &[], 5000, &mut r).map(|_| ())
            },
            |c| {
                let mut r = ChaCha20Rng::seed_from_u64(2);
                let mut p = CotPair::setup(c, &mut r, Block(5), true).unwrap();
                p.enable_ferret(c, FerretConfig::TOY, &mut r).unwrap();
                p.extend(c, &vec![false; 5000], 0, &mut r).map(|_| ())
            },
        );
        assert_eq!(r0, Err(Abort("Ferret consistency check failed")));
        assert_eq!(r1, Err(Abort("Ferret consistency check failed")));
    }
}
