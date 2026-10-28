//! Ferret COT extension (Yang–Weng–Lan–Zhang–Wang, "Ferret: Fast Extension for
//! coRRElated OT with small communicaTion", CCS'20), the F_COT instantiation of
//! the malicious DPF paper (ZGY+24 §7.1), from emp-ot's `FerretCOT` (the
//! authors' implementation) through [`dpf_ot_sys`].
//!
//! Each direction is one emp instance: regular-noise MPCOT over GGM trees,
//! then the local linear code (d = 10). Malicious mode adds the SPCOT
//! consistency check. The `pre` iteration runs on base COTs that we hand in
//! from our `CotPair` (KOS-checked IKNP on Masny–Rindal, or semi-honest IKNP on
//! Naor–Pinkas), not on emp's own IKNP-over-Chou–Orlandi; every later
//! iteration reserves part of its output for the next, as in Ferret's
//! bootstrapping. emp's semi-honest receiver takes its punctured indices from
//! its random base-COT choices, so a refill is one message from the sender.
//!
//! **lsb(Δ).** emp packs the receiver's choice bit into `lsb(M)`, so it needs
//! `lsb(Δ) = 1` and `lsb(K) = 0`. A sender whose Δ has lsb 0 (e.g. party 0 in
//! ht-aes and Half-Tree, `lsb(Δ_b) = b`) runs emp with `Δ' = Δ ⊕ 1`. Our base
//! COTs under Δ are valid under Δ' after emp's own normalisation (`K` with lsb
//! cleared, `M` with lsb set to the choice). The receiver turns emp's output
//! back into a COT under Δ by clearing lsb(M), which needs to know lsb(Δ):
//! [`FerretPair::bootstrap`] exchanges it (one bit per direction, the bit emp
//! itself fixes to 1).
//!
//! **Abort.** In malicious mode the receiver sends the check's verdict (one
//! byte) after every refill, so a sender facing an aborting receiver returns
//! [`Abort`] instead of waiting.
//!
//! [`FerretPair`] is one party's two instances (sender with its own Δ, receiver
//! of the peer's). Chosen-choice COTs are derandomised with one bit each.

use crate::block::Block;
use crate::coin::Abort;
use crate::net::Channel;
use dpf_ot_sys::{Ferret, FerretParams};
use rand::{CryptoRng, Rng, RngCore};

/// Nonzero entries per column of the LPN code (emp's `LpnF2<_, 10>`).
pub const LPN_D: usize = 10;

/// COTs emp sets aside per iteration for the SPCOT consistency check. emp
/// reserves them in both modes.
const CHECK_COTS: usize = 128;

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
    /// and emp's 128 check COTs (set aside even in semi-honest mode).
    pub fn consumed(&self, _malicious: bool) -> usize {
        self.k + self.t * self.log_bin + CHECK_COTS
    }
}

/// Bootstrapping (`pre`) and steady-state (`main`) parameters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FerretConfig {
    pub pre: LpnParams,
    pub main: LpnParams,
}

impl FerretConfig {
    /// emp-ot's `ferret_b13` (128-bit security against the attacks considered
    /// in YWL+20 §6): main `n = 10,485,760, k = 452,000, t = 1,280, h = 13`,
    /// pre `n = 470,016, k = 32,768, t = 918, h = 9`.
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
        for p in [self.pre, self.main] {
            assert_eq!(p.n, p.t << p.log_bin, "n must equal t·2^log_bin");
            assert!(p.consumed(malicious) < p.n, "an iteration must produce more than it consumes");
        }
        assert!(self.pre.n >= self.main.consumed(malicious), "pre output must cover main's reserve");
    }

    /// emp's `PrimalLPNParameter`.
    fn emp(&self) -> FerretParams {
        let (m, p) = (self.main, self.pre);
        [m.n, m.t, m.k, m.log_bin, p.n, p.t, p.k, p.log_bin].map(|x| x as i64)
    }

    /// COTs needed from the base OT extension to bootstrap.
    pub fn base_cots(&self, _malicious: bool) -> usize {
        dpf_ot_sys::ferret_base_cots(&self.emp())
    }

    /// Fresh COTs per main iteration.
    pub fn yield_per_iteration(&self, malicious: bool) -> usize {
        self.main.n - self.main.consumed(malicious)
    }
}

fn ferret_abort(e: dpf_ot_sys::OtError) -> Abort {
    super::abort(e, "Ferret consistency check failed")
}

/// Main iterations emp runs to hand out `n` more COTs with `left` buffered.
fn iterations_for(n: usize, left: usize, limit: usize) -> usize {
    n.saturating_sub(left).div_ceil(limit)
}

/// The Ferret sender of one direction: keys `K` with `M = K ⊕ r·Δ` at the peer.
pub struct FerretSender {
    ot: Ferret,
    malicious: bool,
    /// Byte offset of the first tree's secret sum in a refill: emp sends
    /// `log_bin` levels of `(M_0, M_1)` (32 bytes) per tree before it.
    sum_offset: usize,
    buf: Vec<Block>,
    pos: usize,
    /// Main iterations run so far.
    pub iterations: usize,
    /// Corrupts the first tree's secret sum in the next refill (tests of the
    /// receiver's check).
    #[doc(hidden)]
    pub fault_next: bool,
}

/// The Ferret receiver of one direction.
pub struct FerretReceiver {
    ot: Ferret,
    malicious: bool,
    /// `lsb(Δ) = 0` at the sender: emp runs with `Δ ⊕ 1`.
    flip: bool,
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
        _rng: &mut R,
    ) -> Result<Self, Abort> {
        cfg.validate(malicious);
        let mut ot = Ferret::new(true, malicious, &cfg.emp()).map_err(ferret_abort)?;
        let base: Vec<u128> = base.iter().map(|b| b.0).collect();
        ot.setup(ch, Some(delta.0 | 1), &base, &[]).map_err(ferret_abort)?;
        Ok(FerretSender { ot, malicious, sum_offset: 32 * cfg.main.log_bin, buf: vec![], pos: 0, iterations: 0, fault_next: false })
    }

    pub fn available(&self) -> usize {
        self.buf.len() - self.pos
    }

    /// Runs main iterations until at least `m` COTs are buffered.
    pub fn ensure<R: RngCore + CryptoRng>(&mut self, ch: &mut Channel, m: usize, _rng: &mut R) -> Result<(), Abort> {
        let need = m.saturating_sub(self.available());
        if need == 0 {
            return Ok(());
        }
        if std::mem::take(&mut self.fault_next) {
            self.ot.fault_next = Some(self.sum_offset);
        }
        let (left, limit) = self.ot.state();
        let k = self.ot.rcot(ch, need).map_err(ferret_abort)?;
        if self.malicious && ch.try_recv().as_deref() != Some(&[1]) {
            return Err(Abort("peer aborted"));
        }
        self.iterations += iterations_for(need, left, limit);
        self.buf.drain(..self.pos);
        self.pos = 0;
        self.buf.extend(k.into_iter().map(Block));
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
    /// Runs the `pre` iteration on base COTs `(bits, macs)`. `sender_lsb` is
    /// `lsb(Δ)` of the sender (see the module docs).
    #[allow(clippy::too_many_arguments)]
    pub fn bootstrap<R: RngCore + CryptoRng>(
        ch: &mut Channel,
        cfg: FerretConfig,
        bits: &[bool],
        macs: &[Block],
        sender_lsb: bool,
        malicious: bool,
        _rng: &mut R,
    ) -> Result<Self, Abort> {
        cfg.validate(malicious);
        let mut ot = Ferret::new(false, malicious, &cfg.emp()).map_err(ferret_abort)?;
        let macs: Vec<u128> = macs.iter().map(|b| b.0).collect();
        ot.setup(ch, None, &macs, bits).map_err(ferret_abort)?;
        Ok(FerretReceiver { ot, malicious, flip: !sender_lsb, buf: (vec![], vec![]), pos: 0, iterations: 0 })
    }

    pub fn available(&self) -> usize {
        self.buf.1.len() - self.pos
    }

    pub fn ensure<R: RngCore + CryptoRng>(&mut self, ch: &mut Channel, m: usize, _rng: &mut R) -> Result<(), Abort> {
        let need = m.saturating_sub(self.available());
        if need == 0 {
            return Ok(());
        }
        let (left, limit) = self.ot.state();
        let out = self.ot.rcot(ch, need);
        if self.malicious {
            // The verdict of the check, so the sender does not wait for a
            // receiver that aborted.
            ch.try_send(vec![out.is_ok() as u8]);
        }
        let out = out.map_err(ferret_abort)?;
        self.iterations += iterations_for(need, left, limit);
        self.buf.0.drain(..self.pos);
        self.buf.1.drain(..self.pos);
        self.pos = 0;
        for x in out {
            let r = x & 1 == 1;
            self.buf.0.push(r);
            self.buf.1.push(Block(if self.flip { x & !1 } else { x }));
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
    malicious: bool,
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
        // The lsb of each sender's Δ, both in one round.
        ch.send(vec![delta.lsb() as u8]);
        let peer_lsb = ch.recv().first() == Some(&1);
        // Direction 0 (party 0 sends) always runs first.
        let (sender, receiver) = if party == 0 {
            let s = FerretSender::bootstrap(ch, cfg, delta, k, malicious, rng)?;
            (s, FerretReceiver::bootstrap(ch, cfg, bits, macs, peer_lsb, malicious, rng)?)
        } else {
            let r = FerretReceiver::bootstrap(ch, cfg, bits, macs, peer_lsb, malicious, rng)?;
            (FerretSender::bootstrap(ch, cfg, delta, k, malicious, rng)?, r)
        };
        let mut p = FerretPair { party, delta, malicious, sender, receiver };
        let full = cfg.yield_per_iteration(malicious);
        p.ensure(ch, full, full, rng)?;
        Ok(p)
    }

    /// Refills until `mine` COTs as receiver and `theirs` as sender are
    /// buffered. Semi-honest refills are one message from each sender, so
    /// both parties refill as sender first and the two directions share a
    /// round. Malicious refills are interactive and run direction 0 first.
    pub fn ensure<R: RngCore + CryptoRng>(&mut self, ch: &mut Channel, mine: usize, theirs: usize, rng: &mut R) -> Result<(), Abort> {
        if !self.malicious || self.party == 0 {
            self.sender.ensure(ch, theirs, rng)?;
            self.receiver.ensure(ch, mine, rng)
        } else {
            self.receiver.ensure(ch, mine, rng)?;
            self.sender.ensure(ch, theirs, rng)
        }
    }

    /// Chosen-choice COTs in both directions, as `CotPair::extend`: refills if
    /// needed, then derandomises with one bit per COT (one round).
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

    /// Runs several extend batches; party 0 receives `a` and party 1 receives
    /// `b` COTs per batch on random chosen bits, and checks `M = K ⊕ c·Δ`.
    /// `d` are the parties' Δ, so the lsb-0 path of the module docs is covered.
    fn run(malicious: bool, d: [Block; 2], sizes: &[(usize, usize)]) {
        let mut rng = ChaCha20Rng::seed_from_u64(7);
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
        // Crosses several refills in both directions (TOY yields ~500 per iteration).
        let sizes = [(10, 3), (700, 50), (1, 1300), (2000, 2000)];
        let mut rng = ChaCha20Rng::seed_from_u64(3);
        let random = [Block::random(&mut rng), Block::random(&mut rng)];
        // lsb(Δ_b) = b as in ht-aes and Half-Tree: party 0's Δ has lsb 0.
        let lsb_b = [random[0].with_lsb(false), random[1].with_lsb(true)];
        for d in [random, lsb_b] {
            run(false, d, &sizes);
            run(true, d, &sizes);
        }
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

    /// A sender that corrupts a refill is caught by the receiver's check; the
    /// sender then sees the receiver abort.
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
        assert_eq!(r1, Err(Abort("Ferret consistency check failed")));
        assert_eq!(r0, Err(Abort("peer aborted")));
    }
}
