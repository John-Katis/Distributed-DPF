//! mpz-ot-core's Ferret (YWL+20, regular-noise MPCOT, always with the SPCOT
//! consistency check) driven over [`dpf_common::net::Channel`], next to our
//! `dpf_common::ot::ferret`.
//!
//! mpz-ot-core is sans-IO: every step returns a serde message, which we
//! bincode-encode and send as one `Channel` message, so `CommStats` counts
//! bytes and rounds as for our code. One iteration is four messages
//! (R→S `ReceiverExtend`, S→R `SenderExtend`, R→S `ReceiverCheck`,
//! S→R `SenderCheck`), plus one `Init` (R→S, the LPN seed) at setup.
//!
//! mpz's bootstrap takes random COTs from any `RCOTSender`/`RCOTReceiver`.
//! [`BaseSender`]/[`BaseReceiver`] hand it COTs made by our `CotPair`
//! (endemic base OT + KOS), so Δ is the `CotPair`'s Δ.

use dpf_common::block::Block;
use dpf_common::net::Channel;
use mpz_common::future::{new_output, MaybeDone};
use mpz_core::lpn::LpnParameters;
use mpz_core::Block as MBlock;
use mpz_ot_core::ferret::{self, FerretConfig, REGULAR_PARAMS};
use mpz_ot_core::rcot::{RCOTReceiver, RCOTReceiverOutput, RCOTSender, RCOTSenderOutput};
use mpz_ot_core::TransferId;
use serde::de::DeserializeOwned;
use serde::Serialize;

pub fn to_m(b: Block) -> MBlock {
    MBlock::from(b.0.to_le_bytes())
}

pub fn from_m(b: MBlock) -> Block {
    Block(u128::from_le_bytes(b.to_bytes()))
}

#[derive(Debug)]
pub struct Error(pub String);

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Error {}

fn err(e: impl std::fmt::Display) -> Error {
    Error(e.to_string())
}

fn send<T: Serialize>(ch: &mut Channel, m: &T) {
    ch.send(bincode::serialize(m).unwrap());
}

fn recv<T: DeserializeOwned>(ch: &mut Channel) -> T {
    bincode::deserialize(&ch.recv()).unwrap()
}

/// Our sender-side base COTs (keys `K`), consumed from the back as mpz does.
pub struct BaseSender {
    delta: MBlock,
    keys: Vec<MBlock>,
    id: TransferId,
}

impl BaseSender {
    pub fn new(delta: Block, keys: &[Block]) -> Self {
        BaseSender { delta: to_m(delta), keys: keys.iter().map(|&k| to_m(k)).collect(), id: TransferId::default() }
    }
}

impl RCOTSender<MBlock> for BaseSender {
    type Error = Error;
    type Future = MaybeDone<RCOTSenderOutput<MBlock>>;

    fn alloc(&mut self, count: usize) -> Result<(), Error> {
        if count > self.keys.len() {
            return Err(Error(format!("base sender: {count} wanted, {} held", self.keys.len())));
        }
        Ok(())
    }

    fn available(&self) -> usize {
        self.keys.len()
    }

    fn delta(&self) -> MBlock {
        self.delta
    }

    fn try_send_rcot(&mut self, count: usize) -> Result<RCOTSenderOutput<MBlock>, Error> {
        self.alloc(count)?;
        let keys = self.keys.split_off(self.keys.len() - count);
        Ok(RCOTSenderOutput { id: self.id.next(), keys })
    }

    fn queue_send_rcot(&mut self, count: usize) -> Result<Self::Future, Error> {
        let out = self.try_send_rcot(count)?;
        let (tx, rx) = new_output();
        tx.send(out);
        Ok(rx)
    }
}

/// Our receiver-side base COTs (random `r`, `M = K ⊕ r·Δ`).
pub struct BaseReceiver {
    choices: Vec<bool>,
    msgs: Vec<MBlock>,
    id: TransferId,
}

impl BaseReceiver {
    pub fn new(choices: &[bool], msgs: &[Block]) -> Self {
        BaseReceiver { choices: choices.to_vec(), msgs: msgs.iter().map(|&m| to_m(m)).collect(), id: TransferId::default() }
    }
}

impl RCOTReceiver<bool, MBlock> for BaseReceiver {
    type Error = Error;
    type Future = MaybeDone<RCOTReceiverOutput<bool, MBlock>>;

    fn alloc(&mut self, count: usize) -> Result<(), Error> {
        if count > self.msgs.len() {
            return Err(Error(format!("base receiver: {count} wanted, {} held", self.msgs.len())));
        }
        Ok(())
    }

    fn available(&self) -> usize {
        self.msgs.len()
    }

    fn try_recv_rcot(&mut self, count: usize) -> Result<RCOTReceiverOutput<bool, MBlock>, Error> {
        self.alloc(count)?;
        let at = self.msgs.len() - count;
        Ok(RCOTReceiverOutput { id: self.id.next(), choices: self.choices.split_off(at), msgs: self.msgs.split_off(at) })
    }

    fn queue_recv_rcot(&mut self, count: usize) -> Result<Self::Future, Error> {
        let out = self.try_recv_rcot(count)?;
        let (tx, rx) = new_output();
        tx.send(out);
        Ok(rx)
    }
}

/// COTs one mpz iteration with `p` consumes (mpz's `iteration_cost`).
pub fn iteration_cost(p: LpnParameters) -> usize {
    p.t * (p.n / p.t).ilog2() as usize + p.k + 128
}

/// Base COTs mpz's bootstrap takes (the cost of `REGULAR_PARAMS[0]`).
pub fn bootstrap_cost() -> usize {
    iteration_cost(REGULAR_PARAMS[0])
}

/// LPN parameter choice.
#[derive(Clone, Copy, Debug)]
pub enum Params {
    /// mpz's own selector over `REGULAR_PARAMS` (n from 256,000 to 32,768,000,
    /// t = 2,000).
    Default,
    /// Our main parameters (emp-ot `ferret_b13`) whenever enough COTs are
    /// held, else the largest `REGULAR_PARAMS` entry that fits.
    Ours(LpnParameters),
}

pub fn config(p: Params) -> FerretConfig {
    match p {
        Params::Default => FerretConfig::default(),
        Params::Ours(main) => {
            let mut b = FerretConfig::builder();
            b.param_selector(move |available, _| {
                if available >= iteration_cost(main) {
                    return main;
                }
                REGULAR_PARAMS.iter().copied().filter(|&q| iteration_cost(q) <= available).last().unwrap_or(REGULAR_PARAMS[0])
            });
            b.build().unwrap()
        }
    }
}

/// `dpf_common::ot::FerretConfig::B13.main` as mpz parameters.
pub fn b13() -> LpnParameters {
    let m = dpf_common::ot::FerretConfig::B13.main;
    LpnParameters { n: m.n, k: m.k, t: m.t }
}

/// The Ferret sender of one direction (holds Δ).
pub struct MpzSender {
    inner: ferret::Sender<BaseSender>,
    /// Iterations run so far (the bootstrap one included).
    pub iterations: usize,
    /// Flips a bit in both masked keys of the first level of the next
    /// `SenderExtend`, for the abort test.
    pub fault_next: bool,
}

impl MpzSender {
    pub fn setup(ch: &mut Channel, seed: Block, p: Params, base: BaseSender) -> Result<Self, Error> {
        let mut inner = ferret::Sender::new(to_m(seed), config(p), base);
        inner.initialize(recv(ch)).map_err(err)?;
        inner.alloc_bootstrap().map_err(err)?;
        Ok(MpzSender { inner, iterations: 0, fault_next: false })
    }

    pub fn available(&self) -> usize {
        self.inner.available()
    }

    /// Runs iterations until at least `m` COTs are held.
    pub fn ensure(&mut self, ch: &mut Channel, m: usize) -> Result<(), Error> {
        if self.inner.available() >= m {
            return Ok(());
        }
        self.inner.alloc(m).map_err(err)?;
        while self.inner.wants_extend() {
            self.inner.start_extend().map_err(err)?;
            let msg = self.inner.extend(recv(ch)).map_err(err)?;
            let mut bytes = bincode::serialize(&msg).unwrap();
            if std::mem::take(&mut self.fault_next) {
                // Vec length (8 bytes), then [Block; 2] = 32 bytes.
                bytes[8] ^= 1;
                bytes[8 + 16] ^= 1;
            }
            ch.send(bytes);
            let msg = self.inner.check(recv(ch)).map_err(err)?;
            send(ch, &msg);
            self.inner.finish_extend().map_err(err)?;
            self.iterations += 1;
        }
        Ok(())
    }

    /// Takes `m` random COT keys `K`. Call [`ensure`](Self::ensure) first.
    pub fn take(&mut self, m: usize) -> Result<Vec<Block>, Error> {
        Ok(self.inner.try_send_rcot(m).map_err(err)?.keys.into_iter().map(from_m).collect())
    }
}

/// The Ferret receiver of one direction.
pub struct MpzReceiver {
    inner: ferret::Receiver<BaseReceiver>,
    pub iterations: usize,
}

impl MpzReceiver {
    pub fn setup(ch: &mut Channel, seed: Block, p: Params, base: BaseReceiver) -> Result<Self, Error> {
        let mut inner = ferret::Receiver::new(to_m(seed), config(p), base);
        send(ch, &inner.initialize().map_err(err)?);
        inner.alloc_bootstrap().map_err(err)?;
        Ok(MpzReceiver { inner, iterations: 0 })
    }

    pub fn available(&self) -> usize {
        self.inner.available()
    }

    pub fn ensure(&mut self, ch: &mut Channel, m: usize) -> Result<(), Error> {
        if self.inner.available() >= m {
            return Ok(());
        }
        self.inner.alloc(m).map_err(err)?;
        while self.inner.wants_extend() {
            send(ch, &self.inner.start_extend().map_err(err)?);
            let msg = self.inner.extend(recv(ch)).map_err(err)?;
            send(ch, &msg);
            self.inner.finish_extend(recv(ch)).map_err(err)?;
            self.iterations += 1;
        }
        Ok(())
    }

    /// Takes `m` random COTs `(r_j, M_j)`.
    pub fn take(&mut self, m: usize) -> Result<(Vec<bool>, Vec<Block>), Error> {
        let out = self.inner.try_recv_rcot(m).map_err(err)?;
        Ok((out.choices, out.msgs.into_iter().map(from_m).collect()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dpf_common::net::run_two_party;
    use dpf_common::ot::cot::RandomCots;
    use dpf_common::ot::CotPair;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    /// Small parameters (mpz's own test set) after the bootstrap iteration.
    const SMALL: LpnParameters = LpnParameters { n: 9600, k: 1220, t: 600 };

    fn small() -> Params {
        // n/t = 16, a power of two as mpz requires.
        Params::Ours(SMALL)
    }

    /// Party 0 is the sender: KOS base COTs from our `CotPair`, then mpz.
    fn run(sizes: &'static [usize], fault_at: Option<usize>) -> (Block, Vec<Vec<Block>>, Result<Vec<(Vec<bool>, Vec<Block>)>, Error>) {
        let base = bootstrap_cost();
        let (s, r) = run_two_party(
            move |ch| {
                let mut rng = ChaCha20Rng::seed_from_u64(1);
                let delta = Block::random(&mut rng);
                let mut cot = CotPair::setup(ch, &mut rng, delta, true).unwrap();
                let RandomCots::Sender(k) = cot.random_cots(ch, 0, base, &mut rng).unwrap() else { unreachable!() };
                let mut s = MpzSender::setup(ch, Block::random(&mut rng), small(), BaseSender::new(delta, &k)).unwrap();
                let mut out = vec![];
                for (i, &m) in sizes.iter().enumerate() {
                    s.fault_next = fault_at == Some(i);
                    s.ensure(ch, m).unwrap();
                    out.push(s.take(m).unwrap());
                }
                (delta, out)
            },
            move |ch| {
                let mut rng = ChaCha20Rng::seed_from_u64(2);
                let delta = Block::random(&mut rng);
                let mut cot = CotPair::setup(ch, &mut rng, delta, true).unwrap();
                let RandomCots::Receiver(b, m) = cot.random_cots(ch, 0, base, &mut rng).unwrap() else { unreachable!() };
                let mut r = MpzReceiver::setup(ch, Block::random(&mut rng), small(), BaseReceiver::new(&b, &m)).unwrap();
                let mut out = vec![];
                for &m in sizes {
                    r.ensure(ch, m)?;
                    out.push(r.take(m)?);
                }
                Ok(out)
            },
        );
        (s.0, s.1, r)
    }

    /// mpz bootstrapped from our KOS COTs: every output satisfies
    /// `M = K ⊕ r·Δ` with our Δ, over several refills.
    #[test]
    fn correlation_with_our_delta() {
        static SIZES: [usize; 4] = [1, 5000, 300_000, 20_000];
        let (delta, keys, got) = run(&SIZES, None);
        let got = got.unwrap();
        for (k, (r, m)) in keys.iter().zip(&got) {
            assert_eq!(k.len(), r.len());
            let ones = r.iter().filter(|&&b| b).count();
            assert!(r.len() < 100 || (ones > r.len() / 3 && ones < 2 * r.len() / 3));
            for j in 0..k.len() {
                assert_eq!(m[j], k[j] ^ delta.and_bit(r[j]));
            }
        }
    }

    /// A corrupted `SenderExtend` makes the receiver's consistency check fail.
    /// The faulty iteration is the last one of the run (the bootstrap one,
    /// or a refill after it), since mpz sends no abort message and the
    /// sender would otherwise wait for the next iteration.
    #[test]
    fn tampered_extend_aborts() {
        static RUNS: [&[usize]; 2] = [&[5000], &[5000, 5800]];
        for (at, sizes) in RUNS.iter().enumerate() {
            let (_, _, got) = run(sizes, Some(at));
            let e = got.expect_err("tampering went unnoticed");
            assert!(e.0.contains("consistency"), "unexpected error: {e}");
        }
    }
}
