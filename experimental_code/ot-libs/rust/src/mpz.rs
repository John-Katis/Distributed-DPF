//! mpz-ot-core (sans-IO) over our `Channel`: every message is bincode-encoded
//! and sent as one `Channel` message. Chou–Orlandi base OT (128 chosen-message
//! OTs), KOS random COT with Δ (base OTs from mpz's Chou–Orlandi), and Ferret
//! on our KOS base COTs (`exp_mpz_ferret`).

use crate::count::{emit, Meas};
use dpf_common::block::Block;
use dpf_common::net::{run_two_party, Channel};
use dpf_common::ot::cot::RandomCots;
use dpf_common::ot::CotPair;
use exp_mpz_ferret::{b13, bootstrap_cost, from_m, BaseReceiver, BaseSender, MpzReceiver, MpzSender, Params};
use mpz_common::future::Output;
use mpz_core::Block as MBlock;
use mpz_ot_core::chou_orlandi;
use mpz_ot_core::kos::{self, ReceiverConfig, SenderConfig, CSP};
use mpz_ot_core::ot::{OTReceiver, OTReceiverOutput, OTSender};
use mpz_ot_core::rcot::{RCOTReceiver, RCOTReceiverOutput, RCOTSender, RCOTSenderOutput};
use rand::SeedableRng;
use rand010::{RngExt, SeedableRng as _};
use rand_chacha::ChaCha20Rng;
use serde::de::DeserializeOwned;
use serde::Serialize;

const LIB: &str = "mpz";

fn send<T: Serialize>(ch: &mut Channel, m: &T) {
    ch.send(bincode::serialize(m).unwrap());
}

fn recv<T: DeserializeOwned>(ch: &mut Channel) -> T {
    bincode::deserialize(&ch.recv()).unwrap()
}

fn rng010(seed: u64) -> rand010::rngs::StdRng {
    rand010::rngs::StdRng::seed_from_u64(seed)
}

/// CO sender side: SenderSetup, then SenderPayload for the receiver's choices.
fn co_send(ch: &mut Channel, data: &[[MBlock; 2]], seed: u64) {
    let (setup, mut s) = chou_orlandi::Sender::new_with_seed(rng010(seed).random()).setup();
    send(ch, &setup);
    let _out = s.queue_send_ot(data).unwrap();
    let payload = s.send(recv(ch)).unwrap();
    send(ch, &payload);
}

fn co_recv(ch: &mut Channel, choices: &[bool], seed: u64) -> Vec<MBlock> {
    let mut r = chou_orlandi::Receiver::new_with_seed(rng010(seed).random()).setup(recv(ch));
    let mut out = r.queue_recv_ot(choices).unwrap();
    send(ch, &r.choose());
    r.receive(recv(ch)).unwrap();
    let OTReceiverOutput { msgs, .. } = out.try_recv().unwrap().unwrap();
    msgs
}

pub fn base_co() {
    let n = 128;
    let mut r = rng010(1);
    let data: Vec<[MBlock; 2]> = (0..n).map(|_| [r.random(), r.random()]).collect();
    let choices: Vec<bool> = (0..n).map(|_| r.random()).collect();
    let (d2, c2) = (data.clone(), choices.clone());
    let ((m0, ()), (m1, got)) = run_two_party(
        move |ch| {
            let mut m = Meas::default();
            m.start_ch(ch, 0);
            co_send(ch, &d2, 2);
            m.stop_ch(ch);
            (m, ())
        },
        move |ch| {
            let mut m = Meas::default();
            m.start_ch(ch, 0);
            let got = co_recv(ch, &c2, 3);
            m.stop_ch(ch);
            (m, got)
        },
    );
    let ok = (0..n).all(|i| got[i] == data[i][choices[i] as usize]);
    emit(LIB, "base-co", "-", n, &["all"], &m0, &m1, ok);
}

/// KOS random COT, one direction. Setup: 128 Chou–Orlandi OTs with the KOS
/// sender (party 0) choosing by the bits of Δ. Extend: the receiver's
/// `Extend` messages, then the check (χ seed from the sender, as mpz's own
/// tests do; mpz-ot tosses a coin for it).
pub fn kos(n: usize) {
    let ((m0, delta, k), (m1, (r, mm))) = run_two_party(
        move |ch| {
            let delta: MBlock = rng010(4).random();
            let mut m = Meas::default();
            m.start_ch(ch, 1);
            let bits: Vec<bool> = { let d = u128::from_le_bytes(delta.to_bytes()); (0..CSP).map(|i| (d >> i) & 1 == 1).collect() };
            let seeds = co_recv(ch, &bits, 5);
            let mut s = kos::Sender::new(SenderConfig::default(), delta).setup(seeds.try_into().unwrap());
            m.stop_ch(ch);
            m.start_ch(ch, 1);
            s.alloc(n).unwrap();
            while s.wants_extend() {
                s.extend(recv(ch)).unwrap();
            }
            let chi: MBlock = s.check_start();
            send(ch, &chi);
            s.check(recv(ch)).unwrap();
            let RCOTSenderOutput { keys, .. } = s.try_send_rcot(n).unwrap();
            m.stop_ch(ch);
            (m, from_m(delta), keys.into_iter().map(from_m).collect::<Vec<Block>>())
        },
        move |ch| {
            let mut rr = rng010(6);
            let seeds: Vec<[MBlock; 2]> = (0..CSP).map(|_| [rr.random(), rr.random()]).collect();
            let mut m = Meas::default();
            m.start_ch(ch, 1);
            co_send(ch, &seeds, 7);
            let mut r = kos::Receiver::new(ReceiverConfig::default()).setup(seeds.try_into().unwrap());
            m.stop_ch(ch);
            m.start_ch(ch, 1);
            r.alloc(n).unwrap();
            while r.wants_extend() {
                send(ch, &r.extend().unwrap());
            }
            let chi: MBlock = recv(ch);
            send(ch, &r.check(chi).unwrap());
            let RCOTReceiverOutput { choices, msgs, .. } = r.try_recv_rcot(n).unwrap();
            m.stop_ch(ch);
            (m, (choices, msgs.into_iter().map(from_m).collect::<Vec<Block>>()))
        },
    );
    let ones = r.iter().filter(|&&b| b).count();
    let ok = ones > n / 3 && ones < 2 * n / 3 && (0..n).all(|j| mm[j] == k[j] ^ delta.and_bit(r[j]));
    emit(LIB, "cot", "mal", n, &["setup", "extend"], &m0, &m1, ok);
}

/// mpz Ferret (always with the check) on our malicious `CotPair` base COTs.
pub fn ferret(p: Params, n: usize) {
    let name = match p {
        Params::Default => "ferret-default",
        Params::Ours(_) => "ferret-b13",
    };
    let ((m0, delta, k), (m1, rm)) = run_two_party(
        move |ch| {
            let mut rng = ChaCha20Rng::seed_from_u64(20);
            let delta = Block::random(&mut rng);
            let mut m = Meas::default();
            m.start_ch(ch, 0);
            let mut cot = CotPair::setup(ch, &mut rng, delta, true).unwrap();
            let RandomCots::Sender(base) = cot.random_cots(ch, 0, bootstrap_cost(), &mut rng).unwrap() else { unreachable!() };
            let mut s = MpzSender::setup(ch, Block::random(&mut rng), p, BaseSender::new(delta, &base)).unwrap();
            m.stop_ch(ch);
            let mut k = vec![];
            for _ in 0..2 {
                m.start_ch(ch, 1);
                s.ensure(ch, n).unwrap();
                k.push(s.take(n).unwrap());
                m.stop_ch(ch);
            }
            (m, delta, k)
        },
        move |ch| {
            let mut rng = ChaCha20Rng::seed_from_u64(21);
            let mut m = Meas::default();
            m.start_ch(ch, 0);
            let mut cot = { let d = Block::random(&mut rng); CotPair::setup(ch, &mut rng, d, true) }.unwrap();
            let RandomCots::Receiver(b, mm) = cot.random_cots(ch, 0, bootstrap_cost(), &mut rng).unwrap() else { unreachable!() };
            let mut r = MpzReceiver::setup(ch, Block::random(&mut rng), p, BaseReceiver::new(&b, &mm)).unwrap();
            m.stop_ch(ch);
            let mut out = vec![];
            for _ in 0..2 {
                m.start_ch(ch, 1);
                r.ensure(ch, n).unwrap();
                out.push(r.take(n).unwrap());
                m.stop_ch(ch);
            }
            (m, out)
        },
    );
    let ok = (0..2).all(|p| {
        let (r, mm) = &rm[p];
        (0..n).all(|j| mm[j] == k[p][j] ^ delta.and_bit(r[j]))
    });
    emit(LIB, name, "mal", n, &["setup", "first N", "next N"], &m0, &m1, ok);
}

pub fn ferret_both(n: usize) {
    ferret(Params::Ours(b13()), n);
    ferret(Params::Default, n);
}
