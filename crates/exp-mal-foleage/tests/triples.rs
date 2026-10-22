//! Both approaches produce correct, authenticated triples; (b) catches a cheat.

use dpf_common::block::Block;
use dpf_common::coin::Abort;
use dpf_common::f4;
use dpf_common::foleage::Params;
use dpf_common::mac::af4::{dealer, AuthTriple};
use dpf_common::mac::binary::{delta_for_seed, MacParty};
use dpf_common::net::run_two_party;
use dpf_common::ot::FerretConfig;
use exp_mal_foleage::pcg::{deal, Mode};
use exp_mal_foleage::sacrifice::{authenticate_and_sacrifice, Cheat};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

fn open_f4(x: dpf_common::aes_tower::F4Sh<dpf_common::mac::af4::ABit>, y: dpf_common::aes_tower::F4Sh<dpf_common::mac::af4::ABit>, d: [Block; 2]) -> u8 {
    let h = dealer::open(&[x.h, y.h], d).expect("MAC on h");
    let l = dealer::open(&[x.l, y.l], d).expect("MAC on l");
    (h as u8) << 1 | l as u8
}

fn check(t0: &[AuthTriple], t1: &[AuthTriple], d: [Block; 2]) {
    for (x, y) in t0.iter().zip(t1) {
        let (a, b, c) = (open_f4(x.a, y.a, d), open_f4(x.b, y.b, d), open_f4(x.c, y.c, d));
        assert_eq!(c, f4::mul(a, b));
    }
}

#[test]
fn full_mode_triples_are_authenticated() {
    let mut rng = ChaCha20Rng::seed_from_u64(1);
    let d = [Block::random(&mut rng).with_lsb(false), Block::random(&mut rng).with_lsb(true)];
    let s = deal(Params::new(7), Mode::Full, d, &mut rng);
    let (r0, r1) = (s[0].expand(), s[1].expand());
    check(&r0.full_triples(), &r1.full_triples(), d);
}

fn run_b(cheat: [Option<Cheat>; 2]) -> [Result<Vec<AuthTriple>, Abort>; 2] {
    let seeds: [[u8; 32]; 2] = [[7; 32], [8; 32]];
    let d = [delta_for_seed(seeds[0], 0), delta_for_seed(seeds[1], 1)];
    let mut rng = ChaCha20Rng::seed_from_u64(2);
    let [s0, s1] = deal(Params::new(7), Mode::Linear, d, &mut rng);
    let party = |seed: [u8; 32], s: exp_mal_foleage::pcg::Seed, c: Option<Cheat>| {
        move |ch: &mut dpf_common::net::Channel| {
            let mut mac = MacParty::setup(ch, seed).unwrap();
            let mut r = mac.rng().clone();
            mac.cot.enable_ferret(ch, FerretConfig::TOY, &mut r).unwrap();
            *mac.rng() = r;
            assert_eq!(mac.delta(), s.keys[0]);
            let raw = s.expand();
            authenticate_and_sacrifice(ch, &mut mac, &raw, 400, c)
        }
    };
    let (a, b) = run_two_party(party(seeds[0], s0, cheat[0]), party(seeds[1], s1, cheat[1]));
    [a, b]
}

#[test]
fn sacrifice_mode_triples_are_authenticated() {
    let seeds: [[u8; 32]; 2] = [[7; 32], [8; 32]];
    let d = [delta_for_seed(seeds[0], 0), delta_for_seed(seeds[1], 1)];
    let [a, b] = run_b([None, None]);
    check(&a.unwrap(), &b.unwrap(), d);
}

#[test]
fn sacrifice_catches_a_shifted_c() {
    for idx in [0, 5, 1999] {
        let [a, b] = run_b([None, Some(Cheat { index: idx })]);
        assert!(a.is_err() && b.is_err(), "index {idx}");
    }
}
