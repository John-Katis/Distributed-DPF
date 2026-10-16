//! Duoram's adjusted DPF against the cleartext point function over Z_2^w.

use dpf_common::arith::mask;
use duoram::{deal, gen_reference, run_gen_2p, run_gen_3p, DuoramKey, Lanes, Run};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;

const SIZES: &[u64] = &[2, 3, 5, 64, 1000, 1024, (1 << 12) + 3];
const BITS: &[usize] = &[1, 16, 64];
/// Widths on 128-bit words.
const WIDE: &[usize] = &[65, 128];

fn check<R: Lanes>(keys: &[DuoramKey<R>; 2], n: u64, alpha: u64, beta: R) {
    let m = R::mask(keys[0].bits);
    let ctx = format!("N={n} alpha={alpha} bits={}", keys[0].bits);
    assert_eq!(keys[0].public_part(), keys[1].public_part(), "{ctx}");
    let ev = [keys[0].eval_full(), keys[1].eval_full()];
    for x in 0..n {
        let want = if x == alpha { beta } else { R::ZERO };
        let p = [keys[0].eval_point(x), keys[1].eval_point(x)];
        assert_eq!(p[0].add(p[1]).and(m), want, "eval_point at x={x}: {ctx}");
        assert_eq!((ev[0][x as usize], ev[1][x as usize]), (p[0], p[1]), "eval_full != eval_point at x={x}: {ctx}");
    }
}

/// The App. D lemma: the converted flags are additive shares of e_r.
fn converted_flags_in<R: Lanes>(bits: usize) {
    let mut rng = ChaCha20Rng::seed_from_u64(1);
    for &n in &[2u64, 8, 1024] {
        let keys = gen_reference(n, bits, 0, R::ZERO, rng.gen());
        // With β = 0 the output is F·t̃ − … ; check t̃ directly through the key fields.
        let leaves = [keys[0].leaves(), keys[1].leaves()];
        let (mut ones, mut total) = (0, R::ZERO);
        for i in 0..leaves[0].len() {
            let tt = |k: &DuoramKey<R>, l: dpf_common::block::Block| {
                let s = |x: R| if k.party == 1 { x.neg() } else { x };
                let (_, v2) = duoram::tree::lanes::<R>(l);
                let t = s(R::from_u64(l.lsb() as u64));
                t.mul(k.c).add(s(v2)).sub(t.mul(k.fbar))
            };
            let v = tt(&keys[0], leaves[0][i]).add(tt(&keys[1], leaves[1][i]));
            assert!(v == R::ZERO || v == R::ONE, "t̃ at {i} is {v:?}");
            ones += (v == R::ONE) as usize;
            total = total.add(v);
        }
        assert_eq!((ones, total), (1, R::ONE), "N={n}");
    }
}

/// The App. D lemma: the converted flags are additive shares of e_r.
#[test]
fn converted_flags_are_additive_unit_vector() {
    converted_flags_in::<u64>(64);
    converted_flags_in::<u128>(128);
}

fn dealer_in<R: Lanes>(widths: &[usize]) {
    let mut rng = ChaCha20Rng::seed_from_u64(2);
    for &n in SIZES {
        for &bits in widths {
            for alpha in [0, n - 1, rng.gen_range(0..n)] {
                let beta = R::random(&mut rng).and(R::mask(bits));
                check(&gen_reference(n, bits, alpha, beta, rng.gen()), n, alpha, beta);
            }
        }
    }
}

#[test]
fn dealer_keys_match_cleartext_function() {
    dealer_in::<u64>(BITS);
    dealer_in::<u128>(WIDE);
}

fn check_run<R: Lanes>(run: Run<R>, n: u64, bits: usize, alpha: u64, beta: R) {
    let [o0, o1] = run.outs;
    let keys = [o0.key, o1.key];
    check(&keys, n, alpha, beta);
    // The preprocessing builds the same tree as the dealer for the same roots
    // and target.
    let r = alpha.wrapping_sub(keys[0].shift) & mask(keys[0].depth());
    let dealt = deal([keys[0].root, keys[1].root], n, bits, alpha, beta, r, R::ZERO);
    assert_eq!(dealt[0].cws, keys[0].cws, "N={n} alpha={alpha}");
    assert_eq!(dealt[0].f.and(R::mask(bits)), keys[0].f.and(R::mask(bits)), "N={n} alpha={alpha}");
    // The online phase is one round of two words each way.
    assert_eq!(o0.online_stats.bytes_sent, 2 * R::BYTES);
}

fn two_party_in<R: Lanes>(widths: &[usize], rng_seed: u64) {
    let mut rng = ChaCha20Rng::seed_from_u64(rng_seed);
    let mut seed = rng_seed << 32;
    for &n in SIZES {
        for &bits in widths {
            for alpha in [0, n - 1, rng.gen_range(0..n)] {
                let beta = R::random(&mut rng).and(R::mask(bits));
                seed += 1;
                check_run(run_gen_2p(n, bits, alpha, beta, seed), n, bits, alpha, beta);
            }
        }
    }
}

#[test]
fn two_party_gen_matches_cleartext_function() {
    two_party_in::<u64>(BITS, 3);
}

#[test]
fn two_party_gen_matches_cleartext_function_128() {
    two_party_in::<u128>(WIDE, 5);
}

fn three_party_in<R: Lanes>(widths: &[usize], rng_seed: u64) {
    let mut rng = ChaCha20Rng::seed_from_u64(rng_seed);
    let mut seed = rng_seed << 32;
    for &n in SIZES {
        for &bits in widths {
            for alpha in [0, n - 1, rng.gen_range(0..n)] {
                let beta = R::random(&mut rng).and(R::mask(bits));
                seed += 1;
                let run = run_gen_3p(n, bits, alpha, beta, seed);
                assert!(run.helper.unwrap().bytes_sent > 0);
                check_run(run, n, bits, alpha, beta);
            }
        }
    }
}

#[test]
fn three_party_gen_matches_cleartext_function() {
    three_party_in::<u64>(BITS, 4);
}

#[test]
fn three_party_gen_matches_cleartext_function_128() {
    three_party_in::<u128>(WIDE, 6);
}

/// Every ring word on the wire has the width of the ring: going from 64- to
/// 128-bit words adds 8 bytes per word and, in 2P, 64 Gilboa COTs per
/// full-width product.
#[test]
fn traffic_follows_word_width() {
    let n = 1000;
    let depth = dpf_common::block::depth_for(n);
    let (a, b) = (run_gen_3p(n, 64, 3, 5u64, 1), run_gen_3p(n, 128, 3, 5u128, 1));
    // P2 deals n + 2 product triples of two words each.
    assert_eq!(b.outs[0].helper_bytes - a.outs[0].helper_bytes, (depth + 2) * 2 * 8);
    // P0's masked inputs (n + 2 words) and the two openings of each phase.
    let sent64 = a.outs[0].pre_stats.bytes_sent + a.outs[0].online_stats.bytes_sent;
    let sent128 = b.outs[0].pre_stats.bytes_sent + b.outs[0].online_stats.bytes_sent;
    assert_eq!(sent128 - sent64, (depth + 2 + 2 + 2) * 8);
    let (a, b) = (run_gen_2p(n, 64, 3, 5u64, 1), run_gen_2p(n, 128, 3, 5u128, 1));
    assert_eq!(b.outs[0].cots - a.outs[0].cots, 2 * 64);
}

#[test]
fn public_words_do_not_leak() {
    let mut rng = ChaCha20Rng::seed_from_u64(29);
    let trials = 64;
    let mut lsb_hits = 0;
    for _ in 0..trials {
        let n = 1 << 8;
        let beta: u64 = rng.gen();
        let keys = gen_reference(n, 64, rng.gen_range(0..n), beta, rng.gen());
        // The CW's lsb would equal the off-path flag CW and reveal r_i.
        assert!(keys[0].cws.iter().all(|cw| !cw.s.lsb()), "CW has a nonzero lsb");
        // F = β − Γ must not reveal lsb(β).
        lsb_hits += ((keys[0].f ^ beta) & 1 == 0) as u32;
    }
    assert!((12..=52).contains(&lsb_hits), "lsb(β) predictable: {lsb_hits}/{trials}");
}
