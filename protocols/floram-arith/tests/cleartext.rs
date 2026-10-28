//! Arithmetic DPF against the cleartext point function over Z_2^ℓ.

use dpf_common::arith::Ring;
use floram_arith::{deal, gen_reference, run_gen, ArithKey};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;

const SIZES: &[u64] = &[2, 3, 5, 7, 1000, 1024, (1 << 12) + 3];
const BITS: &[usize] = &[1, 16, 32, 64];
/// Widths on 128-bit words; 128 takes Convert from the PRG.
const WIDE: &[usize] = &[65, 127, 128];

fn check<R: Ring>(keys: &[ArithKey<R>; 2], fulls: Option<&[Vec<R>; 2]>, n: u64, alpha: u64, beta: R) {
    let m = keys[0].ring_mask();
    let ctx = format!("N={n} alpha={alpha} bits={}", keys[0].bits);
    assert_eq!(keys[0].public_part(), keys[1].public_part(), "{ctx}");
    let ev = [keys[0].eval_full(), keys[1].eval_full()];
    for x in 0..n {
        let want = if x == alpha { beta } else { R::ZERO };
        let p = [keys[0].eval_point(x), keys[1].eval_point(x)];
        assert_eq!(p[0].add(p[1]).and(m), want, "eval_point at x={x}: {ctx}");
        assert_eq!(ev[0][x as usize], p[0], "eval_full != eval_point at x={x}: {ctx}");
        assert_eq!(ev[1][x as usize], p[1], "eval_full != eval_point at x={x}: {ctx}");
    }
    if let Some(f) = fulls {
        assert_eq!(&ev[0], &f[0], "gen output differs: {ctx}");
        assert_eq!(&ev[1], &f[1], "gen output differs: {ctx}");
    }
}

fn two_party_gen<R: Ring>(widths: &[usize], rng_seed: u64) {
    let mut rng = ChaCha20Rng::seed_from_u64(rng_seed);
    let mut seed = rng_seed << 32;
    for &n in SIZES {
        for &bits in widths {
            for alpha in [0, n - 1, rng.gen_range(0..n)] {
                let beta = R::random(&mut rng).and(R::mask(bits));
                seed += 1;
                let run = run_gen(n, bits, alpha, beta, seed);
                let [o0, o1] = run.outs;
                let keys = [o0.key, o1.key];
                check(&keys, Some(&[o0.full.unwrap(), o1.full.unwrap()]), n, alpha, beta);
                let d = deal([keys[0].root, keys[1].root], n, bits, alpha, beta);
                assert_eq!(d[0].public_part(), keys[0].public_part(), "protocol differs from dealer");
                // Z_2^ℓ travels in words of the ring: W_CW is one word.
                assert_eq!(keys[0].size_bytes(), 16 + 17 * keys[0].depth() + bits.div_ceil(8));
            }
        }
    }
}

#[test]
fn two_party_gen_matches_cleartext_function() {
    two_party_gen::<u64>(BITS, 31);
}

#[test]
fn two_party_gen_matches_cleartext_function_128() {
    two_party_gen::<u128>(WIDE, 33);
}

/// The ℓ-dependent traffic is the F^{A,ℓ}_MUX and the W_CW opening. For
/// ℓ ≤ 64 the MUX is SCI's multiplexer on 64-bit words, above it ours on
/// 128-bit words, so traffic is constant within each range; rounds never
/// depend on ℓ.
#[test]
fn traffic_follows_word_width() {
    let s = |bits: usize| if bits <= 64 { run_gen(1000, bits, 3, 5u64, 1).outs[0].gen_stats } else { run_gen(1000, bits, 3, 5u128, 1).outs[0].gen_stats };
    let (s32, s64, s65, s128) = (s(32), s(64), s(65), s(128));
    assert_eq!(s32.bytes_sent, s64.bytes_sent);
    assert_eq!(s65.bytes_sent, s128.bytes_sent);
    assert!([s32.rounds, s64.rounds, s65.rounds].iter().all(|&r| r == s128.rounds));
}

#[test]
fn every_alpha_with_wrapping_shares() {
    // N = 13 → n = 4, so additive α shares wrap modulo 16.
    let n = 13;
    let mut wrapped = 0;
    for alpha in 0..n {
        for s in 0..4 {
            let run = run_gen(n, 32, alpha, 0xdead_0000u64 + alpha, 100 * alpha + s);
            wrapped += (run.alpha_shares[0] + run.alpha_shares[1] >= 16) as u32;
            let [o0, o1] = run.outs;
            check(&[o0.key, o1.key], Some(&[o0.full.unwrap(), o1.full.unwrap()]), n, alpha, 0xdead_0000 + alpha);
        }
    }
    assert!(wrapped > 0, "no case exercised a carry out of the top bit");
}

fn dealer<R: Ring>(widths: &[usize]) {
    let mut rng = ChaCha20Rng::seed_from_u64(32);
    for &n in SIZES {
        for &bits in widths {
            let alpha = rng.gen_range(0..n);
            let beta = R::random(&mut rng).and(R::mask(bits));
            check(&gen_reference(n, bits, alpha, beta, rng.gen()), None, n, alpha, beta);
        }
    }
}

#[test]
fn dealer_matches_cleartext_function() {
    dealer::<u64>(BITS);
    dealer::<u128>(WIDE);
}

#[test]
fn correction_words_do_not_leak_alpha() {
    let mut rng = ChaCha20Rng::seed_from_u64(23);
    for _ in 0..32 {
        // σ has lsb 0, so it no longer equals the off-path τ.
        let n = 1 << 8;
        let keys = gen_reference(n, 64, rng.gen_range(0..n), rng.gen::<u64>(), rng.gen());
        assert!(keys[0].cws.iter().all(|cw| !cw.sigma.lsb()), "σ has a nonzero lsb");
        // N = 5, α = 4: the off-path siblings at levels 2 and 3 cover only
        // padding leaves, but σ_2 and σ_3 must still be pseudorandom.
        let beta = rng.gen::<u64>();
        let keys = gen_reference(5, 64, 4, beta, rng.gen());
        assert_ne!(keys[0].cws[1].sigma.0, 0, "σ_2 is publicly zero");
        assert_ne!(keys[0].cws[2].sigma.0, 0, "σ_3 is publicly zero");
        check(&keys, None, 5, 4, beta);
    }
}
