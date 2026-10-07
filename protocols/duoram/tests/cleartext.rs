//! Duoram's adjusted DPF against the cleartext point function over Z_2^w.

use dpf_common::arith::mask;
use duoram::{deal, gen_reference, run_gen_2p, run_gen_3p, DuoramKey, Run};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;

const SIZES: &[u64] = &[2, 3, 5, 64, 1000, 1024, (1 << 12) + 3];
const BITS: &[usize] = &[1, 16, 64];

fn check(keys: &[DuoramKey; 2], n: u64, alpha: u64, beta: u64) {
    let m = mask(keys[0].bits);
    let ctx = format!("N={n} alpha={alpha} bits={}", keys[0].bits);
    assert_eq!(keys[0].public_part(), keys[1].public_part(), "{ctx}");
    let ev = [keys[0].eval_full(), keys[1].eval_full()];
    for x in 0..n {
        let want = if x == alpha { beta } else { 0 };
        let p = [keys[0].eval_point(x), keys[1].eval_point(x)];
        assert_eq!(p[0].wrapping_add(p[1]) & m, want, "eval_point at x={x}: {ctx}");
        assert_eq!((ev[0][x as usize], ev[1][x as usize]), (p[0], p[1]), "eval_full != eval_point at x={x}: {ctx}");
    }
}

/// The App. D lemma: the converted flags are additive shares of e_r.
#[test]
fn converted_flags_are_additive_unit_vector() {
    let mut rng = ChaCha20Rng::seed_from_u64(1);
    for &n in &[2u64, 8, 1024] {
        let keys = gen_reference(n, 64, 0, 0, rng.gen());
        // With β = 0 the output is F·t̃ − … ; check t̃ directly through the key fields.
        let leaves = [keys[0].leaves(), keys[1].leaves()];
        let (mut ones, mut total) = (0, 0u64);
        for i in 0..leaves[0].len() {
            let tt = |k: &DuoramKey, l: dpf_common::block::Block| {
                let s = |x: u64| if k.party == 1 { x.wrapping_neg() } else { x };
                let (_, v2) = duoram::tree::lanes(l);
                let t = s(l.lsb() as u64);
                t.wrapping_mul(k.c).wrapping_add(s(v2)).wrapping_sub(t.wrapping_mul(k.fbar))
            };
            let v = tt(&keys[0], leaves[0][i]).wrapping_add(tt(&keys[1], leaves[1][i]));
            assert!(v == 0 || v == 1, "t̃ at {i} is {v}");
            ones += v as usize;
            total = total.wrapping_add(v);
        }
        assert_eq!((ones, total), (1, 1), "N={n}");
    }
}

#[test]
fn dealer_keys_match_cleartext_function() {
    let mut rng = ChaCha20Rng::seed_from_u64(2);
    for &n in SIZES {
        for &bits in BITS {
            for alpha in [0, n - 1, rng.gen_range(0..n)] {
                let beta = rng.gen::<u64>() & mask(bits);
                check(&gen_reference(n, bits, alpha, beta, rng.gen()), n, alpha, beta);
            }
        }
    }
}

fn check_run(run: Run, n: u64, bits: usize, alpha: u64, beta: u64) {
    let [o0, o1] = run.outs;
    let keys = [o0.key, o1.key];
    check(&keys, n, alpha, beta);
    // The preprocessing builds the same tree as the dealer for the same roots
    // and target.
    let r = alpha.wrapping_sub(keys[0].shift) & mask(keys[0].depth());
    let dealt = deal([keys[0].root, keys[1].root], n, bits, alpha, beta, r, 0);
    assert_eq!(dealt[0].cws, keys[0].cws, "N={n} alpha={alpha}");
    assert_eq!(dealt[0].f & mask(bits), keys[0].f & mask(bits), "N={n} alpha={alpha}");
    // The online phase is one flight each way of two words.
    assert_eq!(o0.online_stats.bytes_sent, 16);
}

#[test]
fn two_party_gen_matches_cleartext_function() {
    let mut rng = ChaCha20Rng::seed_from_u64(3);
    let mut seed = 0;
    for &n in SIZES {
        for &bits in BITS {
            for alpha in [0, n - 1, rng.gen_range(0..n)] {
                let beta = rng.gen::<u64>() & mask(bits);
                seed += 1;
                check_run(run_gen_2p(n, bits, alpha, beta, seed), n, bits, alpha, beta);
            }
        }
    }
}

#[test]
fn three_party_gen_matches_cleartext_function() {
    let mut rng = ChaCha20Rng::seed_from_u64(4);
    let mut seed = 100;
    for &n in SIZES {
        for &bits in BITS {
            for alpha in [0, n - 1, rng.gen_range(0..n)] {
                let beta = rng.gen::<u64>() & mask(bits);
                seed += 1;
                let run = run_gen_3p(n, bits, alpha, beta, seed);
                assert!(run.helper.unwrap().bytes_sent > 0);
                check_run(run, n, bits, alpha, beta);
            }
        }
    }
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
