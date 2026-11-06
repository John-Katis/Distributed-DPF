//! The GGM + LPN-PRG instance of our template against the cleartext point
//! function (every x), for glue levels 0 ≤ ν ≤ n and ℓ up to 256; the 2PC Gen
//! bit-exactly against the cleartext one.

use dpf_common::block::{depth_for, Block};
use dpf_common::ot::FerretConfig;
use ggm_lpn::{deal, run_gen, BinKey, DealParams, Word};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;

const BITS: &[usize] = &[1, 7, 64, 127, 128, 256];

fn nus(n: usize) -> Vec<usize> {
    let mut v = vec![0, 1, n / 2, n.saturating_sub(1), n];
    v.sort();
    v.dedup();
    v
}

fn check(keys: &[BinKey; 2], alpha: u64, beta: Word) {
    let n_size = keys[0].n_size;
    let ctx = format!("N={n_size} nu={} bits={} alpha={alpha}", keys[0].nu, keys[0].bits);
    assert_eq!(keys[0].public_part(), keys[1].public_part(), "{ctx}");
    let ev = [keys[0].eval_full(), keys[1].eval_full()];
    for x in 0..n_size {
        let want = if x == alpha { beta } else { Word::ZERO };
        let p = [keys[0].eval_point(x), keys[1].eval_point(x)];
        assert_eq!(p[0] ^ p[1], want, "eval_point at x={x}: {ctx}");
        assert_eq!((ev[0][x as usize], ev[1][x as usize]), (p[0], p[1]), "eval_full != eval_point at x={x}: {ctx}");
    }
    for batch in [4, 64] {
        for (k, e) in keys.iter().zip(&ev) {
            let mut got = Vec::new();
            k.eval_full_stream(batch, |x0, ys| {
                assert_eq!(x0 as usize, got.len());
                got.extend_from_slice(ys);
            });
            assert_eq!(&got, e, "eval_full_stream != eval_full: {ctx} batch={batch}");
        }
    }
}

#[test]
fn dealer_keys_are_correct() {
    let mut rng = ChaCha20Rng::seed_from_u64(1);
    for &n_size in &[2u64, 3, 8, 33, 128, 1000] {
        let n = depth_for(n_size);
        for nu in nus(n) {
            for &bits in BITS {
                for _ in 0..3 {
                    let alpha = rng.gen_range(0..n_size);
                    let beta = Word::random(&mut rng, bits);
                    let p = DealParams::random(&mut rng, n, nu);
                    check(&deal(&p, n_size, bits, alpha, beta), alpha, beta);
                }
            }
        }
    }
}

#[test]
fn every_alpha_small_domain() {
    let mut rng = ChaCha20Rng::seed_from_u64(2);
    for nu in 0..=4 {
        for alpha in 0..16 {
            let beta = Word::random(&mut rng, 64);
            let p = DealParams::random(&mut rng, 4, nu);
            check(&deal(&p, 16, 64, alpha, beta), alpha, beta);
        }
    }
}

/// The 2PC Gen equals the dealer's on the same randomness, and is correct.
#[test]
fn two_party_gen_matches_deal() {
    let mut seed = 0;
    for &n_size in &[2u64, 5, 64, 300] {
        let n = depth_for(n_size);
        for nu in nus(n) {
            for &bits in &[1usize, 64, 127, 128, 256] {
                seed += 1;
                let beta = Word::random(&mut ChaCha20Rng::seed_from_u64(1000 + seed), bits);
                let (outs, _) = run_gen(n_size, Some(nu), bits, beta, seed, FerretConfig::TOY);
                let alpha = outs[0].alpha_share ^ outs[1].alpha_share;
                let ctx = format!("N={n_size} nu={nu} bits={bits}");
                assert_eq!(alpha >> n, 0, "{ctx}");
                let xor = |a: &[Block], b: &[Block]| a.iter().zip(b).map(|(&x, &y)| x ^ y).collect::<Vec<_>>();
                let p = DealParams {
                    roots: [outs[0].key.root, outs[1].key.root],
                    nu,
                    v: xor(&outs[0].v_share, &outs[1].v_share),
                    u: xor(&outs[0].u_share, &outs[1].u_share),
                };
                let keys = [outs[0].key.clone(), outs[1].key.clone()];
                if alpha < n_size {
                    let want = deal(&p, n_size, bits, alpha, beta);
                    assert_eq!(keys[0].public_part(), want[0].public_part(), "{ctx}");
                    check(&keys, alpha, beta);
                }
                // Rounds of Gen proper: max(ν + 3, 4) (4 for ν = 0).
                let rounds = outs[0].gen_stats.rounds.max(outs[1].gen_stats.rounds);
                let want = if nu == 0 { 4 } else { (nu + 3).max(4) };
                assert_eq!(rounds, want, "gen rounds: {ctx}");
            }
        }
    }
}
