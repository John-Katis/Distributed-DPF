//! The arithmetic payload of the GGM + LPN-PRG instance against the cleartext
//! point function (every x), for glue levels 0 ≤ ν ≤ n; the 2PC Gen
//! bit-exactly against the cleartext one.

use dpf_common::block::{depth_for, Block};
use dpf_common::ot::FerretConfig;
use ggm_lpn::{deal_arith, run_gen_arith, ArithKey, DealParams};
use ht_aes::field::{BabyBear, Field, Gold, M127};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;

fn nus(n: usize) -> Vec<usize> {
    let mut v = vec![0, 1, n / 2, n.saturating_sub(1), n];
    v.sort();
    v.dedup();
    v
}

fn check<F: Field>(keys: &[ArithKey<F>; 2], alpha: u64, beta: F) {
    let n_size = keys[0].n_size;
    let ev = [keys[0].eval_full(), keys[1].eval_full()];
    for x in 0..n_size {
        let want = if x == alpha { beta } else { F::ZERO };
        let p = [keys[0].eval_point(x), keys[1].eval_point(x)];
        assert!(p[0].add(p[1]) == want, "eval_point at x={x}, N={n_size}, nu={}, alpha={alpha}", keys[0].nu);
        assert!(ev[0][x as usize] == p[0] && ev[1][x as usize] == p[1], "eval_full != eval_point at x={x}");
    }
    for (k, e) in keys.iter().zip(&ev) {
        let mut got = Vec::new();
        k.eval_full_stream(4, |x0, ys| {
            assert_eq!(x0 as usize, got.len());
            got.extend_from_slice(ys);
        });
        assert!(got.len() == e.len() && got.iter().zip(e).all(|(a, b)| a == b), "eval_full_stream != eval_full");
    }
}

fn dealer<F: Field>() {
    let mut rng = ChaCha20Rng::seed_from_u64(1);
    for &n_size in &[2u64, 3, 8, 33, 128, 1000] {
        let n = depth_for(n_size);
        for nu in nus(n) {
            for _ in 0..4 {
                let alpha = rng.gen_range(0..n_size);
                let beta = F::random(&mut rng);
                let p = DealParams::random(&mut rng, n, nu);
                check(&deal_arith(&p, n_size, alpha, beta), alpha, beta);
            }
        }
    }
}

#[test]
fn dealer_keys_are_correct() {
    dealer::<BabyBear>();
    dealer::<Gold>();
    dealer::<M127>();
}

fn two_party<F: Field>() {
    let mut rng = ChaCha20Rng::seed_from_u64(2);
    for &n_size in &[8u64, 33, 256] {
        let n = depth_for(n_size);
        for nu in nus(n) {
            let beta = F::random(&mut rng);
            let (outs, _) = run_gen_arith::<F>(n_size, Some(nu), beta, rng.gen(), FerretConfig::TOY);
            let [a, b] = &outs;
            let alpha = a.alpha_share ^ b.alpha_share;
            if alpha < n_size {
                let keys = [a.key.clone(), b.key.clone()];
                check(&keys, alpha, beta);
                let xor = |x: &[Block], y: &[Block]| -> Vec<Block> { x.iter().zip(y).map(|(&p, &q)| p ^ q).collect() };
                let params = DealParams { roots: [a.key.root, b.key.root], nu, v: xor(&a.v_share, &b.v_share), u: xor(&a.u_share, &b.u_share) };
                let dealt = deal_arith(&params, n_size, alpha, beta);
                assert!(dealt[0].w_cw == a.key.w_cw && dealt[0].cws == a.key.cws && dealt[0].ms == a.key.ms, "2PC Gen != deal, N={n_size}, nu={nu}");
            }
            // Gen proper: the leaf runs beside the bottom phase for κ ≤ 127;
            // for κ > 127, product, PRG batch, two openings in sequence.
            let rounds = a.gen_stats.rounds.max(b.gen_stats.rounds);
            let leaf = if F::KAPPA <= 127 { 3 } else { 5 };
            let bottom = if nu == n { 0 } else { 4 };
            assert_eq!(rounds, (if nu >= 1 { nu + 2 } else { 0 }).max(leaf).max(bottom), "gen rounds: N={n_size}, nu={nu}, kappa={}", F::KAPPA);
        }
    }
}

#[test]
fn two_party_gen_matches_deal() {
    two_party::<BabyBear>();
    two_party::<Gold>();
    two_party::<M127>();
}
