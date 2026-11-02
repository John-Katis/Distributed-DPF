//! The semi-honest Gen (payload in F_p, public β) against the cleartext point
//! function and the dealer, for switch levels ν from 0 to n.

use dpf_common::block::Block;
use dpf_common::net::run_two_party;
use ht_aes::field::{BabyBear, Field, Gold, M127};
use ht_aes::semi_honest::{deal, gen, ShKey};
use ht_aes::{sh_ands, sh_calls};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;

fn check<F: Field>(keys: &[ShKey<F>; 2], n: u64, alpha: u64, beta: F) {
    let full = [keys[0].eval_full(), keys[1].eval_full()];
    for x in 0..n {
        let y = keys[0].eval_point(x).add(keys[1].eval_point(x));
        assert_eq!(y, if x == alpha { beta } else { F::ZERO }, "x={x}");
        assert_eq!(full[0][x as usize].add(full[1][x as usize]), y);
    }
    for (k, f) in keys.iter().zip(&full) {
        for batch in [2, 4, 1 << 10] {
            let mut streamed = Vec::new();
            k.eval_full_stream(batch, |x0, ys| {
                assert_eq!(x0, streamed.len() as u64);
                streamed.extend_from_slice(ys);
            });
            assert_eq!(&streamed, f, "batch={batch}");
        }
    }
}

/// One Gen of a key for the public β with switch level ν; returns the keys,
/// the random α (α_0 ⊕ α_1) and the on-path states U_ν, …, U_n.
fn run<F: Field>(n: u64, nu: Option<usize>, beta: F, seed: u64) -> ([ShKey<F>; 2], u64, Vec<Block>) {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let seeds: [[u8; 32]; 2] = [rng.gen(), rng.gen()];
    let (o0, o1) = run_two_party(move |c| gen(c, n, nu, beta, seeds[0], None), move |c| gen(c, n, nu, beta, seeds[1], None));
    let (depth, nu) = (o0.key.depth(), o0.key.nu);
    assert_eq!(o0.ands, sh_ands(depth, nu));
    assert_eq!(o0.ands, sh_calls(depth, nu) * dpf_common::aes_tower::ANDS_PER_CALL);
    // The top phase and the switch (ν + 3 rounds) run concurrently with the
    // AES–MMO calls (40), Step B and M_ℓ (or the leaf's two openings).
    assert_eq!(o0.gen_stats.rounds.max(o1.gen_stats.rounds), (nu + 3).max(42), "n={depth} ν={nu}");
    // The root shares are ⟨Δ⟩, lsb(Δ_b) = b.
    assert!(!o0.key.root.lsb() && o1.key.root.lsb());
    let alpha = o0.alpha_share ^ o1.alpha_share;
    assert!(alpha < 1 << depth);
    let us: Vec<Block> = o0.onpath_share.iter().zip(&o1.onpath_share).map(|(&a, &b)| a ^ b).collect();
    assert_eq!(us.len(), depth - nu + 1);
    ([o0.key, o1.key], alpha, us)
}

fn gen_matches_point_function_and_dealer<F: Field>(seed: u64) {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let mut s = seed;
    for (n, nus) in [(8u64, vec![None, Some(0), Some(3)]), (16, vec![Some(1), Some(2)]), (13, vec![None]), (1 << 9, vec![Some(4), Some(9)])] {
        for nu in nus {
            s += 1;
            let beta = F::random(&mut rng);
            let (keys, alpha, us) = run::<F>(n, nu, beta, s);
            check(&keys, n, alpha, beta);
            assert_eq!(deal([keys[0].root, keys[1].root], keys[0].prf.key(), n, keys[0].nu, alpha, beta, &us), keys);
        }
    }
}

#[test]
fn gen_matches_point_function_and_dealer_babybear() {
    gen_matches_point_function_and_dealer::<BabyBear>(50);
}

#[test]
fn gen_matches_point_function_and_dealer_gold() {
    gen_matches_point_function_and_dealer::<Gold>(1);
}

#[test]
fn gen_matches_point_function_and_dealer_m127() {
    gen_matches_point_function_and_dealer::<M127>(100);
}

#[test]
fn dealer_keys_are_point_functions() {
    let mut rng = ChaCha20Rng::seed_from_u64(2);
    for n in [2u64, 5, 64, 1000] {
        let alpha = rng.gen_range(0..n);
        let beta = M127::random(&mut rng);
        let roots = [Block::random(&mut rng).with_lsb(false), Block::random(&mut rng).with_lsb(true)];
        let depth = dpf_common::block::depth_for(n);
        for nu in [0, depth / 2, depth] {
            let us: Vec<Block> = (nu..=depth).map(|_| Block::random(&mut rng)).collect();
            check(&deal(roots, rng.gen(), n, nu, alpha, beta, &us), n, alpha, beta);
        }
    }
}

#[test]
fn gen_at_domain_2_pow_63() {
    let mut rng = ChaCha20Rng::seed_from_u64(3);
    let n = 1u64 << 63;
    let beta = Gold::random(&mut rng);
    let (keys, alpha, _) = run::<Gold>(n, Some(8), beta, 7);
    assert_eq!(keys[0].depth(), 63);
    for x in [alpha, alpha ^ 1, alpha ^ (1 << 62), 0, n - 1, rng.gen_range(0..n)] {
        let y = keys[0].eval_point(x).add(keys[1].eval_point(x));
        assert_eq!(y, if x == alpha { beta } else { Gold::ZERO }, "x={x}");
    }
}
