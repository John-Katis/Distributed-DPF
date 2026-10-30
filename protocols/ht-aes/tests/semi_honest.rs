//! The semi-honest Gen (payload in F_p) against the cleartext point function
//! and the dealer.

use dpf_common::block::Block;
use dpf_common::net::run_two_party;
use ht_aes::field::{Field, Gold, M127};
use ht_aes::semi_honest::{deal, gen, ShKey};
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

fn run<F: Field>(n: u64, alpha: u64, beta: F, seed: u64) -> [ShKey<F>; 2] {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let a0: u64 = rng.gen::<u64>() % n.next_power_of_two();
    let b0 = F::random(&mut rng);
    let seeds: [[u8; 32]; 2] = [rng.gen(), rng.gen()];
    let (o0, o1) = run_two_party(move |c| gen(c, n, a0, b0, seeds[0], None), move |c| gen(c, n, alpha ^ a0, beta.sub(b0), seeds[1], None));
    let depth = o0.key.depth();
    assert_eq!(o0.ands, ht_aes::sh_ands(depth));
    assert_eq!(o0.gen_stats.rounds.max(o1.gen_stats.rounds), 41 * depth + 44);
    [o0.key, o1.key]
}

fn gen_matches_point_function_and_dealer<F: Field>(seed: u64) {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let mut s = seed;
    for n in [8u64, 16, 13] {
        for alpha in [0, n - 1, rng.gen_range(0..n)] {
            s += 1;
            let beta = F::random(&mut rng);
            let keys = run::<F>(n, alpha, beta, s);
            check(&keys, n, alpha, beta);
            assert_eq!(deal([keys[0].root, keys[1].root], [keys[0].prf.key(), keys[0].pay.key()], n, alpha, beta), keys);
        }
    }
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
        check(&deal(roots, [rng.gen(), rng.gen()], n, alpha, beta), n, alpha, beta);
    }
}

#[test]
fn gen_at_domain_2_pow_63() {
    let mut rng = ChaCha20Rng::seed_from_u64(3);
    let n = 1u64 << 63;
    let alpha = rng.gen_range(0..n);
    let beta = Gold::random(&mut rng);
    let keys = run::<Gold>(n, alpha, beta, 7);
    assert_eq!(keys[0].depth(), 63);
    for x in [alpha, alpha ^ 1, alpha ^ (1 << 62), 0, n - 1, rng.gen_range(0..n)] {
        let y = keys[0].eval_point(x).add(keys[1].eval_point(x));
        assert_eq!(y, if x == alpha { beta } else { Gold::ZERO }, "x={x}");
    }
}
