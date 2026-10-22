//! The semi-honest Gen against the cleartext point function and the dealer.

use dpf_common::arith::Ring;
use dpf_common::block::Block;
use dpf_common::foleage::Params;
use dpf_common::net::run_two_party;
use ht_aes::semi_honest::{deal, gen, ShKey};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;

fn check<T: Ring>(keys: &[ShKey<T>; 2], n: u64, alpha: u64, beta: T) {
    let m = T::mask(keys[0].bits);
    let full = [keys[0].eval_full(), keys[1].eval_full()];
    for x in 0..n {
        let y = keys[0].eval_point(x).add(keys[1].eval_point(x)).and(m);
        assert_eq!(y, if x == alpha { beta } else { T::ZERO }, "x={x}");
        assert_eq!(full[0][x as usize].add(full[1][x as usize]).and(m), y);
    }
}

fn run<T: Ring>(n: u64, bits: usize, alpha: u64, beta: T, seed: u64) -> [ShKey<T>; 2] {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let a0: u64 = rng.gen::<u64>() % n.next_power_of_two();
    let b0 = T::random(&mut rng).and(T::mask(bits));
    let b1 = beta.sub(b0).and(T::mask(bits));
    let seeds: [[u8; 32]; 2] = [rng.gen(), rng.gen()];
    let p = Params::new(10);
    let (o0, o1) = run_two_party(
        move |c| gen(c, n, bits, a0, b0, seeds[0], None, p),
        move |c| gen(c, n, bits, alpha ^ a0, b1, seeds[1], None, p),
    );
    let depth = o0.key.depth();
    assert_eq!(o0.products, ht_aes::sh_products(depth));
    assert_eq!(o0.gen_stats.rounds.max(o1.gen_stats.rounds), 41 * depth + 46);
    [o0.key, o1.key]
}

#[test]
fn gen_matches_point_function_and_dealer() {
    let mut rng = ChaCha20Rng::seed_from_u64(1);
    let mut seed = 0;
    for (n, bits) in [(8u64, 64usize), (16, 7), (13, 64)] {
        for alpha in [0, n - 1, rng.gen_range(0..n)] {
            seed += 1;
            let beta = rng.gen::<u64>() & <u64 as Ring>::mask(bits);
            let keys = run::<u64>(n, bits, alpha, beta, seed);
            check(&keys, n, alpha, beta);
            let dealt = deal([keys[0].root, keys[1].root], n, bits, alpha, beta);
            assert_eq!(dealt, keys);
        }
    }
    let beta: u128 = rng.gen();
    let keys = run::<u128>(16, 128, 9, beta, 99);
    check(&keys, 16, 9, beta);
}

#[test]
fn dealer_keys_are_point_functions() {
    let mut rng = ChaCha20Rng::seed_from_u64(2);
    for n in [2u64, 5, 64, 1000] {
        let alpha = rng.gen_range(0..n);
        let beta: u128 = rng.gen::<u128>() >> 1;
        let roots = [Block::random(&mut rng).with_lsb(false), Block::random(&mut rng).with_lsb(true)];
        check(&deal(roots, n, 127, alpha, beta), n, alpha, beta);
    }
}
