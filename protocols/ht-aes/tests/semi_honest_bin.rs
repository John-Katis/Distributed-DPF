//! The semi-honest Gen with a binary payload against the cleartext point
//! function and the dealer.

use dpf_common::block::Block;
use dpf_common::net::run_two_party;
use ht_aes::malicious::low;
use ht_aes::semi_honest::bin::{deal, gen, gen_reference, BinKey};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;

fn check(keys: &[BinKey; 2], n: u64, alpha: u64, beta: Block) {
    let full = [keys[0].eval_full(), keys[1].eval_full()];
    for x in 0..n {
        let y = keys[0].eval_point(x) ^ keys[1].eval_point(x);
        assert_eq!(y, if x == alpha { beta } else { Block::ZERO }, "x={x}");
        assert_eq!(full[0][x as usize] ^ full[1][x as usize], y);
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

#[test]
fn gen_matches_point_function_and_dealer() {
    let mut rng = ChaCha20Rng::seed_from_u64(1);
    for (i, (n, bits)) in [(8u64, 64usize), (16, 7), (13, 128)].into_iter().enumerate() {
        let alpha = rng.gen_range(0..n);
        let beta = low(Block::random(&mut rng), bits);
        let a0: u64 = rng.gen::<u64>() % n.next_power_of_two();
        let b0 = low(Block::random(&mut rng), bits);
        let seeds: [[u8; 32]; 2] = [rng.gen(), rng.gen()];
        let (o0, o1) = run_two_party(
            move |c| gen(c, n, bits, a0, b0, seeds[0], None),
            move |c| gen(c, n, bits, alpha ^ a0, beta ^ b0, seeds[1], None),
        );
        let depth = o0.key.depth();
        assert_eq!(o0.gen_stats.rounds.max(o1.gen_stats.rounds), 41 * depth + 42, "case {i}");
        let keys = [o0.key, o1.key];
        check(&keys, n, alpha, beta);
        assert_eq!(deal([keys[0].root, keys[1].root], n, bits, alpha, beta), keys);
    }
}

#[test]
fn dealer_keys_are_point_functions() {
    let mut rng = ChaCha20Rng::seed_from_u64(2);
    for (n, bits) in [(2u64, 1usize), (5, 64), (64, 128), (1000, 33)] {
        let alpha = rng.gen_range(0..n);
        let beta = low(Block::random(&mut rng), bits);
        check(&gen_reference(n, bits, alpha, beta, rng.gen()), n, alpha, beta);
    }
}
