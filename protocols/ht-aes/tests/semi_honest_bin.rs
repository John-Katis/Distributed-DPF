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
    let cases = [(2u64, None, 8usize), (8, None, 64), (8, Some(3), 64), (16, Some(1), 7), (13, None, 128), (1 << 9, Some(6), 33), (1 << 9, Some(9), 1)];
    for (i, (n, nu, bits)) in cases.into_iter().enumerate() {
        let beta = low(Block::random(&mut rng), bits);
        let b0 = low(Block::random(&mut rng), bits);
        let seeds: [[u8; 32]; 2] = [rng.gen(), rng.gen()];
        let (o0, o1) = run_two_party(move |c| gen(c, n, nu, bits, b0, seeds[0], None), move |c| gen(c, n, nu, bits, beta ^ b0, seeds[1], None));
        let (depth, nu) = (o0.key.depth(), o0.key.nu);
        // 𝓕_COT and the top phase on one lane (ν + 3), the AES–MMO calls from
        // round 1 (no ⟨Y⟩ with a binary payload), then Step B and M_ℓ.
        let rounds = (nu + 3).max(if nu < depth { 42 } else { 41 });
        assert_eq!(o0.gen_stats.rounds.max(o1.gen_stats.rounds), rounds, "case {i}");
        let alpha = o0.alpha_share ^ o1.alpha_share;
        let us: Vec<Block> = o0.onpath_share.iter().zip(&o1.onpath_share).map(|(&a, &b)| a ^ b).collect();
        let keys = [o0.key, o1.key];
        check(&keys, n, alpha, beta);
        assert_eq!(deal([keys[0].root, keys[1].root], keys[0].prf.key(), n, nu, bits, alpha, beta, &us), keys);
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
