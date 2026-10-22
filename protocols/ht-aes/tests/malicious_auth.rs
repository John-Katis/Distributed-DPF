//! The authenticated malicious Gen (A1–A5): correctness against the dealer, Π_Verify, aborts.

use dpf_common::block::Block;
use dpf_common::coin::Abort;
use dpf_common::net::run_two_party;
use ht_aes::malicious_auth::{deal, low, run_mal, verify, Fault, MalKey, MalRun};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;

fn run(n: u64, bits: usize, alpha: u64, beta: Block, seed: u64, faults: [Option<Fault>; 2]) -> [Result<MalRun, Abort>; 2] {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let a0: u64 = rng.gen::<u64>() % n.next_power_of_two();
    let b0 = low(Block::random(&mut rng), bits);
    let seeds: [[u8; 32]; 2] = [rng.gen(), rng.gen()];
    let (r0, r1) = run_two_party(
        move |c| run_mal(c, n, bits, a0, b0, seeds[0], None, faults[0]),
        move |c| run_mal(c, n, bits, alpha ^ a0, beta ^ b0, seeds[1], None, faults[1]),
    );
    [r0, r1]
}

fn eval_and_verify(keys: [MalKey; 2], d: [Block; 2], xs: Vec<u64>, tamper: bool) -> [Result<Vec<Block>, Abort>; 2] {
    let party = |p: usize, k: MalKey| {
        let xs = xs.clone();
        move |c: &mut dpf_common::net::Channel| {
            let mut outs: Vec<(Block, Block)> = xs.iter().map(|&x| k.eval_point(x)).collect();
            if tamper && p == 1 {
                outs[0].0 ^= Block(1);
            }
            verify(c, &outs, d[p], &mut ChaCha20Rng::seed_from_u64(p as u64))
        }
    };
    let [k0, k1] = keys;
    let (a, b) = run_two_party(party(0, k0), party(1, k1));
    [a, b]
}

#[test]
fn mal_gen_matches_dealer_and_verifies() {
    let mut rng = ChaCha20Rng::seed_from_u64(1);
    for (i, (n, bits)) in [(8u64, 64usize), (13, 128), (16, 5)].into_iter().enumerate() {
        let alpha = rng.gen_range(0..n);
        let beta = low(Block::random(&mut rng), bits);
        let [r0, r1] = run(n, bits, alpha, beta, i as u64, [None, None]);
        let (r0, r1) = (r0.unwrap(), r1.unwrap());
        let depth = r0.key.depth();
        assert_eq!(r0.gen_stats.rounds.max(r1.gen_stats.rounds), 41 * depth + 45);
        assert_eq!(r0.products, ht_aes::malicious_auth::auth_products(depth, bits));
        let delta = r0.delta_share ^ r1.delta_share;
        let dealt = deal([r0.key.root, r1.key.root], n, bits, alpha, beta, delta);
        assert_eq!(dealt, [r0.key.clone(), r1.key.clone()]);
        let xs: Vec<u64> = (0..n).collect();
        let [y0, y1] = eval_and_verify([r0.key.clone(), r1.key.clone()], [r0.delta_share, r1.delta_share], xs.clone(), false);
        let (y0, y1) = (y0.unwrap(), y1.unwrap());
        assert_eq!(y0, y1);
        for x in 0..n {
            assert_eq!(y0[x as usize], if x == alpha { beta } else { Block::ZERO });
        }
        // A falsified output share is caught.
        let [a, b] = eval_and_verify([r0.key, r1.key], [r0.delta_share, r1.delta_share], xs, true);
        assert!(a.is_err() && b.is_err());
    }
}

#[test]
fn faults_in_gen_abort() {
    let mut rng = ChaCha20Rng::seed_from_u64(2);
    let (n, bits) = (8u64, 16usize);
    for level in [0usize, 2, 3, 4] {
        for cheater in [0, 1] {
            let err = Block(1 << rng.gen_range(0..16));
            let mut faults = [None, None];
            faults[cheater] = Some(Fault { level, err });
            let [r0, r1] = run(n, bits, 5, Block(77), 10 + level as u64, faults);
            assert_eq!(r0.err(), Some(Abort("MAC check failed")), "level {level} cheater {cheater}");
            assert_eq!(r1.err(), Some(Abort("MAC check failed")));
        }
    }
}
