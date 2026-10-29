//! The malicious Gen on the semi-honest preprocessing: correctness against
//! the dealer, Π_Verify, and that deviations in Gen are caught by Π_Verify.

use dpf_common::block::Block;
use dpf_common::coin::Abort;
use dpf_common::net::run_two_party;
use ht_aes::malicious::{deal, low, mal_calls, run_mal, verify, Fault, MalKey, MalRun, MalSession};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;

fn run(n: u64, bits: usize, alpha: u64, beta: Block, seed: u64, faults: [Option<Fault>; 2]) -> [MalRun; 2] {
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
        let depth = r0.key.depth();
        assert_eq!(r0.gen_stats.rounds.max(r1.gen_stats.rounds), 41 * depth + 42);
        assert_eq!(r0.ands, mal_calls(depth) * dpf_common::aes_tower::ANDS_PER_CALL);
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

/// A wrong CW share, payload word or MAC word in Gen: the honest run of Gen
/// completes, and Π_Verify over the whole domain aborts.
#[test]
fn faults_in_gen_are_caught_by_verify() {
    let mut rng = ChaCha20Rng::seed_from_u64(2);
    let (n, bits) = (8u64, 16usize);
    for level in [0usize, 2, 3, 4] {
        for cheater in [0, 1] {
            let err = Block(1 << rng.gen_range(0..16));
            let mut faults = [None, None];
            faults[cheater] = Some(Fault { level, err });
            let [r0, r1] = run(n, bits, 5, Block(77), 10 + level as u64, faults);
            let [a, b] = eval_and_verify([r0.key, r1.key], [r0.delta_share, r1.delta_share], (0..n).collect(), false);
            assert_eq!(a.err(), Some(Abort("output MAC check failed")), "level {level} cheater {cheater}");
            assert_eq!(b.err(), Some(Abort("output MAC check failed")));
        }
    }
}

#[test]
fn full_eval_matches_point_eval() {
    let mut rng = ChaCha20Rng::seed_from_u64(3);
    for (n, bits) in [(2u64, 64usize), (13, 128), (64, 5), (1000, 64)] {
        let beta = low(Block::random(&mut rng), bits);
        let (keys, _) = ht_aes::malicious::gen_reference(n, bits, rng.gen_range(0..n), beta, rng.gen());
        for k in &keys {
            let points: Vec<(Block, Block)> = (0..n).map(|x| k.eval_point(x)).collect();
            assert_eq!(k.eval_full(), points);
            for batch in [2, 4, 1 << 10] {
                let mut streamed = Vec::new();
                k.eval_full_stream(batch, |x0, outs| {
                    assert_eq!(x0, streamed.len() as u64);
                    streamed.extend_from_slice(outs);
                });
                assert_eq!(streamed, points, "n={n} batch={batch}");
            }
        }
    }
}

/// Two Gens on one session: fresh roots and fresh COTs per Gen. With
/// the session's COT key as the root, the two keys' words at the first level
/// where the α differ would XOR to Δ and reveal both α.
#[test]
fn two_gens_in_one_session() {
    let mut rng = ChaCha20Rng::seed_from_u64(7);
    let (n, bits) = (1u64 << 10, 64usize);
    let depth = dpf_common::block::depth_for(n);
    let alphas = [0x0f3u64, 0x2f3]; // differ at level 2
    let betas = [low(Block::random(&mut rng), bits), low(Block::random(&mut rng), bits)];
    let a0: [u64; 2] = [rng.gen_range(0..n), rng.gen_range(0..n)];
    let b0 = [low(Block::random(&mut rng), bits), low(Block::random(&mut rng), bits)];
    let seeds: [[u8; 32]; 2] = [rng.gen(), rng.gen()];
    let party = |b: usize| {
        move |c: &mut dpf_common::net::Channel| {
            let mut s = MalSession::setup(c, seeds[b], None);
            let keys: Vec<MalKey> = (0..2)
                .map(|g| {
                    let pre = s.precompute(c, depth, bits);
                    let (a, be) = if b == 0 { (a0[g], b0[g]) } else { (alphas[g] ^ a0[g], betas[g] ^ b0[g]) };
                    s.gen(c, n, bits, a, be, pre, None).0
                })
                .collect();
            (keys, s.delta_mac)
        }
    };
    let ((k0, d0), (k1, d1)) = run_two_party(party(0), party(1));
    for g in 0..2 {
        assert_eq!(deal([k0[g].root, k1[g].root], n, bits, alphas[g], betas[g], d0 ^ d1), [k0[g].clone(), k1[g].clone()]);
        let [y0, _] = eval_and_verify([k0[g].clone(), k1[g].clone()], [d0, d1], (0..n).collect(), false);
        let y0 = y0.unwrap();
        for x in 0..n {
            assert_eq!(y0[x as usize], if x == alphas[g] { betas[g] } else { Block::ZERO });
        }
    }
    assert_ne!(k0[0].root, k0[1].root);
    assert_ne!(k1[0].root, k1[1].root);
    let delta = k0[0].root ^ k1[0].root;
    assert_eq!(delta, k0[1].root ^ k1[1].root, "Δ is the session's");
    assert_ne!(k0[0].cws[1] ^ k0[1].cws[1], delta);
}
