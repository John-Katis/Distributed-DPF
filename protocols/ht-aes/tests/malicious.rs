//! The malicious Gen on the semi-honest preprocessing: correctness against
//! the dealer, Π_Verify, and that deviations in Gen are caught by Π_Verify.

use dpf_common::block::Block;
use dpf_common::coin::Abort;
use dpf_common::net::run_two_party;
use ht_aes::malicious::{deal, deal_mask, low, mal_ands, open_checked, run_mal, verify, Fault, MalKey, MalRun, MalSession};
use ht_aes::malicious_arith::VerifyMask;
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

/// Where a party falsifies its output share: in Π_Verify, or only when the
/// outputs are opened after it.
#[derive(Clone, Copy, PartialEq)]
enum Tamper {
    No,
    Verify,
    Open,
}

/// Evaluates both keys at xs and runs the output pipeline (Π_Verify, then the
/// checked opening); returns each party's result.
fn eval_and_verify(keys: [MalKey; 2], d: [Block; 2], masks: [VerifyMask<Block>; 2], xs: Vec<u64>, tamper: Tamper) -> [Result<Vec<Block>, Abort>; 2] {
    let party = |p: usize| {
        let outs: Vec<(Block, Block)> = xs.iter().map(|&x| keys[p].eval_point(x)).collect();
        move |c: &mut dpf_common::net::Channel| {
            let mut rng = ChaCha20Rng::seed_from_u64(p as u64);
            let mut bad = outs.clone();
            bad[0].0 ^= Block(1);
            let pick = |t: Tamper| if p == 1 && tamper == t { &bad } else { &outs };
            verify(c, pick(Tamper::Verify), d[p], masks[p], &mut rng)?;
            open_checked(c, pick(Tamper::Open), d[p], &mut rng)
        }
    };
    let (a, b) = run_two_party(party(0), party(1));
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
        assert_eq!(r0.ands, mal_ands(depth));
        let delta = r0.delta_share ^ r1.delta_share;
        let dealt = deal([r0.key.root, r1.key.root], [r0.key.prf.key(), r0.key.pay.key(), r0.key.mac.key()], n, bits, alpha, beta, delta);
        assert_eq!(dealt, [r0.key.clone(), r1.key.clone()]);
        let xs: Vec<u64> = (0..n).collect();
        let (d, m) = ([r0.delta_share, r1.delta_share], [r0.mask, r1.mask]);
        let [a, b] = eval_and_verify([r0.key.clone(), r1.key.clone()], d, m, xs.clone(), Tamper::No);
        let ys = a.unwrap();
        assert_eq!(b.unwrap(), ys, "both parties open the same outputs");
        for x in 0..n {
            assert_eq!(ys[x as usize], if x == alpha { beta } else { Block::ZERO });
        }
        // A falsified output share is caught.
        let [a, b] = eval_and_verify([r0.key.clone(), r1.key.clone()], d, m, xs.clone(), Tamper::Verify);
        assert!(a.is_err() && b.is_err());
        // A share falsified only at the opening is caught too.
        let [a, b] = eval_and_verify([r0.key, r1.key], d, m, xs, Tamper::Open);
        assert_eq!(a.err(), Some(Abort("opened output MAC check failed")));
        assert_eq!(b.err(), Some(Abort("opened output MAC check failed")));
    }
}

/// A wrong CW share, payload word, MAC word or share of K in Gen: the run of Gen
/// completes, and Π_Verify over the whole domain aborts.
#[test]
fn faults_in_gen_are_caught_by_verify() {
    let mut rng = ChaCha20Rng::seed_from_u64(2);
    let (n, bits) = (8u64, 16usize);
    for level in [0usize, 2, 3, 4, 5] {
        for cheater in [0, 1] {
            let err = Block(1 << rng.gen_range(0..16));
            let mut faults = [None, None];
            faults[cheater] = Some(Fault { level, err });
            let [r0, r1] = run(n, bits, 5, Block(77), 10 + level as u64, faults);
            let [a, b] = eval_and_verify([r0.key, r1.key], [r0.delta_share, r1.delta_share], [r0.mask, r1.mask], (0..n).collect(), Tamper::No);
            assert_eq!(a.err(), Some(Abort("output MAC check failed")), "level {level} cheater {cheater}");
            assert_eq!(b.err(), Some(Abort("output MAC check failed")));
        }
    }
}

/// Dealer keys with a dealer's Π_Verify masks verify; a mask that does not
/// match δ is rejected.
#[test]
fn dealer_keys_verify() {
    let mut rng = ChaCha20Rng::seed_from_u64(4);
    let (n, bits) = (32u64, 64usize);
    let (keys, d) = ht_aes::malicious::gen_reference(n, bits, 7, low(Block::random(&mut rng), bits), rng.gen());
    let m = deal_mask(d[0] ^ d[1], &mut rng);
    let [a, b] = eval_and_verify(keys.clone(), d, m, (0..n).collect(), Tamper::No);
    assert!(a.is_ok() && b.is_ok());
    let bad = deal_mask(d[0], &mut rng);
    let [a, _] = eval_and_verify(keys, d, bad, (0..n).collect(), Tamper::No);
    assert!(a.is_err());
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
            let keys: Vec<(MalKey, VerifyMask<Block>)> = (0..2)
                .map(|g| {
                    let pre = s.precompute(c, depth, bits);
                    let (a, be) = if b == 0 { (a0[g], b0[g]) } else { (alphas[g] ^ a0[g], betas[g] ^ b0[g]) };
                    let (k, _, m) = s.gen(c, n, bits, a, be, pre, None);
                    (k, m)
                })
                .collect();
            (keys, s.delta_mac)
        }
    };
    let ((k0, d0), (k1, d1)) = run_two_party(party(0), party(1));
    let (m0, m1): (Vec<_>, Vec<_>) = (k0.iter().map(|k| k.1).collect(), k1.iter().map(|k| k.1).collect());
    let (k0, k1): (Vec<MalKey>, Vec<MalKey>) = (k0.into_iter().map(|k| k.0).collect(), k1.into_iter().map(|k| k.0).collect());
    for g in 0..2 {
        assert_eq!(
            deal([k0[g].root, k1[g].root], [k0[g].prf.key(), k0[g].pay.key(), k0[g].mac.key()], n, bits, alphas[g], betas[g], d0 ^ d1),
            [k0[g].clone(), k1[g].clone()]
        );
        let [a, b] = eval_and_verify([k0[g].clone(), k1[g].clone()], [d0, d1], [m0[g], m1[g]], (0..n).collect(), Tamper::No);
        let ys = a.unwrap();
        assert_eq!(b.unwrap(), ys, "both parties open the same outputs");
        for x in 0..n {
            assert_eq!(ys[x as usize], if x == alphas[g] { betas[g] } else { Block::ZERO });
        }
    }
    assert_ne!(k0[0].root, k0[1].root);
    assert_ne!(k1[0].root, k1[1].root);
    let delta = k0[0].root ^ k1[0].root;
    assert_eq!(delta, k0[1].root ^ k1[1].root, "Δ is the session's");
    assert_ne!(k0[0].cws[1] ^ k0[1].cws[1], delta);
}
