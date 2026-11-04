//! The malicious Gen with a binary payload: correctness against the dealer,
//! Π_Verify, that deviations in Gen are caught by Π_Verify, and that the two
//! deviations a payload MAC cannot see are harmless here (the swap, in
//! characteristic 2) or a consistent choice of α* ((B)).

use dpf_common::block::Block;
use dpf_common::coin::Abort;
use dpf_common::net::run_two_party;
use ht_aes::malicious::{deal, deal_mask, low, mal_ands, open_checked, run_mal, verify, Fault, MalKey, MalRun, MalSession};
use ht_aes::malicious_arith::VerifyMask;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;

/// One Gen of a key for the public β (α is sampled in preprocessing: α_0 ⊕ α_1).
fn run(n: u64, nu: Option<usize>, bits: usize, beta: Block, seed: u64, faults: [Option<Fault>; 2]) -> [MalRun; 2] {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let seeds: [[u8; 32]; 2] = [rng.gen(), rng.gen()];
    let (r0, r1) =
        run_two_party(move |c| run_mal(c, n, nu, bits, beta, seeds[0], None, faults[0]), move |c| run_mal(c, n, nu, bits, beta, seeds[1], None, faults[1]));
    [r0, r1]
}

/// `[K, K^mac]` of a key.
fn keys_of(k: &MalKey) -> [[u8; 16]; 2] {
    [k.prf.key(), k.mac.key()]
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
    let cases = [(2u64, None, 8usize), (8, None, 64), (13, Some(1), 128), (16, Some(2), 5), (16, Some(4), 64), (1 << 9, Some(5), 64)];
    for (i, (n, nu, bits)) in cases.into_iter().enumerate() {
        let beta = low(Block::random(&mut rng), bits);
        let [r0, r1] = run(n, nu, bits, beta, i as u64, [None, None]);
        let alpha = r0.alpha_share ^ r1.alpha_share;
        let (depth, nu) = (r0.key.depth(), r0.key.nu);
        let rounds = (nu + 4).max(if nu < depth { 42 } else { 41 });
        assert_eq!(r0.gen_stats.rounds.max(r1.gen_stats.rounds), rounds, "case {i}");
        assert_eq!(r0.ands, mal_ands(depth, nu));
        let delta = r0.delta_share ^ r1.delta_share;
        let us: Vec<Block> = r0.onpath_share.iter().zip(&r1.onpath_share).map(|(&a, &b)| a ^ b).collect();
        let dealt = deal([r0.key.root, r1.key.root], keys_of(&r0.key), n, nu, bits, alpha, beta, delta, &us);
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

/// A wrong share of a CW (in the top phase or below it), the payload word,
/// the MAC word or `M_ν` in Gen: the run of Gen completes, and Π_Verify over
/// the whole domain aborts.
#[test]
fn faults_in_gen_are_caught_by_verify() {
    let mut rng = ChaCha20Rng::seed_from_u64(2);
    let (n, bits) = (16u64, 16usize);
    // Depth 4, ν = 2: CW_1, CW_2 in the top phase, CW_3, CW_4 below it.
    for level in [0usize, 1, 2, 3, 4, 5, 6] {
        for cheater in [0, 1] {
            let err = Block(1 << rng.gen_range(0..16));
            let mut faults = [None, None];
            faults[cheater] = Some(Fault::Word { level, err });
            let [r0, r1] = run(n, Some(2), bits, Block(77), 10 + level as u64, faults);
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

/// The swap (a flipped share of ¬t_{ν,0} into the glue's 𝓕_COT): with a
/// binary payload the outputs `y_0 ⊕ y_1` do not depend on which server holds
/// which state, so the keys are still correct and Π_Verify accepts.
#[test]
fn swap_is_harmless_in_characteristic_2() {
    let (n, bits) = (1u64 << 6, 32usize);
    for cheater in [0, 1] {
        let mut faults = [None, None];
        faults[cheater] = Some(Fault::Swap);
        let beta = Block(0xdead_beef);
        let [r0, r1] = run(n, Some(3), bits, beta, 40 + cheater as u64, faults);
        let alpha = r0.alpha_share ^ r1.alpha_share;
        let [a, b] = eval_and_verify([r0.key, r1.key], [r0.delta_share, r1.delta_share], [r0.mask, r1.mask], (0..n).collect(), Tamper::No);
        let ys = a.unwrap();
        assert_eq!(b.unwrap(), ys);
        for x in 0..n {
            assert_eq!(ys[x as usize], if x == alpha { beta } else { Block::ZERO }, "x={x}");
        }
    }
}

/// A flipped share of α_ℓ into its one product (𝓕_COT above ν, (B) below):
/// the keys are honest keys for α* = α ⊕ e_ℓ, and Π_Verify accepts.
#[test]
fn flipped_alpha_share_is_a_consistent_alpha_star() {
    let (n, bits) = (1u64 << 6, 32usize);
    let depth = 6;
    for (i, level) in [1usize, 4].into_iter().enumerate() {
        let mut faults = [None, None];
        faults[i] = Some(Fault::Alpha(level));
        let beta = Block(0x1234);
        let [r0, r1] = run(n, Some(3), bits, beta, 50 + level as u64, faults);
        let alpha_star = (r0.alpha_share ^ r1.alpha_share) ^ (1 << (depth - 1 - level));
        let [a, b] = eval_and_verify([r0.key, r1.key], [r0.delta_share, r1.delta_share], [r0.mask, r1.mask], (0..n).collect(), Tamper::No);
        let ys = a.unwrap();
        assert_eq!(b.unwrap(), ys);
        for x in 0..n {
            assert_eq!(ys[x as usize], if x == alpha_star { beta } else { Block::ZERO }, "level {level} x={x}");
        }
    }
}

/// Two Gens on one session: one global Δ and one K (and K^mac) for both,
/// roots re-randomised by a fresh W, fresh α and on-path states per Gen.
#[test]
fn two_gens_in_one_session() {
    let mut rng = ChaCha20Rng::seed_from_u64(7);
    let (n, bits) = (1u64 << 10, 64usize);
    let depth = dpf_common::block::depth_for(n);
    let betas = [low(Block::random(&mut rng), bits), low(Block::random(&mut rng), bits)];
    let seeds: [[u8; 32]; 2] = [rng.gen(), rng.gen()];
    let party = |b: usize| {
        move |c: &mut dpf_common::net::Channel| {
            let mut s = MalSession::setup(c, seeds[b], None);
            let keys: Vec<(MalKey, VerifyMask<Block>, u64, Vec<Block>)> = (0..2)
                .map(|g| {
                    let pre = s.precompute(c, depth, 4);
                    let us = pre.pre.us.clone();
                    let (k, _, m, a) = s.gen(c, n, bits, betas[g], pre, None);
                    (k, m, a, us)
                })
                .collect();
            (keys, s.delta_mac)
        }
    };
    let ((k0, d0), (k1, d1)) = run_two_party(party(0), party(1));
    for g in 0..2 {
        let alpha = k0[g].2 ^ k1[g].2;
        let (a, b) = (k0[g].0.clone(), k1[g].0.clone());
        let us: Vec<Block> = k0[g].3.iter().zip(&k1[g].3).map(|(&x, &y)| x ^ y).collect();
        assert_eq!(deal([a.root, b.root], keys_of(&a), n, 4, bits, alpha, betas[g], d0 ^ d1, &us), [a.clone(), b.clone()]);
        let [ra, rb] = eval_and_verify([a, b], [d0, d1], [k0[g].1, k1[g].1], (0..n).collect(), Tamper::No);
        let ys = ra.unwrap();
        assert_eq!(rb.unwrap(), ys, "both parties open the same outputs");
        for x in 0..n {
            assert_eq!(ys[x as usize], if x == alpha { betas[g] } else { Block::ZERO });
        }
    }
    // One Δ and one K for the session; W re-randomises the roots.
    assert_eq!(k0[0].0.root ^ k1[0].0.root, k0[1].0.root ^ k1[1].0.root, "one Δ for the session");
    assert_ne!(k0[0].0.root, k0[1].0.root, "W re-randomises the roots per Gen");
    assert_eq!(keys_of(&k0[0].0), keys_of(&k0[1].0), "one K, K^mac for the session");
}
