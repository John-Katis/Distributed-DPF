//! The malicious Gen with a Boolean payload: correctness against the dealer,
//! Π_Verify, that deviations in Gen are caught by Π_Verify, and that the two
//! deviations a payload MAC cannot see are harmless here (the swap, in
//! characteristic 2) or a consistent choice of α*.

use dpf_common::block::Block;
use dpf_common::coin::Abort;
use dpf_common::net::run_two_party;
use ht_aes::field::{Field, Gf128, Gf64};
use ht_aes::malicious::{bin_tau, deal, gen_reference, low, open_checked, run_mal, verify, Fault, MalKey, MalRun, MalSession, Word};
use ht_aes::malicious_arith::{deal_mask, VerifyMask};
use ht_aes::mal_ands;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;

/// One Gen of a key for the public β (α is sampled in preprocessing: α_0 ⊕ α_1).
fn run<K: Field>(n: u64, nu: Option<usize>, bits: usize, beta: Block, seed: u64, faults: [Option<Fault>; 2]) -> [MalRun<K>; 2] {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let seeds: [[u8; 32]; 2] = [rng.gen(), rng.gen()];
    let (r0, r1) = run_two_party(move |c| run_mal::<K>(c, n, nu, bits, beta, seeds[0], None, faults[0]), move |c| run_mal::<K>(c, n, nu, bits, beta, seeds[1], None, faults[1]));
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
fn eval_and_verify<K: Field>(keys: &[MalKey<K>; 2], d: [K; 2], masks: [VerifyMask<K>; 2], xs: Vec<u64>, tamper: Tamper) -> [Result<Vec<Block>, Abort>; 2] {
    let party = |p: usize| {
        let outs: Vec<(Block, K)> = xs.iter().map(|&x| keys[p].eval_point(x)).collect();
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

fn verify_run<K: Field>(r: [MalRun<K>; 2], xs: Vec<u64>) -> [Result<Vec<Block>, Abort>; 2] {
    let [r0, r1] = r;
    eval_and_verify(&[r0.key, r1.key], [r0.delta_share, r1.delta_share], [r0.mask, r1.mask], xs, Tamper::No)
}

fn xor_pairs(a: &[[Block; 2]], b: &[[Block; 2]]) -> Vec<[Block; 2]> {
    a.iter().zip(b).map(|(x, y)| [x[0] ^ y[0], x[1] ^ y[1]]).collect()
}

fn gen_matches_dealer_and_verifies<K: Field>(cases: &[(u64, Option<usize>, usize)], seed: u64) {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    for (i, &(n, nu, bits)) in cases.iter().enumerate() {
        let beta = low(Block::random(&mut rng), bits);
        let [r0, r1] = run::<K>(n, nu, bits, beta, seed + i as u64, [None, None]);
        let alpha = r0.alpha_share ^ r1.alpha_share;
        let (depth, nu) = (r0.key.depth(), r0.key.nu());
        let rounds = if nu < depth { (nu + 2).max(23) } else { (nu + 1).max(22) };
        assert_eq!(r0.gen_stats.rounds.max(r1.gen_stats.rounds), rounds, "case {i}");
        assert_eq!(r0.ands, mal_ands(depth, nu, bin_tau::<K>(bits)));
        let delta = r0.delta_share.add(r1.delta_share);
        let levels = depth - nu + 1;
        let pairs = xor_pairs(&r0.pairs, &r1.pairs);
        let rs: Vec<bool> = r0.rs.iter().zip(&r1.rs).map(|(&a, &b)| a ^ b).collect();
        let dealt = deal([r0.key.root, r1.key.root], r0.key.prf.key(), n, nu, bits, alpha, beta, delta, &pairs[..levels], &pairs[levels..], &rs);
        assert_eq!(dealt, [r0.key.clone(), r1.key.clone()]);
        let xs: Vec<u64> = (0..n).collect();
        let (d, m) = ([r0.delta_share, r1.delta_share], [r0.mask, r1.mask]);
        let keys = [r0.key, r1.key];
        let [a, b] = eval_and_verify(&keys, d, m, xs.clone(), Tamper::No);
        let ys = a.unwrap();
        assert_eq!(b.unwrap(), ys, "both parties open the same outputs");
        for x in 0..n {
            assert_eq!(ys[x as usize], if x == alpha { beta } else { Block::ZERO });
        }
        // A falsified output share is caught.
        let [a, b] = eval_and_verify(&keys, d, m, xs.clone(), Tamper::Verify);
        assert!(a.is_err() && b.is_err());
        // A share falsified only at the opening is caught too.
        let [a, b] = eval_and_verify(&keys, d, m, xs, Tamper::Open);
        assert_eq!(a.err(), Some(Abort("opened output MAC check failed")));
        assert_eq!(b.err(), Some(Abort("opened output MAC check failed")));
    }
}

#[test]
fn mal_gen_matches_dealer_and_verifies_gf64() {
    gen_matches_dealer_and_verifies::<Gf64>(&[(2, None, 8), (8, None, 64), (16, Some(2), 5), (16, Some(4), 64), (1 << 9, Some(5), 64)], 1);
}

#[test]
fn mal_gen_matches_dealer_and_verifies_gf128() {
    gen_matches_dealer_and_verifies::<Gf128>(&[(8, None, 64), (13, Some(1), 128), (16, Some(2), 100), (1 << 9, Some(5), 128)], 31);
}

#[test]
fn tau_of_the_boolean_leaf() {
    assert_eq!(bin_tau::<Gf64>(64), 1, "ℓ = k = 64: one block serves both masks");
    assert_eq!(bin_tau::<Gf128>(128), 2);
    assert_eq!(bin_tau::<Gf64>(8), 1);
}

/// Every public word of Gen at depth 4 with ν = 2, and for τ = 2 the leaf
/// pair's: Gen completes, and Π_Verify over the whole domain aborts.
fn faults_are_caught<K: Field>(bits: usize, leaf: bool, seed: u64) {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let n = 16u64;
    let mut words: Vec<Word> = (0..4).map(Word::Cw).collect();
    words.extend([Word::Payload, Word::Mac]);
    words.extend((0..3).flat_map(|j| [Word::M0(j), Word::C(j), Word::BTau(j, 0), Word::BTau(j, 1)]));
    if leaf {
        words.extend([Word::LeafC(0), Word::LeafN(0)]);
    }
    for (i, word) in words.into_iter().enumerate() {
        for cheater in [0, 1] {
            let err = Block(1 << rng.gen_range(1..16)).with_lsb(matches!(word, Word::BTau(..)));
            let mut faults = [None, None];
            faults[cheater] = Some(Fault::Word(word, err));
            let r = run::<K>(n, Some(2), bits, Block(77), 10 + i as u64, faults);
            let [a, b] = verify_run(r, (0..n).collect());
            assert_eq!(a.err(), Some(Abort("output MAC check failed")), "{word:?} cheater {cheater}");
            assert_eq!(b.err(), Some(Abort("output MAC check failed")), "{word:?} cheater {cheater}");
        }
    }
}

#[test]
fn faults_in_gen_are_caught_by_verify_gf64() {
    faults_are_caught::<Gf64>(16, false, 2);
}

#[test]
fn faults_in_gen_are_caught_by_verify_gf128() {
    faults_are_caught::<Gf128>(16, true, 3);
}

/// Dealer keys with a dealer's Π_Verify masks verify; a mask that does not
/// match δ is rejected.
#[test]
fn dealer_keys_verify() {
    let mut rng = ChaCha20Rng::seed_from_u64(4);
    let (n, bits) = (32u64, 64usize);
    let (keys, d) = gen_reference::<Gf64>(n, bits, 7, low(Block::random(&mut rng), bits), rng.gen());
    let m = deal_mask(d[0].add(d[1]), &mut rng);
    let [a, b] = eval_and_verify(&keys, d, m, (0..n).collect(), Tamper::No);
    assert!(a.is_ok() && b.is_ok());
    let bad = deal_mask(d[0], &mut rng);
    let [a, _] = eval_and_verify(&keys, d, bad, (0..n).collect(), Tamper::No);
    assert!(a.is_err());
}

fn full_eval_matches_point_eval<K: Field>(cases: &[(u64, usize)]) {
    let mut rng = ChaCha20Rng::seed_from_u64(3);
    for &(n, bits) in cases {
        let beta = low(Block::random(&mut rng), bits);
        let (keys, _) = gen_reference::<K>(n, bits, rng.gen_range(0..n), beta, rng.gen());
        for k in &keys {
            let points: Vec<(Block, K)> = (0..n).map(|x| k.eval_point(x)).collect();
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

#[test]
fn full_eval_matches_point_eval_gf64() {
    full_eval_matches_point_eval::<Gf64>(&[(2, 64), (64, 5), (1000, 64)]);
}

#[test]
fn full_eval_matches_point_eval_gf128() {
    full_eval_matches_point_eval::<Gf128>(&[(13, 128), (1000, 64)]);
}

/// The swap with a Boolean payload: both servers take the other server's state
/// as `st_{ν,0}`. The outputs `y_0 ⊕ y_1` do not depend on which server holds
/// which state, so the keys are correct and Π_Verify accepts.
#[test]
fn swap_is_harmless_in_characteristic_2() {
    let (n, bits) = (1u64 << 6, 32usize);
    let beta = Block(0xdead_beef);
    let r = run::<Gf64>(n, Some(3), bits, beta, 40, [Some(Fault::Swap), Some(Fault::Swap)]);
    let alpha = r[0].alpha_share ^ r[1].alpha_share;
    let [a, b] = verify_run(r, (0..n).collect());
    let ys = a.unwrap();
    assert_eq!(b.unwrap(), ys);
    for x in 0..n {
        assert_eq!(ys[x as usize], if x == alpha { beta } else { Block::ZERO }, "x={x}");
    }
}

/// A flipped share of α_ℓ into its one product (𝓕_COT above ν, Step A below):
/// the keys are honest keys for α* = α ⊕ e_ℓ, and Π_Verify accepts.
#[test]
fn flipped_alpha_share_is_a_consistent_alpha_star() {
    let (n, bits) = (1u64 << 6, 32usize);
    let depth = 6;
    for (i, level) in [1usize, 4].into_iter().enumerate() {
        let mut faults = [None, None];
        faults[i] = Some(Fault::Alpha(level));
        let beta = Block(0x1234);
        let r = run::<Gf64>(n, Some(3), bits, beta, 50 + level as u64, faults);
        let alpha_star = (r[0].alpha_share ^ r[1].alpha_share) ^ (1 << (depth - 1 - level));
        let [a, b] = verify_run(r, (0..n).collect());
        let ys = a.unwrap();
        assert_eq!(b.unwrap(), ys);
        for x in 0..n {
            assert_eq!(ys[x as usize], if x == alpha_star { beta } else { Block::ZERO }, "level {level} x={x}");
        }
    }
}

/// Two Gens on one session: one global Δ and one K for both, roots re-randomised
/// by a fresh W, fresh α and pairs per Gen.
#[test]
fn two_gens_in_one_session() {
    let mut rng = ChaCha20Rng::seed_from_u64(7);
    let (n, bits) = (1u64 << 10, 64usize);
    let betas = [low(Block::random(&mut rng), bits), low(Block::random(&mut rng), bits)];
    let seeds: [[u8; 32]; 2] = [rng.gen(), rng.gen()];
    let party = |b: usize| {
        move |c: &mut dpf_common::net::Channel| {
            let mut s = MalSession::<Gf64>::setup(c, seeds[b], None);
            let runs: Vec<MalRun<Gf64>> = (0..2).map(|g| s.gen(c, n, Some(4), bits, betas[g], None)).collect();
            (runs, s.delta_mac)
        }
    };
    let ((k0, d0), (k1, d1)) = run_two_party(party(0), party(1));
    for g in 0..2 {
        let (a, b) = (&k0[g], &k1[g]);
        let alpha = a.alpha_share ^ b.alpha_share;
        let pairs = xor_pairs(&a.pairs, &b.pairs);
        let rs: Vec<bool> = a.rs.iter().zip(&b.rs).map(|(&x, &y)| x ^ y).collect();
        let dealt = deal([a.key.root, b.key.root], a.key.prf.key(), n, 4, bits, alpha, betas[g], d0.add(d1), &pairs, &[], &rs);
        assert_eq!(dealt, [a.key.clone(), b.key.clone()]);
        let [ra, rb] = eval_and_verify(&[a.key.clone(), b.key.clone()], [d0, d1], [a.mask, b.mask], (0..n).collect(), Tamper::No);
        let ys = ra.unwrap();
        assert_eq!(rb.unwrap(), ys, "both parties open the same outputs");
        for x in 0..n {
            assert_eq!(ys[x as usize], if x == alpha { betas[g] } else { Block::ZERO });
        }
    }
    // One Δ and one K for the session; W re-randomises the roots.
    assert_eq!(k0[0].key.root ^ k1[0].key.root, k0[1].key.root ^ k1[1].key.root, "one Δ for the session");
    assert_ne!(k0[0].key.root, k0[1].key.root, "W re-randomises the roots per Gen");
    assert_eq!(k0[0].key.prf.key(), k0[1].key.prf.key(), "one K for the session");
}
