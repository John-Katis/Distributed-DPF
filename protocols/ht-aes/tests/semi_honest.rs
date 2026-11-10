//! The semi-honest Gen (payload in F_p, public β) against the cleartext point
//! function and the dealer, for glue levels ν from 1 to n.

use dpf_common::block::Block;
use dpf_common::net::run_two_party;
use ht_aes::field::{BabyBear, Field, Gold, M127};
use ht_aes::semi_honest::{deal, gen, Session, ShKey};
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

/// The pair inputs `[X^0_ℓ, X^1_ℓ]` and the bits `r_ℓ` from the two parties' shares.
fn open_pairs(a: &[[Block; 2]], b: &[[Block; 2]], ra: &[bool], rb: &[bool]) -> (Vec<[Block; 2]>, Vec<bool>) {
    (a.iter().zip(b).map(|(x, y)| [x[0] ^ y[0], x[1] ^ y[1]]).collect(), ra.iter().zip(rb).map(|(&x, &y)| x ^ y).collect())
}

type Run<F> = ([ShKey<F>; 2], u64, Vec<[Block; 2]>, Vec<bool>);

/// One Gen of a key for the public β with switch level ν; returns the keys,
/// the random α (α_0 ⊕ α_1), the pair inputs and the bits r_ν, …, r_n.
fn run<F: Field>(n: u64, nu: Option<usize>, beta: F, seed: u64) -> Run<F> {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let seeds: [[u8; 32]; 2] = [rng.gen(), rng.gen()];
    let (o0, o1) = run_two_party(move |c| gen(c, n, nu, beta, seeds[0], None), move |c| gen(c, n, nu, beta, seeds[1], None));
    let (depth, nu) = (o0.key.depth(), o0.key.nu());
    assert_eq!(o0.ands, sh_ands(depth, nu));
    assert_eq!(o0.ands, sh_calls(depth, nu) * dpf_common::aes_tower::ANDS_PER_CALL);
    // The top phase and the glue's COT (ν + 1 rounds) concurrently with the
    // pairs (20), then C_ℓ, then CW_ℓ and M^0_ν, then M^0_ℓ and W_CW.
    assert!(nu >= 1);
    assert_eq!(o0.gen_stats.rounds.max(o1.gen_stats.rounds), rounds(depth, nu), "n={depth} ν={nu}");
    // The roots are k_b = Δ_b ⊕ W, lsb(Δ_b) = b and lsb(W) = 0.
    assert!(!o0.key.root.lsb() && o1.key.root.lsb());
    let alpha = o0.alpha_share ^ o1.alpha_share;
    assert!(alpha < 1 << depth);
    let (pairs, rs) = open_pairs(&o0.pairs, &o1.pairs, &o0.rs, &o1.rs);
    assert_eq!(pairs.len(), depth - nu + 1);
    ([o0.key, o1.key], alpha, pairs, rs)
}

/// Rounds of Gen: `max(ν + 3, 23)`, the leaf keeping it at 23 for ν = n.
fn rounds(n: usize, nu: usize) -> usize {
    if nu < n {
        (nu + 3).max(23)
    } else {
        (nu + 2).max(23)
    }
}

fn gen_matches_point_function_and_dealer<F: Field>(seed: u64) {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let mut s = seed;
    for (n, nus) in [(2u64, vec![None]), (8, vec![None, Some(1), Some(3)]), (16, vec![Some(2), Some(4)]), (13, vec![None]), (1 << 9, vec![Some(4), Some(9)])] {
        for nu in nus {
            s += 1;
            let beta = F::random(&mut rng);
            let (keys, alpha, pairs, rs) = run::<F>(n, nu, beta, s);
            check(&keys, n, alpha, beta);
            assert_eq!(deal([keys[0].root, keys[1].root], keys[0].prf.key(), n, keys[0].nu(), alpha, beta, &pairs, &rs), keys);
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
        for nu in [1, (depth / 2).max(1), depth] {
            let pairs: Vec<[Block; 2]> = (nu..=depth).map(|_| [Block::random(&mut rng), Block::random(&mut rng)]).collect();
            let rs: Vec<bool> = (nu..=depth).map(|_| rng.gen()).collect();
            check(&deal(roots, rng.gen(), n, nu, alpha, beta, &pairs, &rs), n, alpha, beta);
        }
    }
}

#[test]
fn gen_at_domain_2_pow_63() {
    let mut rng = ChaCha20Rng::seed_from_u64(3);
    let n = 1u64 << 63;
    let beta = Gold::random(&mut rng);
    let (keys, alpha, _, _) = run::<Gold>(n, Some(8), beta, 7);
    assert_eq!(keys[0].depth(), 63);
    for x in [alpha, alpha ^ 1, alpha ^ (1 << 62), 0, n - 1, rng.gen_range(0..n)] {
        let y = keys[0].eval_point(x).add(keys[1].eval_point(x));
        assert_eq!(y, if x == alpha { beta } else { Gold::ZERO }, "x={x}");
    }
}

/// Several Gens on one session: one global Δ (also the Ferret keys Γ_b = Δ_b)
/// and one public K for all of them, roots re-randomised by a fresh public W
/// per Gen, fresh α and on-path pairs.
#[test]
fn gens_in_one_session_share_delta_and_key() {
    session_gens(None);
}

/// The same on Ferret, whose keys are then Γ_b = Δ_b (party 0's with lsb 0).
#[test]
fn gens_in_one_session_on_ferret() {
    session_gens(Some(dpf_common::ot::FerretConfig::TOY));
}

fn session_gens(ferret: Option<dpf_common::ot::FerretConfig>) {
    let mut rng = ChaCha20Rng::seed_from_u64(9);
    let n = 1u64 << 9;
    let betas: [M127; 3] = [M127::random(&mut rng), M127::random(&mut rng), M127::random(&mut rng)];
    let seeds: [[u8; 32]; 2] = [rng.gen(), rng.gen()];
    let party = |b: usize| {
        move |c: &mut dpf_common::net::Channel| {
            let mut s = Session::setup(c, seeds[b], ferret);
            [(Some(4), betas[0]), (Some(1), betas[1]), (None, betas[2])].map(|(nu, beta)| s.gen(c, n, nu, beta))
        }
    };
    let (o0, o1) = run_two_party(party(0), party(1));
    let delta = o0[0].key.root ^ o1[0].key.root;
    for (g, (a, b)) in o0.iter().zip(&o1).enumerate() {
        let alpha = a.alpha_share ^ b.alpha_share;
        let (pairs, rs) = open_pairs(&a.pairs, &b.pairs, &a.rs, &b.rs);
        let keys = [a.key.clone(), b.key.clone()];
        check(&keys, n, alpha, betas[g]);
        assert_eq!(deal([keys[0].root, keys[1].root], keys[0].prf.key(), n, keys[0].nu(), alpha, betas[g], &pairs, &rs), keys);
        assert_eq!(keys[0].root ^ keys[1].root, delta, "one Δ for the session");
        assert_eq!(keys[0].prf, o0[0].key.prf, "one K for the session");
        assert!(!keys[0].root.lsb() && keys[1].root.lsb());
        assert_eq!(a.gen_stats.rounds.max(b.gen_stats.rounds), rounds(keys[0].depth(), keys[0].nu()));
    }
    assert_ne!(o0[0].key.root, o0[1].key.root, "W re-randomises the roots per Gen");
    assert_ne!(o0[1].key.root, o0[2].key.root);
}
