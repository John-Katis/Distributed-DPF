//! Actively secure DPF: honest runs output valid SPDZ sharings of `unit(α)` and
//! `β·unit(α)`, and any tampered correction word makes the MAC check abort.

use dpf_common::coin::Abort;
use dpf_common::mac::binary::{dealer, AuthGf};
use dpf_common::ot::FerretConfig;
use half_tree::malicious::{gen_reference, Fault, MalFull, MalKey};
use half_tree::{run_mal_gen, Block};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;

fn check_full(f: &[MalFull; 2], deltas: [Block; 2], n: u64, alpha: u64, beta: &[Block]) {
    for x in 0..n as usize {
        let u = dealer::open_gf(&[f[0].u[x], f[1].u[x]], deltas).expect("u MAC invalid");
        assert_eq!(u, Block((x as u64 == alpha) as u128), "u wrong at x={x}");
        for (k, b) in beta.iter().enumerate() {
            let v = dealer::open_gf(&[f[0].v[k][x], f[1].v[k][x]], deltas).expect("v MAC invalid");
            assert_eq!(v, if x as u64 == alpha { *b } else { Block::ZERO }, "v wrong at x={x} k={k}");
        }
    }
}

fn check_keys(keys: &[MalKey; 2], fulls: &[MalFull; 2]) {
    assert_eq!(keys[0].public_part(), keys[1].public_part());
    for (k, f) in keys.iter().zip(fulls) {
        assert_eq!(&k.eval_full(), f, "eval_full differs from gen output");
        for x in 0..k.n_size {
            let (u, v) = k.eval_point(x);
            assert_eq!(u, f.u[x as usize]);
            assert_eq!(v, f.v_at(x as usize));
        }
    }
}

#[test]
fn honest_runs_give_valid_authenticated_unit_vectors() {
    let mut rng = ChaCha20Rng::seed_from_u64(5);
    let mut seed = 0;
    for n in [2u64, 3, 7, 100, 1024, 1027] {
        for bm in [1usize, 2] {
            for alpha in [0, n - 1, rng.gen_range(0..n)] {
                let beta: Vec<Block> = (0..bm).map(|_| Block::random(&mut rng)).collect();
                seed += 1;
                let run = run_mal_gen(n, alpha, &beta, seed, [None, None], None);
                let [r0, r1] = run.outs.map(|r| r.expect("honest run aborted"));
                let deltas = [r0.delta, r1.delta];
                let fulls = [r0.out.full, r1.out.full];
                check_full(&fulls, deltas, n, alpha, &beta);
                check_keys(&[r0.out.key, r1.out.key], &fulls);
            }
        }
    }
}

#[test]
fn dealer_keys_are_valid() {
    let mut rng = ChaCha20Rng::seed_from_u64(6);
    for n in [2u64, 5, 1000, 4096] {
        let alpha = rng.gen_range(0..n);
        let beta: Vec<Block> = (0..2).map(|_| Block::random(&mut rng)).collect();
        let (keys, deltas) = gen_reference(n, alpha, &beta, rng.gen());
        let fulls = [keys[0].eval_full(), keys[1].eval_full()];
        check_full(&fulls, deltas, n, alpha, &beta);
        let (u0, _) = keys[0].eval_point(alpha);
        let (u1, _) = keys[1].eval_point(alpha);
        assert_eq!(dealer::open_gf(&[u0, u1], deltas), Some(Block(1)));
    }
}

#[test]
fn tampered_correction_words_abort() {
    let mut rng = ChaCha20Rng::seed_from_u64(7);
    let n = 256u64;
    let depth = 8;
    for (i, level) in [0usize, 3, depth - 1, depth].into_iter().enumerate() {
        for cheater in 0..2 {
            let err = Block(1u128 << rng.gen_range(0..128));
            let mut faults = [None, None];
            faults[cheater] = Some(Fault { level, err });
            let run = run_mal_gen(n, rng.gen_range(0..n), &[Block(42)], 100 + i as u64, faults, None);
            for (b, r) in run.outs.iter().enumerate() {
                assert_eq!(r.as_ref().err(), Some(&Abort("MAC check failed")), "level {level} cheater {cheater}: party {b} did not abort");
            }
        }
    }
}

#[test]
fn output_shares_hide_beta() {
    let run = run_mal_gen(64, 9, &[Block(77)], 1, [None, None], None);
    let r0 = run.outs[0].as_ref().unwrap();
    let v: &AuthGf = &r0.out.full.v[0][9];
    assert_ne!(v.x, Block(77));
}

#[test]
fn ferret_backed_runs_are_valid_and_catch_tampering() {
    let mut rng = ChaCha20Rng::seed_from_u64(8);
    for n in [16u64, 1000] {
        let alpha = rng.gen_range(0..n);
        let beta = vec![Block::random(&mut rng)];
        let run = run_mal_gen(n, alpha, &beta, 77 + n, [None, None], Some(FerretConfig::TOY));
        let [r0, r1] = run.outs.map(|r| r.expect("honest Ferret run aborted"));
        let fulls = [r0.out.full, r1.out.full];
        check_full(&fulls, [r0.delta, r1.delta], n, alpha, &beta);
    }
    let fault = Some(Fault { level: 2, err: Block(1 << 40) });
    let run = run_mal_gen(64, 3, &[Block(9)], 5, [fault, None], Some(FerretConfig::TOY));
    for r in &run.outs {
        assert_eq!(r.as_ref().err(), Some(&Abort("MAC check failed")));
    }
}
