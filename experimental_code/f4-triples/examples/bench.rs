//! Cost of the F4 triples one ht-aes Gen needs, per source.
//!
//! ```text
//! cargo run --release -p exp-f4-triples --example bench-f4-triples -- foleage --c 5 [--log3 N] [--in-bits 32] [--variant sh|mal]
//! cargo run --release -p exp-f4-triples --example bench-f4-triples -- ot [--in-bits 32] [--variant sh|mal]
//! ```
//!
//! Both start from the ht-aes setup (base OTs, Ferret `B13`), not counted.
//! `foleage`: seed generation for `3^N` OLEs (default: the largest N outside
//! ePrint 2025/892 for that c) and both parties' expansion, then how many Gens
//! of depth n the instance serves and the seed generation's share per Gen.
//! `ot`: the triples of one Gen from random COTs.

use dpf_common::block::Block;
use dpf_common::f4;
use dpf_common::net::{run_two_party, Channel};
use dpf_common::ot::{CotPair, FerretConfig};
use exp_f4_triples::foleage::{seedgen::seed_gen, Params};
use exp_f4_triples::ot_triples::rot_f4_triples;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::time::Instant;

struct Args {
    mode: String,
    c: usize,
    log3: Option<usize>,
    depth: usize,
    variant: String,
}

fn args() -> Args {
    let v: Vec<String> = std::env::args().skip(1).collect();
    let mut a = Args { mode: v.first().cloned().expect("foleage|ot"), c: 4, log3: None, depth: 32, variant: "sh".into() };
    let mut i = 1;
    while i < v.len() {
        let val = || v.get(i + 1).expect("missing flag value").clone();
        match v[i].as_str() {
            "--c" => a.c = val().parse().unwrap(),
            "--log3" => a.log3 = Some(val().parse().unwrap()),
            "--in-bits" => a.depth = val().parse().unwrap(),
            "--variant" => a.variant = val(),
            other => panic!("unknown argument {other}"),
        }
        i += 2;
    }
    a
}

/// F4 products of one Gen of depth n.
fn products(variant: &str, n: usize) -> usize {
    match variant {
        "sh" => ht_aes::sh_products(n),
        "mal" => ht_aes::malicious::mal_products(n),
        v => panic!("variant {v}: sh|mal"),
    }
}

fn session(ch: &mut Channel, seed: u64) -> (CotPair, ChaCha20Rng) {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let d = Block::random(&mut rng).with_lsb(ch.party() == 1);
    let mut cot = CotPair::setup(ch, &mut rng, d, false).unwrap();
    cot.enable_ferret(ch, FerretConfig::B13, &mut rng).unwrap();
    (cot, rng)
}

fn main() {
    let a = args();
    let per_gen = products(&a.variant, a.depth);
    match a.mode.as_str() {
        "foleage" => {
            let p = Params::with_c(a.log3.unwrap_or(Params::max_log3(a.c)), a.c);
            let party = move |seed: u64| {
                move |ch: &mut Channel| {
                    let (mut cot, mut rng) = session(ch, seed);
                    let before = ch.stats();
                    let t = Instant::now();
                    let s = seed_gen(ch, &mut cot, p, &mut rng);
                    let (stats, sg) = (ch.stats().since(&before), t.elapsed());
                    let t = Instant::now();
                    let ole = s.expand();
                    let ex = t.elapsed();
                    // A sample of OLEs for the correctness check.
                    let step = p.oles() / 997;
                    let sample: Vec<(u8, u8)> = (0..p.oles()).step_by(step).map(|k| (ole.x[k], ole.z[k])).collect();
                    (stats, sg, ex, sample)
                }
            };
            let ((s0, sg0, ex0, o0), (s1, sg1, ex1, o1)) = run_two_party(party(1), party(2));
            for (x, y) in o0.iter().zip(&o1) {
                assert_eq!(x.1 ^ y.1, f4::mul(x.0, y.0), "OLE check failed");
            }
            let keys = p.oles() / (2 * per_gen);
            let bytes = s0.total_bytes();
            println!("source,c,N,oles,dpfs,seedgen_bytes,seedgen_rounds,seedgen_ms,expand_ms,variant,in_bits,triples_per_gen,gens_per_instance,seedgen_bytes_per_gen");
            println!(
                "foleage,{},{},{},{},{},{},{:.1},{:.1},{},{},{},{},{}",
                p.c,
                p.log3,
                p.oles(),
                p.dpfs(),
                bytes,
                s0.rounds.max(s1.rounds),
                sg0.max(sg1).as_secs_f64() * 1e3,
                ex0.max(ex1).as_secs_f64() * 1e3,
                a.variant,
                a.depth,
                per_gen,
                keys,
                bytes.checked_div(keys).map_or("inf".into(), |b| b.to_string())
            );
        }
        "ot" => {
            let party = move |seed: u64| {
                move |ch: &mut Channel| {
                    let (mut cot, mut rng) = session(ch, seed);
                    let (before, cots) = (ch.stats(), cot.produced);
                    let t = Instant::now();
                    let tr = rot_f4_triples(ch, &mut cot, per_gen, &mut rng);
                    (ch.stats().since(&before), t.elapsed(), cot.produced - cots, tr)
                }
            };
            let ((s0, t0, cots, tr0), (s1, t1, _, tr1)) = run_two_party(party(1), party(2));
            for (x, y) in tr0.iter().zip(&tr1) {
                assert_eq!(x.2 ^ y.2, f4::mul(x.0 ^ y.0, x.1 ^ y.1), "triple check failed");
            }
            println!("source,variant,in_bits,triples_per_gen,bytes,rounds,ms,cots_per_direction");
            println!("ot,{},{},{},{},{},{:.1},{}", a.variant, a.depth, per_gen, s0.total_bytes(), s0.rounds.max(s1.rounds), t0.max(t1).as_secs_f64() * 1e3, cots);
        }
        m => panic!("mode {m}: foleage|ot"),
    }
}
