//! Costs of the two approaches per instance size.
//!
//! ```text
//! cargo run --release -p exp-mal-foleage --example bench-mal-foleage -- [N ...]   (default 8 9 10)
//! ```
//!
//! One CSV row per (approach, N): instance triples, triples out, dealer seed
//! bytes per party, expansion ms (one party), and for (b) the 2PC
//! authentication + sacrifice (bytes both directions, rounds, ms; Ferret B13
//! bootstrapped before and not counted). `seed_bits_per_triple` is what a
//! distributed seed generation would at least have to move;
//! `comm_bits_per_triple` is the online cost of (b) per output triple.

use dpf_common::foleage::Params;
use dpf_common::mac::binary::{delta_for_seed, MacParty};
use dpf_common::net::run_two_party;
use dpf_common::ot::FerretConfig;
use exp_mal_foleage::pcg::{deal, Mode};
use exp_mal_foleage::sacrifice::{authenticate_and_sacrifice, bucket_size};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::time::Instant;

fn main() {
    let ns: Vec<usize> = std::env::args().skip(1).map(|a| a.parse().expect("N")).collect();
    let ns = if ns.is_empty() { vec![8, 9, 10] } else { ns };
    println!("approach,N,instance_triples,triples_out,bucket,seed_bytes_per_party,seed_bits_per_triple,deal_ms,expand_ms,expand_ns_per_triple,comm_bytes,comm_bits_per_triple,rounds,auth_ms");
    for &n in &ns {
        let p = Params::new(n);
        for mode in [Mode::Full, Mode::Linear] {
            let seeds: [[u8; 32]; 2] = [[n as u8; 32], [100 + n as u8; 32]];
            let d = [delta_for_seed(seeds[0], 0), delta_for_seed(seeds[1], 1)];
            let mut rng = ChaCha20Rng::seed_from_u64(n as u64);
            let t = Instant::now();
            let [s0, s1] = deal(p, mode, d, &mut rng);
            let deal_ms = t.elapsed().as_secs_f64() * 1e3;
            let seed_bytes = s0.size_bytes();
            let t = Instant::now();
            let r0 = s0.expand();
            let expand_ms = t.elapsed().as_secs_f64() * 1e3;
            let inst = p.oles();
            match mode {
                Mode::Full => {
                    println!(
                        "a,{n},{inst},{inst},1,{seed_bytes},{:.1},{deal_ms:.0},{expand_ms:.0},{:.0},0,0,0,0",
                        8.0 * seed_bytes as f64 / inst as f64,
                        expand_ms * 1e6 / inst as f64
                    );
                }
                Mode::Linear => {
                    // Largest output that fits with its own bucket size.
                    let mut out = inst;
                    while out * bucket_size(out) > inst {
                        out -= 1;
                    }
                    let bkt = bucket_size(out);
                    let r1 = s1.expand();
                    let party = |seed: [u8; 32], raw: exp_mal_foleage::pcg::Raw| {
                        move |ch: &mut dpf_common::net::Channel| {
                            let mut mac = MacParty::setup(ch, seed).unwrap();
                            let mut r = mac.rng().clone();
                            mac.cot.enable_ferret(ch, FerretConfig::B13, &mut r).unwrap();
                            *mac.rng() = r;
                            ch.sync();
                            let before = ch.stats();
                            let t = Instant::now();
                            let tr = authenticate_and_sacrifice(ch, &mut mac, &raw, out, None).expect("honest run");
                            (tr.len(), ch.stats().since(&before), t.elapsed())
                        }
                    };
                    let ((k, st, el), (_, st1, _)) = run_two_party(party(seeds[0], r0), party(seeds[1], r1));
                    let bytes = st.bytes_sent + st1.bytes_sent;
                    println!(
                        "b,{n},{inst},{k},{bkt},{seed_bytes},{:.1},{deal_ms:.0},{expand_ms:.0},{:.0},{bytes},{:.1},{},{:.0}",
                        8.0 * seed_bytes as f64 / k as f64,
                        expand_ms * 1e6 / inst as f64,
                        8.0 * bytes as f64 / k as f64,
                        st.rounds.max(st1.rounds),
                        el.as_secs_f64() * 1e3
                    );
                }
            }
        }
    }
}
