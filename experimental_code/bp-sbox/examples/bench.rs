//! The AES part of one ht-aes Gen (sh-bin) on three S-box backends, and the
//! whole ht-aes Gen as it is (OtTower) for the rest.
//!
//! ```text
//! cargo run --release -p exp-bp-sbox --example bench-bp-sbox -- [--n 32] [--reps 5]
//! ```
//!
//! The AES part is what `ht_aes::semi_honest::walk` and the leaf run through
//! `mmo_shared`: n levels of two `H_K` calls each, Π_KeyExp of K and K' with
//! the level-1 calls, and the two leaf calls under K', `2n + 2` calls in
//! `40(n + 1)` rounds. The OT tower's COTs come from Ferret (B13) as in
//! ht-aes. Setup (base OTs, Ferret bootstrap) is not counted; "pool" is
//! taking the COTs from Ferret, "online" the AES calls.

use dpf_common::aes_tower::{bits_of, block_of, mmo_shared, Mmo, OtTower, SharedKey, TowerBackend};
use dpf_common::bench::{LAN, WAN};
use dpf_common::block::Block;
use dpf_common::net::{run_two_party, Channel, CommStats};
use dpf_common::ot::{CotPair, FerretConfig, RandomCots};
use exp_bp_sbox::{boyar_peralta, tower, CotCircuit, Schedule};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use std::time::{Duration, Instant};

struct Party {
    keys: [Block; 2],
    delta: Block,
    out: [Block; 2],
    stats: CommStats,
    online: Duration,
    pool_time: Duration,
    ands: usize,
    left: usize,
}

struct Run {
    bytes: usize,
    rounds: usize,
    online: Duration,
    pool_time: Duration,
    pool: usize,
    ands: usize,
}

fn aes_part<B, F>(n: usize, cots_per_sbox: usize, mk: F, seeds: [[u8; 32]; 2]) -> Run
where
    B: TowerBackend<Bit = bool> + Counted,
    F: Fn(usize, RandomCots, Block) -> B + Send + Sync + Copy,
{
    let need = (2 * n + 2) * 160 * cots_per_sbox + 2 * 40 * cots_per_sbox;
    let party = |b: usize| {
        move |ch: &mut Channel| {
            let mut rng = ChaCha20Rng::from_seed(seeds[b]);
            let gamma = Block::random(&mut rng);
            let mut cot = CotPair::setup(ch, &mut rng, gamma, false).unwrap();
            cot.enable_ferret(ch, FerretConfig::B13, &mut rng).unwrap();
            ch.sync();
            let t = Instant::now();
            let pool = cot.random_cots(ch, 0, need, &mut rng).unwrap();
            let mut be = mk(b, pool, cot.delta());
            let pool_time = t.elapsed();
            ch.sync();
            let keys = [Block::random(&mut rng), Block::random(&mut rng)];
            let mut sk: Vec<SharedKey<bool>> = keys.iter().map(|&k| SharedKey::new(bits_of(k))).collect();
            let delta = Block::random(&mut rng).with_lsb(b == 1);
            let mut st = if b == 0 { delta } else { Block::ZERO };
            let before = ch.stats();
            let t = Instant::now();
            for _ in 0..n {
                let l = mmo_shared(&mut be, ch, &mut sk, &[(0, bits_of(st)), (0, bits_of(st ^ delta))]);
                st = block_of(&l[0]);
            }
            let w = mmo_shared(&mut be, ch, &mut sk, &[(1, bits_of(st)), (1, bits_of(st ^ delta))]);
            let online = t.elapsed();
            let stats = ch.stats().since(&before);
            let (ands, left) = be.counts();
            Party { keys, delta, out: [block_of(&w[0]), block_of(&w[1])], stats, online, pool_time, ands, left }
        }
    };
    let (p0, p1) = run_two_party(party(0), party(1));
    // Check against the cleartext walk.
    let k = [p0.keys[0] ^ p1.keys[0], p0.keys[1] ^ p1.keys[1]].map(|k| Mmo::new(k.to_bytes()));
    let delta = p0.delta ^ p1.delta;
    let mut st = p0.delta;
    for _ in 0..n {
        st = k[0].h(st);
    }
    assert_eq!(p0.out[0] ^ p1.out[0], k[1].h(st), "leaf word 0");
    assert_eq!(p0.out[1] ^ p1.out[1], k[1].h(st ^ delta), "leaf word 1");
    assert_eq!((p0.left, p1.left), (0, 0), "COT pool not used up exactly");
    Run {
        bytes: p0.stats.bytes_sent + p1.stats.bytes_sent,
        rounds: p0.stats.rounds.max(p1.stats.rounds),
        online: p0.online.max(p1.online),
        pool_time: p0.pool_time.max(p1.pool_time),
        pool: need,
        ands: p0.ands,
    }
}

trait Counted {
    fn counts(&self) -> (usize, usize);
}

impl Counted for OtTower {
    fn counts(&self) -> (usize, usize) {
        (self.ands, self.remaining())
    }
}

impl Counted for CotCircuit {
    fn counts(&self) -> (usize, usize) {
        (self.ands, self.remaining())
    }
}

fn median(mut v: Vec<Duration>) -> Duration {
    v.sort();
    v[v.len() / 2]
}

fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1e3
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let arg = |name: &str, def: usize| args.iter().position(|a| a == name).map_or(def, |i| args[i + 1].parse().unwrap());
    let n = arg("--n", 32);
    let reps = arg("--reps", 5);
    let mut rng = ChaCha20Rng::seed_from_u64(1);

    // The whole ht-aes Gen (sh-bin, ℓ = 64) on the OtTower, for the non-AES part.
    let (mut g, mut p) = (vec![], vec![]);
    let mut last = None;
    for _ in 0..reps {
        let seeds: [[u8; 32]; 2] = [rng.gen(), rng.gen()];
        let (b0, b1) = (Block::random(&mut rng), Block::random(&mut rng));
        let party = |b: usize, beta: Block| move |ch: &mut Channel| ht_aes::semi_honest::bin::gen(ch, 1u64 << n, 64, beta, seeds[b], Some(FerretConfig::B13));
        let (o0, o1) = run_two_party(party(0, b0), party(1, b1));
        g.push(o0.gen_time.max(o1.gen_time));
        p.push(o0.pre_time.max(o1.pre_time));
        last = Some((o0, o1));
    }
    let (o0, o1) = last.unwrap();
    let gen_bytes = o0.gen_stats.bytes_sent + o1.gen_stats.bytes_sent;
    let gen_rounds = o0.gen_stats.rounds.max(o1.gen_stats.rounds);
    let (gen_ms, pre_ms) = (ms(median(g)), ms(median(p)));
    let tower_pool = (2 * n + 2) * 160 * 18 + 2 * 40 * 18;
    // Party 0 counts the COTs of both directions; all but the tower's are symmetric.
    let rest_per_dir = (o0.cots - tower_pool) / 2;

    let s_t = Schedule::new(&tower());
    let s_b = Schedule::new(&boyar_peralta());
    println!("## Per S-box (OT tower protocol: 1 COT + 1 bit per corrected bit, 2 bits per AND)\n");
    println!("| circuit | ANDs | AND layers (ANDs, new COTs) | COTs | bits | rounds |");
    println!("|---|---|---|---|---|---|");
    for (name, s) in [("F4 tower (ours)", &s_t), ("Boyar–Peralta", &s_b)] {
        let per: Vec<String> = s.layers.iter().map(|l| format!("({}, {})", l.ands.len(), l.correct.len())).collect();
        println!("| {name} | {} | {} | {} | {} | {} |", s.ands(), per.join(" "), s.cots, s.bits(), s.layers.len());
    }

    println!("\n## AES part of one Gen, n = {n} ({} calls + 2 key expansions, Ferret B13, median of {reps})\n", 2 * n + 2);
    println!("| backend | ANDs | COTs | bytes | rounds | online ms | pool ms |");
    println!("|---|---|---|---|---|---|---|");
    let mut runs = Vec::new();
    for name in ["OtTower (ht-aes)", "CotCircuit: F4 tower", "CotCircuit: Boyar–Peralta"] {
        let mut on = vec![];
        let mut pt = vec![];
        let mut r = None;
        for _ in 0..reps {
            let seeds: [[u8; 32]; 2] = [rng.gen(), rng.gen()];
            let run = match name {
                "OtTower (ht-aes)" => aes_part(n, 18, OtTower::new, seeds),
                "CotCircuit: F4 tower" => aes_part(n, s_t.cots, |b, c, g| CotCircuit::new(tower(), b, c, g), seeds),
                _ => aes_part(n, s_b.cots, |b, c, g| CotCircuit::new(boyar_peralta(), b, c, g), seeds),
            };
            on.push(run.online);
            pt.push(run.pool_time);
            r = Some(run);
        }
        let r = r.unwrap();
        let (on, pt) = (median(on), median(pt));
        println!("| {name} | {} | {} | {} | {} | {:.1} | {:.1} |", r.ands, r.pool, r.bytes, r.rounds, ms(on), ms(pt));
        runs.push((name, r, on));
    }

    let yield_ = FerretConfig::B13.yield_per_iteration(false);
    // One Ferret main iteration: drain the buffer with `yield_` COTs, then the
    // next `yield_` take exactly one iteration.
    let fer = |b: usize| {
        move |ch: &mut Channel| {
            let mut rng = ChaCha20Rng::seed_from_u64(99 + b as u64);
            let gamma = Block::random(&mut rng);
            let mut cot = CotPair::setup(ch, &mut rng, gamma, false).unwrap();
            cot.enable_ferret(ch, FerretConfig::B13, &mut rng).unwrap();
            cot.random_cots(ch, 0, yield_, &mut rng).unwrap();
            ch.sync();
            let before = ch.stats();
            let t = Instant::now();
            cot.random_cots(ch, 0, yield_, &mut rng).unwrap();
            (ch.stats().since(&before), t.elapsed())
        }
    };
    let ((f0, ft0), (f1, ft1)) = run_two_party(fer(0), fer(1));
    let (fer_bytes, fer_ms) = (f0.bytes_sent + f1.bytes_sent, ms(ft0.max(ft1)));
    let base_aes = &runs[0].1;
    println!("\n## Whole Gen (sh-bin, ℓ = 64, n = {n}); Boyar–Peralta = measured Gen − AES(OtTower) + AES(Boyar–Peralta)\n");
    println!("Ferret B13 yields {yield_} COTs per main iteration and direction (direction 0 carries the OT tower); one iteration: {fer_bytes} B, {fer_ms:.0} ms.\n");
    println!("| S-box | Gen bytes | Gen rounds | LAN ms | WAN ms | Gen ms | dir-0 COTs per key | keys per Ferret iteration | Ferret B per key | Ferret ms per key |");
    println!("|---|---|---|---|---|---|---|---|---|---|");
    for (label, aes, on) in [("F4 tower (measured)", &runs[0].1, runs[0].2), ("Boyar–Peralta (est.)", &runs[2].1, runs[2].2)] {
        let bytes = gen_bytes - base_aes.bytes + aes.bytes;
        let gms = gen_ms - ms(runs[0].2) + ms(on);
        let cots = aes.pool + rest_per_dir;
        let lan = ms(LAN.net_time(gen_rounds, bytes)) + gms;
        let wan = ms(WAN.net_time(gen_rounds, bytes)) + gms;
        let share = cots as f64 / yield_ as f64;
        println!(
            "| {label} | {bytes} | {gen_rounds} | {lan:.0} | {wan:.0} | {gms:.1} | {cots} | {} | {:.0} | {:.1} |",
            yield_ / cots,
            share * fer_bytes as f64,
            share * fer_ms
        );
    }
    println!("\n(ht-aes Gen measured: {gen_bytes} B, {gen_rounds} rounds, gen {gen_ms:.1} ms, pre {pre_ms:.1} ms, {} COTs at party 0 over both directions.)", o0.cots);
}
