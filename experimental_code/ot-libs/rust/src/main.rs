//! Our OTs against mpz and swanky, one CSV row per phase (see count.rs).
//!
//! ```text
//! cargo run --release -- [n_ext = 2^23] [n_ferret = 20,000,000] [n_1ofN = 2^20]
//! ```

mod count;
mod mpz;
mod ours;
mod swanky;

fn main() {
    let a: Vec<usize> = std::env::args().skip(1).map(|s| s.parse().unwrap()).collect();
    let n_ext = a.first().copied().unwrap_or(1 << 23);
    let n_fer = a.get(1).copied().unwrap_or(20_000_000);
    let n_nco = a.get(2).copied().unwrap_or(1 << 20);

    ours::base(false);
    ours::base(true);
    ours::cot(false, n_ext);
    ours::cot(true, n_ext);
    ours::ot(n_ext);
    ours::ferret(false, n_fer);
    ours::ferret(true, n_fer);
    ours::kk13(n_nco, 8, 2);
    ours::kk13(n_nco, 8, 8);

    mpz::base_co();
    mpz::kos(n_ext);
    mpz::ferret_both(n_fer);

    swanky::base_all();
    swanky::ext_all(n_ext);
}
