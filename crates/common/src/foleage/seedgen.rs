//! Dealer-free seed generation for FOLEAGE (§5), semi-honest.
//!
//! Every DPF `d = (i_A, i_B, j_A, j_B)` has its point at the trit-wise sum of
//! party 0's offset `p_0` (entry `(i_A, j_A)` of its noise) and party 1's
//! `p_1`, so trit k of the point is shared additively in Z_3 as
//! `(p_{0,k}, p_{1,k})`. Its value `β = v_0·v_1` is shared by one F4-OLE from
//! COTs. All `c²t²` DPFs then run the following in parallel:
//!
//! * Levels (Fig. 9 with ΠrDPF-CW of Fig. 7): each party expands every node of
//!   its tree on the current level and XORs the j-children into `S_j`. With
//!   `α_i = a + b`, `CW_i = S ⊕ place(R, α_i)`, `R = r_0 ⊕ r_1`, `lsb(R) = 1`:
//!   `place(r_σ, a + b)` is computed by one chosen 1-out-of-3 OT in which
//!   party σ sends `(place(r_σ, a_σ + j) ⊕ z_σ)_{j ∈ Z_3}` and the peer picks
//!   with its trit. `CW_i` is opened, the children are corrected. Two rounds
//!   per level (OT messages, opening).
//! * Output word (Fig. 11): `⟨e_slot·β⟩` over the `3^v` leaf lanes is built
//!   trit by trit, from the least significant one: step i places the current
//!   vector of length `3^{i−1}` into slot `α_i` of a vector three times longer,
//!   again with one 1-out-of-3 OT per direction (one round per step). Then
//!   `CW_out = ⟨e_slot·β⟩ ⊕ Σ_leaves Ext(leaf)` is opened.
//!
//! Chosen 1-out-of-3 OT from two COTs (the Naor–Pinkas 1-out-of-4 from two
//! 1-out-of-2 OTs, choice 3 unused): the receiver's choice `c = c_0 + 2c_1`
//! derandomises the two COTs, and message j is masked with
//! `H(K_0 ⊕ j_0Δ, tw_j) ⊕ H(K_1 ⊕ j_1Δ, tw_j)`. All derandomisation bits
//! (OLE, every level and output step) go in one round at the start.
//!
//! Rounds: coin toss for `a` (2), derandomisation (1), 2 per level, 1 per leaf
//! trit, 1 for `CW_out`; the OLE message rides with the first level.

use super::tdpf::{corrected_nodes, tri_prg, TdpfKey, LEAF_BLOCKS};
use super::{par_map, sample_noise, trit, Params, Seed, T};
use crate::block::{blocks_from_bytes, blocks_to_bytes, Block};
use crate::coin::coin_block;
use crate::f4::{self, Packed};
use crate::hash::FixedKeyHash;
use crate::net::Channel;
use crate::ot::CotPair;
use rand::{CryptoRng, Rng, RngCore};
use std::sync::OnceLock;

fn pad_hash() -> &'static FixedKeyHash {
    static H: OnceLock<FixedKeyHash> = OnceLock::new();
    H.get_or_init(|| FixedKeyHash::new(b"foleage/ot3-pads"))
}

/// Tweak for word `w` of message `j` of 1-out-of-3 OT number `g`.
#[inline]
fn tw(g: usize, j: usize, w: usize) -> u64 {
    ((g as u64) << 6) | (j as u64) << 3 | w as u64
}

/// `words` pad blocks of message `j`, from the two (sender-side) keys.
fn pad(k: [Block; 2], delta: Block, g: usize, j: usize, words: usize) -> Vec<Block> {
    let h = pad_hash();
    (0..words).map(|w| h.h(k[0] ^ delta.and_bit(j & 1 == 1), tw(g, j, w)) ^ h.h(k[1] ^ delta.and_bit(j & 2 == 2), tw(g, j, w))).collect()
}

/// The receiver's pad for its choice `c`, from its two MACs.
fn pad_recv(m: [Block; 2], g: usize, c: usize, words: usize) -> Vec<Block> {
    let h = pad_hash();
    (0..words).map(|w| h.h(m[0], tw(g, c, w)) ^ h.h(m[1], tw(g, c, w))).collect()
}

/// A vector of up to 256 F4 lanes in [`LEAF_BLOCKS`] blocks.
type Lanes = [Block; LEAF_BLOCKS];

fn lane_get(v: &Lanes, i: usize) -> u8 {
    v[i / 64].0.lane(i % 64)
}

fn lane_xor(v: &mut Lanes, i: usize, x: u8) {
    v[i / 64].0 = v[i / 64].0.xor_lane(i % 64, x);
}

/// `v` (length `len`) placed into slot `k` of a vector of length `3·len`.
fn place_vec(v: &Lanes, len: usize, k: usize) -> Lanes {
    let mut out = [Block::ZERO; LEAF_BLOCKS];
    for i in 0..len {
        lane_xor(&mut out, k * len + i, lane_get(v, i));
    }
    out
}

fn random_lanes<R: RngCore + CryptoRng>(len: usize, rng: &mut R) -> Lanes {
    let mut v = [Block::ZERO; LEAF_BLOCKS];
    for (w, b) in v.iter_mut().enumerate() {
        let used = (len.saturating_sub(64 * w)).min(64);
        if used > 0 {
            let r: u128 = rng.gen();
            b.0 = if used == 64 { r } else { r & ((1u128 << (2 * used)) - 1) };
        }
    }
    v
}

/// Bytes of a lane vector of length `len` on the wire.
fn lanes_bytes(len: usize) -> usize {
    (2 * len).div_ceil(8)
}

fn put_lanes(v: &Lanes, len: usize, out: &mut Vec<u8>) {
    out.extend_from_slice(&blocks_to_bytes(v)[..lanes_bytes(len)]);
}

fn get_lanes(b: &[u8]) -> Lanes {
    let mut buf = vec![0u8; 16 * LEAF_BLOCKS];
    buf[..b.len()].copy_from_slice(b);
    let v = blocks_from_bytes(&buf);
    std::array::from_fn(|i| v[i])
}

/// Runs this party's side of the seed generation. `cot` must be set up
/// (Ferret enabled for silent COTs); it consumes about
/// `2·c²t²·(depth + v) + 2·c²t²` COTs per direction.
pub fn seed_gen<R: RngCore + CryptoRng>(ch: &mut Channel, cot: &mut CotPair, params: Params, rng: &mut R) -> Seed {
    let p = &params;
    let me = ch.party();
    let a_seed = coin_block(ch, rng).expect("semi-honest coin toss");
    let noise = sample_noise(p, rng);
    let dpfs = p.dpfs();
    let (depth, v) = (p.depth(), p.leaf_trits);
    let bt = p.block_trits();
    let ots = depth + v; // per DPF and direction

    // This party's noise entry in DPF d.
    let entry = |d: usize| {
        let (ia, ib, ja, jb) = p.dpf_entries(d);
        if me == 0 { noise[ia * T + ja] } else { noise[ib * T + jb] }
    };
    // This party's trit for OT l of DPF d: tree level l + 1 takes trit
    // bt − 1 − l (top first); leaf step l − depth + 1 takes trit l − depth.
    let my_trit = |d: usize, l: usize| {
        let off = entry(d).offset;
        if l < depth { trit(off, bt - 1 - l) } else { trit(off, l - depth) }
    };

    // Derandomise all COTs at once: OLE choice bits (party 0 only), then two
    // bits per 1-out-of-3 OT.
    let ole_bits = 2 * dpfs;
    let mut mine: Vec<bool> = Vec::with_capacity(ole_bits + 2 * dpfs * ots);
    if me == 0 {
        for d in 0..dpfs {
            let x = entry(d).value;
            mine.extend([x & 2 == 2, x & 1 == 1]);
        }
    }
    for d in 0..dpfs {
        for l in 0..ots {
            let c = my_trit(d, l);
            mine.extend([c & 1 == 1, c & 2 == 2]);
        }
    }
    let theirs = 2 * dpfs * ots + if me == 1 { ole_bits } else { 0 };
    let (k, m) = cot.extend(ch, &mine, theirs, rng).expect("semi-honest COT");
    let delta = cot.delta();
    let (ks, ms) = (if me == 1 { &k[ole_bits..] } else { &k[..] }, if me == 0 { &m[ole_bits..] } else { &m[..] });
    let skey = |g: usize| [ks[2 * g], ks[2 * g + 1]];
    let rmac = |g: usize| [ms[2 * g], ms[2 * g + 1]];

    // β = v_0·v_1: party 0 chooses with the bits (h, l) of v_0, party 1 sends
    // H(K) ⊕ H(K ⊕ Δ) ⊕ (ω·v_1 or v_1) per bit. Shares in `beta`.
    let h2 = |x: Block, i: usize| pad_hash().h(x, (1 << 62) | i as u64).0 as u8 & 3;
    let mut beta = vec![0u8; dpfs];
    if me == 1 {
        let mut msg = Vec::with_capacity(dpfs);
        for d in 0..dpfs {
            let vb = entry(d).value;
            let mut byte = 0u8;
            for (bit, val) in [f4::mul(f4::OMEGA, vb), vb].into_iter().enumerate() {
                let kk = k[2 * d + bit];
                let (x0, x1) = (h2(kk, 2 * d + bit), h2(kk ^ delta, 2 * d + bit));
                beta[d] ^= x0;
                byte |= (x0 ^ x1 ^ val) << (2 * bit);
            }
            msg.push(byte);
        }
        ch.send(msg);
    }

    // The trees are not kept: level l of DPF d is recomputed from its root and
    // the CWs so far (about 1.5× the PRG calls, memory per DPF and thread).
    let prg = tri_prg();
    let roots: Vec<Block> = (0..dpfs).map(|_| Block::random(rng).with_lsb(me == 1)).collect();
    let mut cws: Vec<Vec<[Block; 3]>> = vec![Vec::with_capacity(depth); dpfs];
    for l in 0..depth {
        // S_j: the j-children of all nodes on level l, uncorrected.
        let sums = par_map(dpfs, |d| {
            let mut kids = Vec::new();
            prg.expand(&corrected_nodes(roots[d], &cws[d]), &mut kids);
            let mut s = [Block::ZERO; 3];
            for (i, &kid) in kids.iter().enumerate() {
                s[i % 3] ^= kid;
            }
            s
        });
        // z, and the OT messages for the peer's trit.
        let mut zs = Vec::with_capacity(dpfs);
        let mut msg = Vec::with_capacity(dpfs * 9);
        for d in 0..dpfs {
            let r = Block::random(rng).with_lsb(me == 0);
            let z: [Block; 3] = std::array::from_fn(|_| Block::random(rng));
            let a = my_trit(d, l);
            let g = d * ots + l;
            for j in 0..3 {
                let pd = pad(skey(g), delta, g, j, 3);
                for (w, &zw) in z.iter().enumerate() {
                    let placed = if w == (a + j) % 3 { r } else { Block::ZERO };
                    msg.push(zw ^ placed ^ pd[w]);
                }
            }
            zs.push(z);
        }
        ch.send_blocks(&msg);
        if l == 0 && me == 0 {
            // The OLE message, sent together with party 1's first OT messages.
            let got = ch.recv();
            assert_eq!(got.len(), dpfs, "malformed OLE message");
            for (d, &byte) in got.iter().enumerate() {
                let x = entry(d).value;
                for (bit, c) in [x & 2 == 2, x & 1 == 1].into_iter().enumerate() {
                    let u = byte >> (2 * bit) & 3;
                    beta[d] ^= h2(m[2 * d + bit], 2 * d + bit) ^ if c { u } else { 0 };
                }
            }
        }
        let got = ch.recv_blocks(dpfs * 9);
        let mut share = Vec::with_capacity(3 * dpfs);
        for d in 0..dpfs {
            let g = d * ots + l;
            let c = my_trit(d, l);
            let pr = pad_recv(rmac(g), g, c, 3);
            for w in 0..3 {
                share.push(sums[d][w] ^ zs[d][w] ^ got[9 * d + 3 * c + w] ^ pr[w]);
            }
        }
        ch.send_blocks(&share);
        let peer = ch.recv_blocks(3 * dpfs);
        for d in 0..dpfs {
            cws[d].push(std::array::from_fn(|w| share[3 * d + w] ^ peer[3 * d + w]));
        }
    }

    // Output word: ⟨e_slot·β⟩, one leaf trit per round.
    let mut vecs: Vec<Lanes> = beta.iter().map(|&b| {
        let mut x = [Block::ZERO; LEAF_BLOCKS];
        lane_xor(&mut x, 0, b);
        x
    }).collect();
    for step in 0..v {
        let len = 3usize.pow(step as u32);
        let nb = lanes_bytes(3 * len);
        let words = (3 * len).div_ceil(64);
        let mut zs = Vec::with_capacity(dpfs);
        let mut msg = Vec::with_capacity(dpfs * 3 * nb);
        for d in 0..dpfs {
            let l = depth + step;
            let g = d * ots + l;
            let a = my_trit(d, l);
            let z = random_lanes(3 * len, rng);
            for j in 0..3 {
                let pd = pad(skey(g), delta, g, j, words);
                let mut m = place_vec(&vecs[d], len, (a + j) % 3);
                for w in 0..LEAF_BLOCKS {
                    m[w] ^= z[w] ^ pd.get(w).copied().unwrap_or_default();
                }
                put_lanes(&m, 3 * len, &mut msg);
            }
            zs.push(z);
        }
        ch.send(msg);
        let got = ch.recv();
        assert_eq!(got.len(), dpfs * 3 * nb, "malformed output-word OT message");
        for d in 0..dpfs {
            let l = depth + step;
            let g = d * ots + l;
            let c = my_trit(d, l);
            let pr = pad_recv(rmac(g), g, c, words);
            let mut r = get_lanes(&got[(3 * d + c) * nb..(3 * d + c + 1) * nb]);
            for w in 0..LEAF_BLOCKS {
                r[w] ^= pr.get(w).copied().unwrap_or_default() ^ zs[d][w];
            }
            // Keep only the 3·len lanes (the pads cover whole blocks).
            let mut clean = [Block::ZERO; LEAF_BLOCKS];
            for i in 0..3 * len {
                lane_xor(&mut clean, i, lane_get(&r, i));
            }
            vecs[d] = clean;
        }
    }
    let ext = par_map(dpfs, |d| {
        let mut ext = Vec::new();
        prg.extend(&corrected_nodes(roots[d], &cws[d]), &mut ext);
        let mut acc = [Block::ZERO; LEAF_BLOCKS];
        for (i, &e) in ext.iter().enumerate() {
            acc[i % LEAF_BLOCKS] ^= e;
        }
        acc
    });
    let mut share = Vec::with_capacity(dpfs * LEAF_BLOCKS);
    for d in 0..dpfs {
        for w in 0..LEAF_BLOCKS {
            share.push(vecs[d][w] ^ ext[d][w]);
        }
    }
    ch.send_blocks(&share);
    let peer = ch.recv_blocks(dpfs * LEAF_BLOCKS);
    let keys = (0..dpfs)
        .map(|d| TdpfKey {
            root: roots[d],
            cws: std::mem::take(&mut cws[d]),
            cw_out: std::array::from_fn(|w| share[LEAF_BLOCKS * d + w] ^ peer[LEAF_BLOCKS * d + w]),
        })
        .collect();
    Seed { party: me, params, a_seed, noise, keys }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::foleage::tests::check_oles;
    use crate::foleage::tdpf::leaf_len;
    use crate::foleage::{trit_add, triples};
    use crate::net::run_two_party;
    use crate::ot::FerretConfig;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    fn run(log3: usize, ferret: bool) -> ([Seed; 2], [crate::net::CommStats; 2]) {
        run_c(Params::new(log3), ferret)
    }

    fn run_c(p: Params, ferret: bool) -> ([Seed; 2], [crate::net::CommStats; 2]) {
        let party = |seed: u64| {
            move |ch: &mut Channel| {
                let mut rng = ChaCha20Rng::seed_from_u64(seed);
                let d = Block::random(&mut rng);
                let mut cot = CotPair::setup(ch, &mut rng, d, false).unwrap();
                if ferret {
                    cot.enable_ferret(ch, FerretConfig::TOY, &mut rng).unwrap();
                }
                let before = ch.stats();
                let s = seed_gen(ch, &mut cot, p, &mut rng);
                (s, ch.stats().since(&before))
            }
        };
        let ((s0, c0), (s1, c1)) = run_two_party(party(1), party(2));
        ([s0, s1], [c0, c1])
    }

    #[test]
    fn distributed_seeds_are_dpfs_of_the_cross_terms() {
        let (s, stats) = run(7, false);
        let p = s[0].params;
        assert_eq!(s[0].a_seed, s[1].a_seed);
        let leaf = leaf_len(p.leaf_trits);
        // Every DPF is the point function of its cross term.
        for d in [0, 1, 500, p.dpfs() - 1] {
            let (ia, ib, ja, jb) = p.dpf_entries(d);
            let (ea, eb) = (s[0].noise[ia * T + ja], s[1].noise[ib * T + jb]);
            let off = trit_add(ea.offset, eb.offset, p.block_trits());
            let (y0, y1) = (s[0].keys[d].full_eval(), s[1].keys[d].full_eval());
            for l in 0..3usize.pow(p.depth() as u32) {
                let want = if l == off / leaf { super::super::tdpf::unit_leaf(off % leaf, f4::mul(ea.value, eb.value)) } else { [Block::ZERO; LEAF_BLOCKS] };
                for w in 0..LEAF_BLOCKS {
                    assert_eq!(y0[LEAF_BLOCKS * l + w] ^ y1[LEAF_BLOCKS * l + w], want[w], "DPF {d} leaf {l}");
                }
            }
        }
        let o = check_oles(&s);
        let t = [triples(&o[0], 0, 500), triples(&o[1], 1, 500)];
        for (x, y) in t[0].iter().zip(&t[1]) {
            assert_eq!(x.2 ^ y.2, f4::mul(x.0 ^ y.0, x.1 ^ y.1));
        }
        // 2 (coin) + 1 (derandomisation) + 2 per level + 1 per leaf trit + 1.
        assert_eq!(stats[0].rounds.max(stats[1].rounds), 2 + 1 + 2 * p.depth() + p.leaf_trits + 1);
    }

    #[test]
    fn seed_gen_with_c_5_and_6() {
        for c in [5, 6] {
            let (s, _) = run_c(Params::with_c(6, c), false);
            assert_eq!(s[0].keys.len(), c * c * T * T);
            check_oles(&s);
        }
    }

    #[test]
    fn seed_gen_on_ferret() {
        let (s, _) = run(6, true);
        check_oles(&s);
    }
}
