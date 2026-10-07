//! Fixed-key AES hashes for garbling and OT-extension padding, plus an AES-CTR
//! stream for expanding OT seeds.

// `aes` 0.8 re-exports generic-array 0.14, whose newest patch release marks it deprecated.
#![allow(deprecated)]

use crate::block::Block;
use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockEncrypt, KeyInit};
use aes::Aes128;
use std::sync::OnceLock;

/// σ(x_L ∥ x_R) = (x_L ⊕ x_R) ∥ x_L, the linear orthomorphism of GKWY20. This is
/// `half_tree_sigma` from the half-tree IDPF code: low 64 bits are x_L, high are x_R.
#[inline]
pub fn sigma(x: Block) -> Block {
    let lo = x.0 as u64;
    let hi = (x.0 >> 64) as u64;
    Block(((lo as u128) << 64) | ((lo ^ hi) as u128))
}

/// A fixed-key AES permutation π, used as a tweakable hash.
pub struct FixedKeyHash {
    aes: Aes128,
}

impl FixedKeyHash {
    pub fn new(key: &[u8; 16]) -> Self {
        FixedKeyHash { aes: Aes128::new(GenericArray::from_slice(key)) }
    }

    #[inline]
    fn pi(&self, x: Block) -> Block {
        let mut g = GenericArray::from(x.to_bytes());
        self.aes.encrypt_block(&mut g);
        Block::from_bytes(g.as_slice())
    }

    /// Tweakable hash for half-gates: H(X, i) = π(σ(X) ⊕ i) ⊕ σ(X).
    #[inline]
    pub fn h(&self, x: Block, tweak: u64) -> Block {
        let s = sigma(x);
        self.pi(s ^ Block(tweak as u128)) ^ s
    }

    /// `dst[i] = h(src[i], tweak)`, batched.
    pub fn h_many(&self, src: &[Block], tweak: u64, dst: &mut [Block]) {
        assert_eq!(src.len(), dst.len());
        let mut buf = [GenericArray::default(); BATCH];
        let mut sig = [Block::ZERO; BATCH];
        for (s, d) in src.chunks(BATCH).zip(dst.chunks_mut(BATCH)) {
            let k = s.len();
            for i in 0..k {
                sig[i] = sigma(s[i]);
                buf[i] = GenericArray::from((sig[i] ^ Block(tweak as u128)).to_bytes());
            }
            self.aes.encrypt_blocks(&mut buf[..k]);
            for i in 0..k {
                d[i] = Block::from_bytes(buf[i].as_slice()) ^ sig[i];
            }
        }
    }
}

/// Hash used to pad IKNP OT-extension messages.
pub fn ot_hash() -> &'static FixedKeyHash {
    static H: OnceLock<FixedKeyHash> = OnceLock::new();
    H.get_or_init(|| FixedKeyHash::new(b"dpf-common/ot-h!"))
}

/// AES-128 in counter mode, keyed by a seed. It keeps its position across calls,
/// like Obliv-C's `BCipherRandomGen`, so OT-extension columns never repeat.
pub struct CtrPrg {
    aes: Aes128,
    ctr: u128,
}

impl CtrPrg {
    pub fn new(seed: Block) -> Self {
        CtrPrg { aes: Aes128::new(GenericArray::from_slice(&seed.to_bytes())), ctr: 0 }
    }

    /// The next `n` 128-bit words of the stream.
    pub fn next_words(&mut self, n: usize) -> Vec<u128> {
        let mut buf: Vec<_> = (0..n)
            .map(|i| GenericArray::from((self.ctr + i as u128).to_le_bytes()))
            .collect();
        self.ctr += n as u128;
        self.aes.encrypt_blocks(&mut buf);
        buf.iter().map(|g| u128::from_le_bytes(g.as_slice().try_into().unwrap())).collect()
    }
}

/// Blocks per batched AES call, as in `prg.rs`.
const BATCH: usize = 64;

/// Fixed AES key of the Half-Tree CCR hash. It equals `HT_EXPAND_AES_KEY` of the
/// Verifiable-Half-Tree-IDPF code, so both implementations compute the same `H`.
pub const CCR_AES_KEY: [u8; 16] = *b"HT-IDPF-HALFTREE";

/// The circular-correlation-robust hash of Half-Tree (GKWY20 / GYW+23 Thm. 2),
/// keyed by a public `S`:
///
/// ```text
/// H_S(x) = π(σ(x ⊕ S)) ⊕ σ(x ⊕ S)
/// ```
///
/// with π fixed-key AES and σ the orthomorphism [`sigma`]. One AES call per hash.
#[derive(Clone)]
pub struct CcrHash {
    aes: Aes128,
    s: Block,
}

impl CcrHash {
    pub fn new(s: Block) -> Self {
        CcrHash { aes: Aes128::new(GenericArray::from_slice(&CCR_AES_KEY)), s }
    }

    /// The public hash key `S`.
    pub fn key(&self) -> Block {
        self.s
    }

    #[inline]
    pub fn h(&self, x: Block) -> Block {
        let s = sigma(x ^ self.s);
        let mut g = GenericArray::from(s.to_bytes());
        self.aes.encrypt_block(&mut g);
        Block::from_bytes(g.as_slice()) ^ s
    }

    /// `dst[i] = H_S(src[i] ⊕ tweak)`, batched.
    pub fn h_many_tweak(&self, src: &[Block], tweak: Block, dst: &mut [Block]) {
        assert_eq!(src.len(), dst.len());
        let mut buf = [GenericArray::default(); BATCH];
        let mut sig = [Block::ZERO; BATCH];
        for (s, d) in src.chunks(BATCH).zip(dst.chunks_mut(BATCH)) {
            let k = s.len();
            for i in 0..k {
                sig[i] = sigma(s[i] ^ tweak ^ self.s);
                buf[i] = GenericArray::from(sig[i].to_bytes());
            }
            self.aes.encrypt_blocks(&mut buf[..k]);
            for i in 0..k {
                d[i] = Block::from_bytes(buf[i].as_slice()) ^ sig[i];
            }
        }
    }

    /// `dst[i] = H_S(src[i])`, batched.
    pub fn h_many(&self, src: &[Block], dst: &mut [Block]) {
        self.h_many_tweak(src, Block::ZERO, dst);
    }

    /// `(H_S(a ⊕ ta), H_S(b ⊕ tb))` in one 2-block AES call. With a random
    /// public S this is the half-gates hash `H'_S(x, j) = H(S ⊕ x ⊕ j)` of
    /// GKWY20 Thm. 3 (H = MMO^σ).
    #[inline]
    pub fn h2_tweak(&self, a: Block, ta: u64, b: Block, tb: u64) -> (Block, Block) {
        let sa = sigma(a ^ Block(ta as u128) ^ self.s);
        let sb = sigma(b ^ Block(tb as u128) ^ self.s);
        let mut buf = [GenericArray::from(sa.to_bytes()), GenericArray::from(sb.to_bytes())];
        self.aes.encrypt_blocks(&mut buf);
        (Block::from_bytes(buf[0].as_slice()) ^ sa, Block::from_bytes(buf[1].as_slice()) ^ sb)
    }
}

/// The tweakable circular-correlation-robust hash of GKWY20 §7.4,
///
/// ```text
/// TMMO_π(x, i) = π(π(x) ⊕ i) ⊕ π(x)
/// ```
///
/// with π fixed-key AES (two calls per hash). Ferret's SPCOT needs a tweakable
/// CR hash to turn correlated OTs into chosen-message OTs (YWL+20 Fig. 6).
pub struct TmmoHash {
    aes: Aes128,
}

impl TmmoHash {
    pub fn new(key: &[u8; 16]) -> Self {
        TmmoHash { aes: Aes128::new(GenericArray::from_slice(key)) }
    }

    #[inline]
    fn pi(&self, x: Block) -> Block {
        let mut g = GenericArray::from(x.to_bytes());
        self.aes.encrypt_block(&mut g);
        Block::from_bytes(g.as_slice())
    }

    #[inline]
    pub fn h(&self, x: Block, tweak: u128) -> Block {
        let p = self.pi(x);
        self.pi(p ^ Block(tweak)) ^ p
    }
}

/// TMMO instance for Ferret's SPCOT masks.
pub fn tccr_hash() -> &'static TmmoHash {
    static H: OnceLock<TmmoHash> = OnceLock::new();
    H.get_or_init(|| TmmoHash::new(b"dpf-common/tccr!"))
}

/// Hash that turns a (pseudo)random leaf seed into payload words (the
/// `Convert` of Half-Tree and BCG+21). Domain-separated from every other hash by
/// its key. Word `k` of the expansion of `s` is `h(s, k)`.
pub fn convert_hash() -> &'static FixedKeyHash {
    static H: OnceLock<FixedKeyHash> = OnceLock::new();
    H.get_or_init(|| FixedKeyHash::new(b"dpf-common/conv!"))
}

/// Hash used to derive random OTs from correlated OTs (`H(K)`, `H(K ⊕ Δ)`).
pub fn cot_hash() -> &'static FixedKeyHash {
    static H: OnceLock<FixedKeyHash> = OnceLock::new();
    H.get_or_init(|| FixedKeyHash::new(b"dpf-common/cot-h"))
}
