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

    /// Hashes two inputs under consecutive tweaks in one 2-block AES call.
    #[inline]
    pub fn h2(&self, a: Block, ta: u64, b: Block, tb: u64) -> (Block, Block) {
        let sa = sigma(a);
        let sb = sigma(b);
        let mut buf = [
            GenericArray::from((sa ^ Block(ta as u128)).to_bytes()),
            GenericArray::from((sb ^ Block(tb as u128)).to_bytes()),
        ];
        self.aes.encrypt_blocks(&mut buf);
        (Block::from_bytes(buf[0].as_slice()) ^ sa, Block::from_bytes(buf[1].as_slice()) ^ sb)
    }
}

/// Hash used by the garbled circuit. Domain-separated from the OT hash by its key.
pub fn gc_hash() -> &'static FixedKeyHash {
    static H: OnceLock<FixedKeyHash> = OnceLock::new();
    H.get_or_init(|| FixedKeyHash::new(b"dpf-common/gc-h!"))
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
