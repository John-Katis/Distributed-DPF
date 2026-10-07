//! Oblivious transfer: Naor–Pinkas base OTs, semi-honest IKNP as in Obliv-C,
//! and 128-bit correlated OT (optionally KOS-checked) for the Half-Tree
//! protocols and the MAC library.

pub mod cot;
pub mod iknp;
pub mod np;

pub use cot::{CotPair, CotReceiver, CotSender, COT_KEY_BITS, KOS_EXTRA};
pub use iknp::{IknpReceiver, IknpSender, OT_KEY_BITS};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::Block;
    use crate::net::run_two_party;
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn base_ot() {
        let choices: Vec<bool> = (0..37).map(|i| i % 3 == 0).collect();
        let ch2 = choices.clone();
        let (pairs, got) = run_two_party(
            |c| np::send_random(c, 37, &mut ChaCha20Rng::seed_from_u64(1)),
            move |c| np::recv_random(c, &ch2, &mut ChaCha20Rng::seed_from_u64(2)),
        );
        for i in 0..37 {
            let (k0, k1) = pairs[i];
            assert_ne!(k0, k1);
            assert_eq!(got[i], if choices[i] { k1 } else { k0 });
        }
    }

    #[test]
    fn iknp_batches() {
        let mut rng = ChaCha20Rng::seed_from_u64(3);
        let sizes = [1usize, 5, 128, 129, 300];
        let msgs: Vec<Vec<(Block, Block)>> = sizes
            .iter()
            .map(|&m| (0..m).map(|_| (Block::random(&mut rng), Block::random(&mut rng))).collect())
            .collect();
        let choices: Vec<Vec<bool>> = sizes.iter().map(|&m| (0..m).map(|_| rng.gen()).collect()).collect();
        let (m2, c2) = (msgs.clone(), choices.clone());
        let (_, got) = run_two_party(
            move |c| {
                let mut r = ChaCha20Rng::seed_from_u64(4);
                let mut s = IknpSender::setup(c, &mut r);
                for batch in &m2 {
                    s.send(c, batch);
                }
            },
            move |c| {
                let mut r = ChaCha20Rng::seed_from_u64(5);
                let mut rcv = IknpReceiver::setup(c, &mut r);
                c2.iter().map(|ch| rcv.recv(c, ch)).collect::<Vec<_>>()
            },
        );
        for b in 0..sizes.len() {
            for j in 0..sizes[b] {
                let (x0, x1) = msgs[b][j];
                assert_eq!(got[b][j], if choices[b][j] { x1 } else { x0 });
            }
        }
    }
}
