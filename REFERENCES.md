# References

Papers and techniques this code implements, with the place where each is used.

## The four DPF protocols

| Key | Reference | Implemented in |
|---|---|---|
| Floram | J. Doerner, a. shelat. *Scaling ORAM for Secure Computation.* ACM CCS 2017. | `protocols/floram-cprg` |
| Half-Tree | X. Guo, K. Yang, X. Wang, W. Zhang, X. Xie, J. Zhang, Z. Liu. *Half-Tree: Halving the Cost of Tree Expansion in COT and DPF.* EUROCRYPT 2023. | `protocols/half-tree` (`semi_honest`, `tree`), `dpf_common::hash::CcrHash` |
| ZGY+24 | W. Zhang, X. Guo, K. Yang, R. Zhu, Y. Yu, X. Wang. *Efficient Actively Secure DPF and RAM-based 2PC with One-Bit Leakage.* IEEE S&P 2024. | `protocols/half-tree` (`malicious`), `dpf_common::mac::binary` |
| XLH+25 | P. Xing, H. Li, M. Hao, H. Chen, J. Hu, D. Liu. *Distributed Function Secret Sharing and Applications.* NDSS 2025. | `protocols/floram-arith` (A2B, CCMP, arithmetic final CW) |

## Building blocks

| Key | Reference | Used for |
|---|---|---|
| GGM86 | O. Goldreich, S. Goldwasser, S. Micali. *How to Construct Random Functions.* J. ACM 1986. | GGM trees: Floram tree, Ferret single-point COT |
| BGI16 | E. Boyle, N. Gilboa, Y. Ishai. *Function Secret Sharing: Improvements and Extensions.* ACM CCS 2016. | DPF key format (σ/τ CWs) and arithmetic output word, `floram-arith::key` |
| GKWY20 | C. Guo, J. Katz, X. Wang, Y. Yu. *Efficient and Secure Multiparty Computation from Fixed-Key Block Ciphers.* IEEE S&P 2020. | σ orthomorphism, fixed-key-AES (C)CR hashes (`dpf_common::hash`) |
| NP01 | M. Naor, B. Pinkas. *Efficient Oblivious Transfer Protocols.* SODA 2001. | semi-honest base OT (`ot::np`) |
| MR19 | D. Masny, P. Rindal. *Endemic Oblivious Transfer.* ACM CCS 2019. | malicious base OT (`ot::endemic`) |
| RFC 9380 | A. Faz-Hernández et al. *Hashing to Elliptic Curves.* IETF RFC 9380, 2023. | hash-to-curve in `ot::endemic` |
| IKNP03 | Y. Ishai, J. Kilian, K. Nissim, E. Petrank. *Extending Oblivious Transfers Efficiently.* CRYPTO 2003. | OT/COT extension (`ot::iknp`, `ot::cot`) |
| KOS15 | M. Keller, E. Orsini, P. Scholl. *Actively Secure OT Extension with Optimal Overhead.* CRYPTO 2015. | consistency check of the malicious COT (`ot::cot`) |
| Ferret | K. Yang, C. Weng, X. Lan, J. Zhang, X. Wang. *Ferret: Fast Extension for Correlated OT with Small Communication.* ACM CCS 2020. | LPN-based COT extension (`ot::ferret`) |
| EMP | X. Wang, A. J. Malozemoff, J. Katz. *EMP-toolkit.* github.com/emp-toolkit, 2016. | Ferret parameter set `FerretConfig::B13` (from emp-ot) |
| Yao86 | A. C. Yao. *How to Generate and Exchange Secrets.* FOCS 1986. | garbled circuits (`gc`) |
| KS08 | V. Kolesnikov, T. Schneider. *Improved Garbled Circuit: Free XOR Gates and Applications.* ICALP 2008. | free-XOR in `gc` |
| ZRE15 | S. Zahur, M. Rosulek, D. Evans. *Two Halves Make a Whole.* EUROCRYPT 2015. | half-gates AND in `gc` |
| Gil99 | N. Gilboa. *Two Party RSA Key Generation.* CRYPTO 1999. | OT-based multiplication / VOLE (`mac::ring`, `arith::mux`) |
| SIRNN | D. Rathee, M. Rathee, R. K. K. Goli, D. Gupta, R. Sharma, N. Chandran, A. Rastogi. *SiRnn: A Math Library for Secure RNN Inference.* IEEE S&P 2021. | OT-based arithmetic MUX (`arith::mux`), as used by XLH+25 |
| BDOZ11 | R. Bendlin, I. Damgård, C. Orlandi, S. Zakarias. *Semi-Homomorphic Encryption and Multiparty Computation.* EUROCRYPT 2011. | BDOZ-authenticated bits (`mac::binary::AuthBit`) |
| NNOB12 | J. B. Nielsen, P. S. Nordholt, C. Orlandi, S. S. Burra. *A New Approach to Practical Active-Secure Two-Party Computation.* CRYPTO 2012. | COT as IT-MAC (F_aBit) |
| DPSZ12 | I. Damgård, V. Pastro, N. P. Smart, S. Zakarias. *Multiparty Computation from Somewhat Homomorphic Encryption.* CRYPTO 2012. | SPDZ MACs (`mac::binary::AuthGf`, `mac::fp`) |
| DKL+13 | I. Damgård, M. Keller, E. Larraia, V. Pastro, P. Scholl, N. P. Smart. *Practical Covertly Secure MPC for Dishonest Majority.* ESORICS 2013. | batch MAC check (`MacParty::check`, `ArithMacParty::check`) |
| BLN+21 | S. S. Burra, E. Larraia, J. B. Nielsen, P. S. Nordholt, C. Orlandi, E. Orsini, P. Scholl, N. P. Smart. *High-Performance Multi-Party Computation for Binary Circuits Based on Oblivious Transfer.* J. Cryptology 2021. | local BDOZ→SPDZ conversion (`AuthBit::to_gf`) |
| CWYY23 | H. Cui, X. Wang, K. Yang, Y. Yu. *Actively Secure Half-Gates with Minimum Overhead under Duplex Networks.* EUROCRYPT 2023. | `lsb(Δ_0 ⊕ Δ_1) = 1` check (`MacParty::setup`) |
| SPDZ2k | R. Cramer, I. Damgård, D. Escudero, P. Scholl, C. Xing. *SPDZ2k: Efficient MPC mod 2^k for Dishonest Majority.* CRYPTO 2018. | `mac::z2k`, masked MAC check |
| MASCOT | M. Keller, E. Orsini, P. Scholl. *MASCOT: Faster Malicious Arithmetic Secure Computation with Oblivious Transfer.* ACM CCS 2016. | consistency check of the OT-based authentication (`mac::ring`) |
