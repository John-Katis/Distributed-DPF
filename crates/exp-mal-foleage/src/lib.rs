//! **Experimental**: maliciously secure F4 Beaver triples from FOLEAGE.
//!
//! The semi-honest FOLEAGE PCG ([`dpf_common::foleage`]) gives XOR shares of
//! `(a, b, c = ab)`. Malicious 2PC on top of it (the authenticated AES tower of
//! [`dpf_common::mac::af4`]) needs every bit of every triple under a SPDZ MAC
//! `Δ = Δ_0 ⊕ Δ_1 ∈ GF(2^128)`. Two ways to get there, both on one triple PCG
//! ([`pcg`]):
//!
//! * **(a) all MACs from the PCG** ([`pcg::Mode::Full`]): the MACs of a and b
//!   are a subfield VOLE on each party's own sparse noise (`4ct` extra
//!   GF-valued DPFs); the MAC of c needs one GF-valued DPF per nonzero term of
//!   `(e_0 + e_1)(f_0 + f_1)` (`4c²t²`), with payload `ι(v_e v_f)·Δ`. No
//!   interaction after the seeds; MACs and values agree by construction.
//! * **(b) linear MACs + sacrifice** ([`pcg::Mode::Linear`] +
//!   [`sacrifice`]): only a and b get MACs from the PCG; c is authenticated by
//!   derandomising aBits (an error there is chosen without honest
//!   information) and then checked by SPDZ sacrifice with bucketing.
//!
//! Bit MACs need MACs on `v` and `v²` (the AES layers are only F2-linear);
//! both come from two lanes `ι(v)Δ`, `ι(v)Γ` with `Γ = √Δ` ([`gf`]).
//!
//! The seeds are **dealt** ([`pcg::deal`]); a maliciously secure distributed
//! seed generation is the open problem, see `README.md`.

pub mod gf;
pub mod pcg;
pub mod sacrifice;
pub mod wide;
