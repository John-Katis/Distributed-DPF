//! `Π_Verify` of the malicious variants, with both of its openings masked.
//!
//! For a batch of authenticated outputs `(⟦y_i⟧, ⟦m_i⟧)` over the MAC field E,
//! which stay shared, and (arithmetic payload) the keys' glue residuals `⟦ω_j⟧`
//! over `𝔽' = F_{2^127−1}`: toss public coins `χ_i ∈ E`, `χ'_j ∈ 𝔽'`, open `z =
//! Σ χ_i y_i + ρ`, and let `μ_b = Σ χ_i m_{i,b} + (m_ρ)_b − δ_b·z` and `μ'_b = Σ
//! χ'_j ω_{j,b}`.
//!
//! **The openings are masked.** Opening μ and μ′ themselves would leak on abort.
//! A server that adds a known e to its share of `W^MAC_CW` makes `μ = ±χ_α·e`,
//! and the public coins then give α; a server that adds d to one factor of
//! `𝓕_Mul(v', v')` makes `μ' = ∓χ'·d·v'`, an on-path state. So the servers open
//! `r·μ` and `r'·μ'` for fresh shared r, r′: one triple per field per Π_Verify,
//! `(r, v, rv)`, used as `r·μ = rv + r·(μ − v)` with `μ − v` opened. Each
//! opening then is 0 if the value is 0 and uniform otherwise, so an abort shows
//! only that the check failed. The shares of `(r·μ, r'·μ')` are committed
//! before they are opened.
//!
//! Rounds: two for the coins, one for z, one for `μ − v`, two for the commitment.

use crate::field::{Ext, Field, M127};
use crate::leaf::Triple;
use dpf_common::block::Block;
use dpf_common::coin::{coin_block, commit_and_open, Abort};
use dpf_common::hash::CtrPrg;
use dpf_common::net::Channel;
use rand::{CryptoRng, RngCore};

/// This party's shares of one Π_Verify's preprocessing: the mask `(ρ, δ·ρ)` and
/// the triple `(r, v, rv)` that masks μ.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifyMask<E> {
    pub r: E,
    pub dr: E,
    pub blind: Triple<E>,
}

/// Fresh XOR/additive shares of a Beaver triple (a dealer's).
pub fn deal_triple<E: Field, R: RngCore + CryptoRng>(rng: &mut R) -> [Triple<E>; 2] {
    let (u, v) = (E::random(rng), E::random(rng));
    let (u0, v0, w0) = (E::random(rng), E::random(rng), E::random(rng));
    [(u0, v0, w0), (u.sub(u0), v.sub(v0), u.mul(v).sub(w0))]
}

/// Shares of a [`VerifyMask`] for a known δ (a dealer's).
pub fn deal_mask<E: Field, R: RngCore + CryptoRng>(delta_mac: E, rng: &mut R) -> [VerifyMask<E>; 2] {
    let (r, r0, d0) = (E::random(rng), E::random(rng), E::random(rng));
    let [t0, t1] = deal_triple(rng);
    [VerifyMask { r: r0, dr: d0, blind: t0 }, VerifyMask { r: r.sub(r0), dr: delta_mac.mul(r).sub(d0), blind: t1 }]
}

/// Π_Verify on `outs = [(y_i, m_i)]`, both over E, and, with an arithmetic
/// payload, `glue = (ω shares, the triple that masks μ′)`.
pub fn pi_verify<E: Field, R: RngCore + CryptoRng>(
    ch: &mut Channel,
    outs: &[(E, E)],
    delta_share: E,
    mask: VerifyMask<E>,
    glue: Option<(&[M127], Triple<M127>)>,
    rng: &mut R,
) -> Result<(), Abort> {
    let omegas: &[M127] = glue.map_or(&[], |g| g.0);
    let coins = CtrPrg::new(coin_block(ch, rng)?).next_words(outs.len() + omegas.len());
    let (mut y, mut m) = (mask.r, mask.dr);
    for (o, &c) in outs.iter().zip(&coins) {
        let c = E::from_seed(Block(c));
        y = y.add(c.mul(o.0));
        m = m.add(c.mul(o.1));
    }
    let mu_glue = omegas.iter().zip(&coins[outs.len()..]).fold(M127::ZERO, |a, (&w, &c)| a.add(M127::from_seed(Block(c)).mul(w)));

    // Open z.
    let mut msg = Vec::with_capacity(E::BYTES);
    y.put(&mut msg);
    ch.send(msg);
    let theirs = ch.recv();
    if theirs.len() != E::BYTES {
        return Err(Abort("malformed verify message"));
    }
    let z = y.add(E::get(&theirs));
    let mu = m.sub(delta_share.mul(z));

    // Open μ − v and μ' − v'.
    let (r, v, w) = mask.blind;
    let e_mine = mu.sub(v);
    let mut msg = Vec::with_capacity(E::BYTES + M127::BYTES);
    e_mine.put(&mut msg);
    let glue_triple = glue.map(|g| g.1);
    let eg_mine = glue_triple.map(|(_, vg, _)| mu_glue.sub(vg));
    if let Some(eg) = eg_mine {
        eg.put(&mut msg);
    }
    let len = msg.len();
    ch.send(msg);
    let theirs = ch.recv();
    if theirs.len() != len {
        return Err(Abort("malformed verify message"));
    }
    let e = e_mine.add(E::get(&theirs));

    // Commit to and open the shares of r·μ and r'·μ'.
    let share = w.add(e.mul(r));
    let mut msg = Vec::with_capacity(len);
    share.put(&mut msg);
    let share_glue = glue_triple.zip(eg_mine).map(|((rg, _, wg), eg_mine)| {
        let eg = eg_mine.add(M127::get(&theirs[E::BYTES..]));
        wg.add(eg.mul(rg))
    });
    if let Some(sg) = share_glue {
        sg.put(&mut msg);
    }
    let other = commit_and_open(ch, &msg, rng)?;
    if other.len() != len {
        return Err(Abort("malformed verify message"));
    }
    let glue_ok = share_glue.is_none_or(|sg| sg.add(M127::get(&other[E::BYTES..])) == M127::ZERO);
    if share.add(E::get(&other)) != E::ZERO || !glue_ok {
        return Err(Abort("output MAC check failed"));
    }
    Ok(())
}

/// Opens checked outputs: exchanges the output shares, then checks the opened
/// `y_i` against their MAC shares with fresh coins `χ'_i`, `Σ χ'_i (m_{i,b} −
/// δ_b·y_i)` committed and opened, so a party that opens a share other than the
/// one Π_Verify checked is caught. The check runs after Π_Verify accepted, and
/// the opened sum can only contain δ, which an abort retires. Returns the outputs.
pub fn open_checked<F: Field, E: Ext<F>, R: RngCore + CryptoRng>(ch: &mut Channel, outs: &[(F, E)], delta_share: E, rng: &mut R) -> Result<Vec<F>, Abort> {
    let mut msg = Vec::with_capacity(outs.len() * F::BYTES);
    outs.iter().for_each(|o| o.0.put(&mut msg));
    ch.send(msg);
    let theirs = ch.recv();
    if theirs.len() != outs.len() * F::BYTES {
        return Err(Abort("malformed output shares"));
    }
    let ys: Vec<F> = outs.iter().zip(theirs.chunks(F::BYTES)).map(|(o, t)| o.0.add(F::get(t))).collect();
    let chi = CtrPrg::new(coin_block(ch, rng)?).next_words(outs.len());
    let sigma = outs.iter().zip(&ys).zip(&chi).fold(E::ZERO, |acc, ((o, &y), &c)| acc.add(E::from_seed(Block(c)).mul(o.1.sub(delta_share.mul(E::embed(y))))));
    let mut msg = Vec::with_capacity(E::BYTES);
    sigma.put(&mut msg);
    let other = commit_and_open(ch, &msg, rng)?;
    if other.len() != E::BYTES {
        return Err(Abort("malformed verify message"));
    }
    if E::get(&other).add(sigma) != E::ZERO {
        return Err(Abort("opened output MAC check failed"));
    }
    Ok(ys)
}
