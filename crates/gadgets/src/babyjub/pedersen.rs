//! In-circuit Baby Jubjub vector Pedersen commitment.
//!
//! Mirrors `crypto::babyjub::pedersen::commit` against the circuit
//! world. The native construction:
//!
//! ```text
//! C = Σ_i x_i · G_i + blinding · H
//! ```
//!
//! where `x_i ∈ Fq` (the stream element, what every encoding
//! produces), `blinding ∈ Fr`, and `G_0, G_1, ..., H` are
//! protocol-pinned nothing-up-my-sleeve generators.
//!
//! ## What this gadget enables
//!
//! Proving statements about a committed stream without revealing
//! it. Canonical claims:
//!
//! - **"This commitment opens to a stream with property P,"** where
//!   the stream is a witness, the commitment is a public input,
//!   and P is something checkable inside the circuit (e.g. "the
//!   first element is in some range," or "the stream is the
//!   encoding of a specific public value").
//! - **"This commitment opens to the same value as that other
//!   commitment (under a different blinding)."** Useful for
//!   linking off-chain witnesses without de-anonymizing them.
//!
//! ## Why generators are circuit constants, not witnesses
//!
//! `G_0..G_n` and `H` are derived natively via try-and-increment
//! hash-to-curve (see `crypto::babyjub::pedersen::derive_g_at`,
//! `derive_h`). We do NOT reproduce that derivation in-circuit —
//! it would be a heavy hash-to-curve gadget for zero gain, since
//! the generators are pinned by the protocol and never change.
//! Instead: precompute the points natively at circuit-construction
//! time and embed them as `BabyJubAffineVar::constant(...)`. Each
//! generator costs zero witness slots; only the affine
//! combinations in scalar-mul cost constraints.
//!
//! ## Why stream length is fixed at circuit-design time
//!
//! Circuits have static shape — the constraint system cannot
//! conditionally include / exclude a scalar-mul block based on a
//! runtime length. The gadget is generic over `const N: usize` so
//! a circuit picks its stream length at instantiation, and the
//! generator constants `G_0..G_{N-1}` get baked in alongside.
//!
//! When a future use case wants runtime length, the right shape
//! is a separate "padded to max" gadget that always does N
//! scalar-muls and treats unused slots as `x_i = 0` (which
//! contributes the identity point — correct, but wasted
//! constraints). That gadget can land on top of this one when
//! needed.
//!
//! ## Why `Fq → Fr` reduction is free here
//!
//! The native side computes `fq_to_fr(x_i)` (modular reduction
//! mod `l`) before each scalar-mul. In R1CS, that reduction
//! collapses: we bit-decompose `x_i` into its full 254-bit
//! representation and feed those bits to the curve's
//! `scalar_mul_le`. Since `G_i` has order `l`, double-and-add
//! over 254 bits naturally computes `(x_i mod l) · G_i`. No
//! explicit reduction step needed; the bit-decomposition handles
//! it.

use ark_ed_on_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::boolean::Boolean;
use ark_r1cs_std::convert::ToBitsGadget;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::groups::CurveVar;
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};

use crypto::babyjub::{g_generator, h_generator, EdwardsProjective, Fq};

use super::BabyJubAffineVar;

/// Embed the protocol's blinding generator `H` as a circuit
/// constant. `H` is pinned in `specs/babyjub-pedersen.md` and
/// derived natively via try-and-increment hash-to-curve; we
/// precompute the affine point and inject it without circuit
/// allocation cost.
pub fn h_generator_constant() -> BabyJubAffineVar {
    let h_projective: EdwardsProjective = h_generator().into();
    BabyJubAffineVar::constant(h_projective)
}

/// Embed the protocol's `i`-th value generator `G_i` as a circuit
/// constant. Same as [`h_generator_constant`] but indexed for
/// vector commitments. Each `G_i` is constant — same on every
/// call for the same `i`.
pub fn g_generator_constant(i: usize) -> BabyJubAffineVar {
    let g_projective: EdwardsProjective = g_generator(i).into();
    BabyJubAffineVar::constant(g_projective)
}

/// In-circuit vector Pedersen commitment over a fixed-length
/// stream:
///
/// ```text
/// C = Σ_{i=0}^{N-1} stream[i] · G_i + blinding · H
/// ```
///
/// `N` is the stream length, pinned at circuit-design time.
/// `stream` is a witness slice of `FpVar<Fq>`. `blinding` is a
/// witness scalar in `Fr`.
///
/// Returns the commitment point. Constrained equal to
/// `crypto::babyjub::pedersen::commit(&stream_native, blinding)`
/// when witness values match.
///
/// ## Cost
///
/// Roughly `N` element scalar-muls (~1.5k constraints each, since
/// the full 254-bit decomposition is needed for the `Fq` stream
/// elements) plus one blinding scalar-mul (~1.3k for 251 bits of
/// `Fr`) plus `N+1` curve-point additions. For `N=9` (the
/// `text-utf8-v1` size) that's ~15k constraints.
pub fn commit_var<const N: usize>(
    cs: ConstraintSystemRef<Fq>,
    stream: &[FpVar<Fq>; N],
    blinding: Fr,
) -> Result<BabyJubAffineVar, SynthesisError> {
    // Start with the blinding term: `blinding · H`.
    let h_var = h_generator_constant();
    let blinding_bigint = blinding.into_bigint();
    let blinding_bit_len = Fr::MODULUS_BIT_SIZE as usize;
    let mut blinding_bits: Vec<Boolean<Fq>> = Vec::with_capacity(blinding_bit_len);
    for i in 0..blinding_bit_len {
        blinding_bits.push(Boolean::<Fq>::new_witness(
            cs.clone(),
            || Ok(blinding_bigint.get_bit(i)),
        )?);
    }
    let mut acc = h_var.scalar_mul_le(blinding_bits.iter())?;

    // Add each `stream[i] · G_i` term. The stream element's full
    // 254-bit decomposition feeds `scalar_mul_le`; the reduction
    // mod `l` happens implicitly via the double-and-add against a
    // generator of order `l`.
    for (i, x) in stream.iter().enumerate() {
        let g_i = g_generator_constant(i);
        let x_bits = x.to_bits_le()?;
        let term = g_i.scalar_mul_le(x_bits.iter())?;
        acc += term;
    }

    Ok(acc)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::babyjub::alloc_point_witness;
    use ark_ff::Field;
    use ark_r1cs_std::eq::EqGadget;
    use ark_relations::r1cs::ConstraintSystem;
    use crypto::babyjub::commit as native_commit;

    /// Allocate `xs` as witness `FpVar`s into a fixed-size array.
    fn alloc_array<const N: usize>(
        cs: ConstraintSystemRef<Fq>,
        xs: &[Fq; N],
    ) -> Result<[FpVar<Fq>; N], SynthesisError> {
        let v: Vec<FpVar<Fq>> = xs
            .iter()
            .map(|x| FpVar::<Fq>::new_witness(cs.clone(), || Ok(*x)))
            .collect::<Result<Vec<_>, _>>()?;
        v.try_into()
            .map_err(|_| SynthesisError::Unsatisfiable)
    }

    /// Native↔circuit equivalence for a single-element commitment.
    /// The smallest non-trivial case, exercising one `G_0`
    /// scalar-mul plus the blinding term.
    #[test]
    fn commit_var_matches_native_single_element() {
        let cs = ConstraintSystem::<Fq>::new_ref();

        let stream: [Fq; 1] = [Fq::from(42u64)];
        let blinding = Fr::from(7u64);
        let expected = native_commit(&stream, blinding);

        let stream_vars = alloc_array(cs.clone(), &stream).unwrap();
        let got_var = commit_var(cs.clone(), &stream_vars, blinding).unwrap();

        let expected_var = alloc_point_witness(cs.clone(), expected).unwrap();
        got_var.enforce_equal(&expected_var).unwrap();
        assert!(cs.is_satisfied().unwrap());
    }

    /// Equivalence for a 4-element stream. Exercises 4 distinct
    /// `G_i` generators; catches per-index errors in generator
    /// embedding that a single-element test would miss.
    #[test]
    fn commit_var_matches_native_four_elements() {
        let cs = ConstraintSystem::<Fq>::new_ref();

        let stream: [Fq; 4] = [
            Fq::from(1u64),
            Fq::from(2u64),
            Fq::from(3u64),
            Fq::from(4u64),
        ];
        let blinding = Fr::from(99u64);
        let expected = native_commit(&stream, blinding);

        let stream_vars = alloc_array(cs.clone(), &stream).unwrap();
        let got_var = commit_var(cs.clone(), &stream_vars, blinding).unwrap();

        let expected_var = alloc_point_witness(cs.clone(), expected).unwrap();
        got_var.enforce_equal(&expected_var).unwrap();
        assert!(cs.is_satisfied().unwrap());
    }

    /// Equivalence for the 9-element stream — the canonical
    /// `text-utf8-v1` encoding size. The realistic protocol
    /// workload.
    #[test]
    fn commit_var_matches_native_nine_elements() {
        let cs = ConstraintSystem::<Fq>::new_ref();

        let stream: [Fq; 9] = [
            Fq::from(1u64),
            Fq::from(2u64),
            Fq::from(3u64),
            Fq::from(4u64),
            Fq::from(5u64),
            Fq::from(6u64),
            Fq::from(7u64),
            Fq::from(8u64),
            Fq::from(9u64),
        ];
        let blinding = Fr::from(12345u64);
        let expected = native_commit(&stream, blinding);

        let stream_vars = alloc_array(cs.clone(), &stream).unwrap();
        let got_var = commit_var(cs.clone(), &stream_vars, blinding).unwrap();

        let expected_var = alloc_point_witness(cs.clone(), expected).unwrap();
        got_var.enforce_equal(&expected_var).unwrap();
        assert!(cs.is_satisfied().unwrap());
    }

    /// Equivalence with a near-full-range stream element. Catches
    /// truncation errors in the 254-bit decomposition that
    /// small-value tests would not expose.
    #[test]
    fn commit_var_matches_native_large_field_element() {
        let cs = ConstraintSystem::<Fq>::new_ref();

        // 2^250 — well past 64 bits, well into the upper range
        // of Fq.
        let big = Fq::from(2u64).pow([250u64, 0, 0, 0]);
        let stream: [Fq; 1] = [big];
        let blinding = Fr::from(7u64);
        let expected = native_commit(&stream, blinding);

        let stream_vars = alloc_array(cs.clone(), &stream).unwrap();
        let got_var = commit_var(cs.clone(), &stream_vars, blinding).unwrap();

        let expected_var = alloc_point_witness(cs.clone(), expected).unwrap();
        got_var.enforce_equal(&expected_var).unwrap();
        assert!(cs.is_satisfied().unwrap());
    }

    /// Negative-direction confirmation: a deliberately wrong
    /// expected commitment unsatisfies the constraint system.
    #[test]
    fn commit_var_rejects_wrong_expected() {
        let cs = ConstraintSystem::<Fq>::new_ref();

        let stream: [Fq; 2] = [Fq::from(1u64), Fq::from(2u64)];
        let blinding = Fr::from(7u64);
        let wrong = native_commit(&stream, Fr::from(8u64)); // different blinding

        let stream_vars = alloc_array(cs.clone(), &stream).unwrap();
        let got_var = commit_var(cs.clone(), &stream_vars, blinding).unwrap();

        let wrong_var = alloc_point_witness(cs.clone(), wrong).unwrap();
        got_var.enforce_equal(&wrong_var).unwrap();
        assert!(!cs.is_satisfied().unwrap());
    }
}
