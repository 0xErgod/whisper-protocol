//! In-circuit Baby Jubjub curve operations.
//!
//! Mirrors `crypto::babyjub::curve` against `FpVar<Fq>` so circuits
//! can prove statements about curve points (public keys, ECDH shared
//! points, Pedersen commitments, Schnorr R-points) without leaving
//! the field.
//!
//! ## Why this is small
//!
//! Twisted-Edwards point addition and scalar multiplication are
//! shipped by arkworks (`ark-r1cs-std`'s
//! `groups::curves::twisted_edwards::AffineVar`), generic over any
//! `TECurveConfig`. Our native `crypto::babyjub::BabyJubConfig` is
//! exactly that — a `TECurveConfig` impl that pins the ERC-2494 /
//! circomlib dialect (`a = 168700`, NOT arkworks' default `a = 1`).
//!
//! Specializing arkworks' generic gadget on our config gives us the
//! audited addition formulas and scalar-mul algorithm for free, on
//! the right curve. No hand-written R1CS for Edwards arithmetic.
//!
//! What this module DOES contribute:
//!
//! - **Type aliases** that fix the curve config so callers don't
//!   thread two generic parameters through every signature.
//! - **A native↔circuit equivalence test** confirming the gadget
//!   computes the same point as `crypto::babyjub::curve::mul` on
//!   matching inputs. This is the load-bearing artifact: it pins
//!   that the gadget is running against `a = 168700`, not the
//!   arkworks default.
//! - **A pinned generator gadget** for `Base8`, exposed as a
//!   constant `BabyJubAffineVar`.

pub mod cipher;
pub mod ecdh;
pub mod kdf;
pub mod keypair;
pub mod mac;

pub use cipher::{decrypt_var, encrypt_var};
pub use ecdh::shared_secret_var;
pub use kdf::kdf_derive_var;
pub use keypair::pk_from_sk_var;
pub use mac::mac_var;

use ark_ed_on_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::boolean::Boolean;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::groups::curves::twisted_edwards::AffineVar;
use ark_r1cs_std::groups::CurveVar;
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};

use crypto::babyjub::{generator, BabyJubConfig, EdwardsAffine, EdwardsProjective, Fq};

/// In-circuit Baby Jubjub point in twisted-Edwards affine
/// coordinates. Wraps arkworks' generic `AffineVar` specialized on
/// our curve config so callers see one type name with no generic
/// parameters to thread through.
pub type BabyJubAffineVar = AffineVar<BabyJubConfig, FpVar<Fq>>;

/// Allocate a curve point as a circuit witness from its native
/// affine representation. Thin wrapper around the arkworks gadget's
/// `new_witness` constructor that fixes the projective-vs-affine
/// type story so callers don't have to.
///
/// **Subgroup membership is NOT enforced by this allocation.** The
/// witness carries whatever point the caller supplies, on the
/// twisted-Edwards curve or not. Circuits whose security depends on
/// "this is a prime-subgroup point" MUST add an explicit subgroup
/// check; see `crypto::babyjub::curve::is_in_prime_subgroup` for
/// the native reference (the gadget version is a future brick).
pub fn alloc_point_witness(
    cs: ConstraintSystemRef<Fq>,
    point: EdwardsAffine,
) -> Result<BabyJubAffineVar, SynthesisError> {
    // The arkworks gadget allocates from the projective form by
    // convention; we lift the affine input via the standard
    // conversion. Same point, different in-memory shape.
    let projective: EdwardsProjective = point.into();
    BabyJubAffineVar::new_witness(cs, || Ok(projective))
}

/// Allocate the generator `Base8` as a circuit constant. Cheaper
/// than a witness allocation because the coordinates fold into
/// affine-combination representation; one less witness slot per use.
///
/// The point itself is the same `Base8` `crypto::babyjub::generator`
/// returns and the same one pinned in `specs/babyjub-curve.md §
/// Generator`. Every public key in the protocol is a scalar multiple
/// of this point.
pub fn generator_constant() -> BabyJubAffineVar {
    let g_projective: EdwardsProjective = generator().into();
    BabyJubAffineVar::constant(g_projective)
}

/// In-circuit scalar multiplication: `scalar · point`. Mirrors
/// `crypto::babyjub::curve::mul`.
///
/// The scalar is allocated as little-endian bits inside the circuit.
/// We expose the bit-allocation as a helper rather than asking the
/// caller to thread a `Vec<Boolean<Fq>>` through every call site,
/// because every consumer of this gadget will want the same LE-bit
/// representation. A caller who needs a constraint-shared scalar
/// (e.g. proving two operations use the same secret key) should
/// allocate the bits once and reuse them via the lower-level
/// `point.scalar_mul_le(&bits)` directly.
///
/// Returns the product point as a `BabyJubAffineVar`. Constrained
/// equal to the native `mul(&scalar_native, &point_native)` when
/// the witness values match.
pub fn scalar_mul_var(
    cs: ConstraintSystemRef<Fq>,
    scalar: Fr,
    point: &BabyJubAffineVar,
) -> Result<BabyJubAffineVar, SynthesisError> {
    // Decompose `scalar` into LE bits as `Boolean<Fq>` witnesses.
    // The bit length is the scalar field's modulus bit size; using
    // the full width keeps the gadget honest about which scalars
    // can be represented (every `Fr` element fits).
    let scalar_bigint = scalar.into_bigint();
    let bit_length = Fr::MODULUS_BIT_SIZE as usize;
    let mut bits: Vec<Boolean<Fq>> = Vec::with_capacity(bit_length);
    for i in 0..bit_length {
        let b = scalar_bigint.get_bit(i);
        bits.push(Boolean::<Fq>::new_witness(cs.clone(), || Ok(b))?);
    }

    point.scalar_mul_le(bits.iter())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::Field;
    use ark_r1cs_std::eq::EqGadget;
    use ark_relations::r1cs::ConstraintSystem;
    use crypto::babyjub::{generator as native_generator, mul as native_mul};

    /// Native↔circuit equivalence for scalar multiplication on
    /// `Base8`. The single load-bearing test for this brick: a
    /// pass here pins that the gadget is using `a = 168700`
    /// (Baby Jubjub / ERC-2494), not arkworks' default Edwards
    /// dialect. A drift in curve coefficients would land on a
    /// different point and unsatisfy the constraint system.
    #[test]
    fn scalar_mul_var_matches_native_on_generator() {
        let cs = ConstraintSystem::<Fq>::new_ref();

        let scalar = Fr::from(42u64);
        let g_native = native_generator();
        let expected = native_mul(&scalar, &g_native);

        let g_var = generator_constant();
        let got_var = scalar_mul_var(cs.clone(), scalar, &g_var).unwrap();

        let expected_var = alloc_point_witness(cs.clone(), expected).unwrap();
        got_var.enforce_equal(&expected_var).unwrap();
        assert!(cs.is_satisfied().unwrap());
    }

    /// Equivalence for a larger scalar — exercises more of the
    /// double-and-add loop and confirms the LE-bit decomposition
    /// doesn't truncate.
    #[test]
    fn scalar_mul_var_matches_native_large_scalar() {
        let cs = ConstraintSystem::<Fq>::new_ref();

        // 2^200 — far past `u64`, deep into the scalar field.
        let scalar = Fr::from(2u64).pow([200u64, 0, 0, 0]);
        let g_native = native_generator();
        let expected = native_mul(&scalar, &g_native);

        let g_var = generator_constant();
        let got_var = scalar_mul_var(cs.clone(), scalar, &g_var).unwrap();

        let expected_var = alloc_point_witness(cs.clone(), expected).unwrap();
        got_var.enforce_equal(&expected_var).unwrap();
        assert!(cs.is_satisfied().unwrap());
    }

    /// Negative-direction confirmation: a deliberately wrong
    /// expected point unsatisfies the constraint system. Ensures
    /// the equivalence tests aren't passing by accident.
    #[test]
    fn scalar_mul_var_rejects_wrong_expected() {
        let cs = ConstraintSystem::<Fq>::new_ref();

        let scalar = Fr::from(42u64);
        let g_native = native_generator();
        let wrong_expected = native_mul(&Fr::from(43u64), &g_native);

        let g_var = generator_constant();
        let got_var = scalar_mul_var(cs.clone(), scalar, &g_var).unwrap();

        let wrong_var = alloc_point_witness(cs.clone(), wrong_expected).unwrap();
        got_var.enforce_equal(&wrong_var).unwrap();
        assert!(!cs.is_satisfied().unwrap());
    }

    /// Equivalence for scalar mul on a non-generator point —
    /// confirms the gadget works on arbitrary points, not just
    /// the embedded constant.
    #[test]
    fn scalar_mul_var_matches_native_on_arbitrary_point() {
        let cs = ConstraintSystem::<Fq>::new_ref();

        // Build an arbitrary in-subgroup point as `7 · Base8`.
        let base_scalar = Fr::from(7u64);
        let base_point = native_mul(&base_scalar, &native_generator());

        let scalar = Fr::from(13u64);
        let expected = native_mul(&scalar, &base_point);

        let base_var = alloc_point_witness(cs.clone(), base_point).unwrap();
        let got_var = scalar_mul_var(cs.clone(), scalar, &base_var).unwrap();

        let expected_var = alloc_point_witness(cs.clone(), expected).unwrap();
        got_var.enforce_equal(&expected_var).unwrap();
        assert!(cs.is_satisfied().unwrap());
    }
}
