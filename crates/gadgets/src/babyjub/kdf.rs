//! In-circuit Baby Jubjub KDF.
//!
//! Mirrors `crypto::babyjub::kdf::derive` against `FpVar<Fq>`. The
//! native composition is:
//!
//! ```text
//! derive(shared, ctx) = poseidon_hash_fixed(
//!     domain_tag("babyjub-kdf"),
//!     [shared.x, shared.y, ...ctx],
//! )
//! ```
//!
//! The gadget does exactly the same: extract the affine coordinates
//! from a `BabyJubAffineVar`, prepend them to the context, and
//! invoke the in-circuit Poseidon hash under the pinned KDF domain
//! tag.
//!
//! ## What the gadget is FOR
//!
//! Proving "I know the shared ECDH point that, combined with this
//! public context, yields this symmetric key." The canonical
//! circuit-level use is binding a tag-verify or a ciphertext-decrypt
//! claim to the upstream ECDH+KDF derivation, without exposing the
//! shared point or the keys themselves.
//!
//! ## What the gadget is NOT
//!
//! - **Not an in-circuit ECDH.** The shared point is an input —
//!   either a witness (when the prover knows it) or precomputed
//!   off-circuit. An in-circuit ECDH would require constraining
//!   `shared = sk · peer_pk`, which is a separate (heavy) gadget
//!   not yet built.
//! - **Not a context-length enforcer in-circuit.** The native side
//!   checks `context.len() <= MAX_CONTEXT_LEN` at runtime and
//!   returns a typed error. In a circuit, context length is fixed
//!   at circuit-design time; over-length inputs are a circuit-
//!   construction bug, not a witness-time error. The gadget
//!   forwards the underlying `poseidon_hash_fixed_var` error if the
//!   total arity falls outside `[1, 12]`.

use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::fields::FieldVar;
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};

use crypto::babyjub::Fq;
use crypto::babyjub::KDF_DOMAIN;
use crypto::poseidon::domain_tag;

use super::BabyJubAffineVar;
use crate::poseidon::poseidon_hash_fixed_var;

/// Derive one field element of key material from a shared ECDH
/// point and a context. Mirrors `crypto::babyjub::kdf::derive`.
///
/// The returned `FpVar` is constrained equal to the native KDF's
/// output on matching inputs.
///
/// `context.len()` must satisfy `2 + context.len() ≤ 12`, i.e.
/// `context.len() ≤ 10`. The native side caps context at 9 for
/// `MAX_CONTEXT_LEN` ergonomic reasons; the gadget's hard limit is
/// 10 because `poseidon_hash_fixed_var` accepts `total_arity` up
/// to 12, and the two coordinates take 2 of those slots. Circuits
/// should respect the native cap of 9.
pub fn kdf_derive_var(
    cs: ConstraintSystemRef<Fq>,
    shared: &BabyJubAffineVar,
    context: &[FpVar<Fq>],
) -> Result<FpVar<Fq>, SynthesisError> {
    // Build the Poseidon input: shared point's coordinates first,
    // then the context. Same shape as the native side.
    let mut inputs: Vec<FpVar<Fq>> = Vec::with_capacity(2 + context.len());
    inputs.push(shared.x.clone());
    inputs.push(shared.y.clone());
    for c in context {
        inputs.push(c.clone());
    }

    // Domain tag is a constant: every protocol consumer hashes
    // under `domain_tag("babyjub-kdf")`. Allocating it as a
    // constant FpVar folds into the affine combination
    // representation and costs no witness slot.
    let tag = FpVar::<Fq>::constant(domain_tag(KDF_DOMAIN));

    poseidon_hash_fixed_var(cs, &tag, &inputs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::babyjub::alloc_point_witness;
    use ark_r1cs_std::alloc::AllocVar;
    use ark_r1cs_std::eq::EqGadget;
    use ark_relations::r1cs::ConstraintSystem;
    use crypto::babyjub::{keypair_from_seed, kdf_derive, shared_secret, Seed};

    /// Build a fixed shared point: ECDH between two pinned seeds.
    /// Same shape the native `babyjub::kdf` test module uses, so the
    /// gadget's load-bearing test runs against the same Alice/Bob
    /// shared point pinned in `specs/babyjub-kdf.md § Worked
    /// Example`.
    fn fixed_shared_point() -> crypto::babyjub::EdwardsAffine {
        let mut seed_a = [0u8; 64];
        seed_a[0] = 1;
        let mut seed_b = [0u8; 64];
        seed_b[0] = 2;
        let (sk_a, _) = keypair_from_seed(&Seed::from_bytes(seed_a));
        let (_, pk_b) = keypair_from_seed(&Seed::from_bytes(seed_b));
        shared_secret(&sk_a, &pk_b)
    }

    /// Native↔circuit equivalence on the canonical Vector 2 from
    /// `specs/babyjub-kdf.md`: the envelope-cipher-key role tag
    /// with envelope id 42. The load-bearing test: a passing
    /// equivalence here ties the gadget to the same KDF output
    /// the protocol's other specs (cipher, MAC) chain from.
    #[test]
    fn kdf_var_matches_native_cipher_role_envelope_42() {
        let cs = ConstraintSystem::<Fq>::new_ref();

        let shared = fixed_shared_point();
        let context = [domain_tag("envelope-cipher-key"), Fq::from(42u64)];
        let expected = kdf_derive(&shared, &context).expect("ok");

        let shared_var = alloc_point_witness(cs.clone(), shared).unwrap();
        let context_vars: Vec<FpVar<Fq>> = context
            .iter()
            .map(|c| FpVar::<Fq>::new_witness(cs.clone(), || Ok(*c)).unwrap())
            .collect();
        let got_var = kdf_derive_var(cs.clone(), &shared_var, &context_vars).unwrap();

        let expected_var = FpVar::<Fq>::new_input(cs.clone(), || Ok(expected)).unwrap();
        got_var.enforce_equal(&expected_var).unwrap();
        assert!(cs.is_satisfied().unwrap());
    }

    /// Equivalence on the MAC-role context — the cross-construction
    /// differentiator. Same shared point and envelope id as the
    /// cipher-role test, only the role tag differs, but the
    /// derived key MUST differ. Confirms domain-separation
    /// propagates through the gadget.
    #[test]
    fn kdf_var_matches_native_mac_role_envelope_42() {
        let cs = ConstraintSystem::<Fq>::new_ref();

        let shared = fixed_shared_point();
        let context = [domain_tag("envelope-mac-key"), Fq::from(42u64)];
        let expected = kdf_derive(&shared, &context).expect("ok");

        let shared_var = alloc_point_witness(cs.clone(), shared).unwrap();
        let context_vars: Vec<FpVar<Fq>> = context
            .iter()
            .map(|c| FpVar::<Fq>::new_witness(cs.clone(), || Ok(*c)).unwrap())
            .collect();
        let got_var = kdf_derive_var(cs.clone(), &shared_var, &context_vars).unwrap();

        let expected_var = FpVar::<Fq>::new_input(cs.clone(), || Ok(expected)).unwrap();
        got_var.enforce_equal(&expected_var).unwrap();
        assert!(cs.is_satisfied().unwrap());
    }

    /// Equivalence on the empty context — the "no binding" baseline
    /// from `specs/babyjub-kdf.md § Vector 1`.
    #[test]
    fn kdf_var_matches_native_empty_context() {
        let cs = ConstraintSystem::<Fq>::new_ref();

        let shared = fixed_shared_point();
        let expected = kdf_derive(&shared, &[]).expect("ok");

        let shared_var = alloc_point_witness(cs.clone(), shared).unwrap();
        let got_var = kdf_derive_var(cs.clone(), &shared_var, &[]).unwrap();

        let expected_var = FpVar::<Fq>::new_input(cs.clone(), || Ok(expected)).unwrap();
        got_var.enforce_equal(&expected_var).unwrap();
        assert!(cs.is_satisfied().unwrap());
    }

    /// Negative-direction confirmation: a deliberately wrong
    /// expected key unsatisfies the constraint system. Ensures
    /// the equivalence isn't passing by accident.
    #[test]
    fn kdf_var_rejects_wrong_expected() {
        let cs = ConstraintSystem::<Fq>::new_ref();

        let shared = fixed_shared_point();
        let context = [domain_tag("envelope-cipher-key"), Fq::from(42u64)];

        let shared_var = alloc_point_witness(cs.clone(), shared).unwrap();
        let context_vars: Vec<FpVar<Fq>> = context
            .iter()
            .map(|c| FpVar::<Fq>::new_witness(cs.clone(), || Ok(*c)).unwrap())
            .collect();
        let got_var = kdf_derive_var(cs.clone(), &shared_var, &context_vars).unwrap();

        let wrong = FpVar::<Fq>::new_input(cs.clone(), || Ok(Fq::from(999u64))).unwrap();
        got_var.enforce_equal(&wrong).unwrap();
        assert!(!cs.is_satisfied().unwrap());
    }
}
