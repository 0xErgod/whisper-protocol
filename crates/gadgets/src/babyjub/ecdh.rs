//! In-circuit Baby Jubjub ECDH.
//!
//! Mirrors `crypto::babyjub::ecdh::shared_secret` against the
//! circuit world. The native operation is `sk · pk_peer` on the
//! curve, and the gadget is literally that, with `sk` allocated as
//! a witness scalar and `pk_peer` as a curve gadget point.
//!
//! ## Why this exists as its own function
//!
//! Calling `scalar_mul_var(cs, sk, pk_peer)` would compute the same
//! point. The wrapper carries no extra constraints. What it
//! carries is **intent**: a circuit reading
//! `shared_secret_var(cs, my_sk, peer_pk)` is self-documenting;
//! a raw `scalar_mul_var(cs, my_sk, peer_pk)` is not. The cost is
//! zero, the readability win is real, and audits inspect the
//! composition more honestly when the protocol-level operation
//! has its own name.
//!
//! ## What this is NOT
//!
//! - **Not a subgroup-membership enforcer.** The native side
//!   relies on `PublicKey` having been validated at its boundary
//!   (the `point_from_strings` decoder, the keypair derivation,
//!   etc.) so that `pk_peer` is in the prime-order subgroup. The
//!   gadget does NOT re-verify subgroup membership; if a circuit
//!   accepts an arbitrary curve point as `pk_peer`, it MUST
//!   compose a subgroup-check gadget first. That gadget is not
//!   yet built — file a TODO at the call site until it lands.
//! - **Not a key derivation.** Returns the raw shared point.
//!   Compose with [`crate::babyjub::kdf_derive_var`] to land at
//!   symmetric key material for envelope use.

use ark_ed_on_bn254::Fr;
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};

use crypto::babyjub::Fq;

use super::{scalar_mul_var, BabyJubAffineVar};

/// In-circuit ECDH: compute `sk · pk_peer`.
///
/// `sk` is a scalar witness (caller decides how it's bound — as a
/// secret, as a hash-derived value, etc.). `pk_peer` is a curve
/// gadget point — typically a witness allocated from a known
/// public key, or a constant if the peer is fixed at circuit-
/// design time.
///
/// Returns the shared point as `BabyJubAffineVar`. Constrained
/// equal to `crypto::babyjub::shared_secret(&sk_native,
/// &pk_peer_native)` when the witness values match.
pub fn shared_secret_var(
    cs: ConstraintSystemRef<Fq>,
    sk: Fr,
    pk_peer: &BabyJubAffineVar,
) -> Result<BabyJubAffineVar, SynthesisError> {
    scalar_mul_var(cs, sk, pk_peer)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::babyjub::alloc_point_witness;
    use ark_r1cs_std::eq::EqGadget;
    use ark_relations::r1cs::ConstraintSystem;
    use crypto::babyjub::{keypair_from_seed, shared_secret, Seed};

    /// Native↔circuit equivalence on the canonical Alice/Bob pair
    /// pinned in `specs/babyjub-ecdh.md`. The shared point the
    /// gadget computes here is the same one every downstream
    /// envelope-fixture chains from.
    #[test]
    fn shared_secret_var_matches_native() {
        let cs = ConstraintSystem::<Fq>::new_ref();

        // Alice and Bob, fixed seeds from the spec.
        let mut seed_a = [0u8; 64];
        seed_a[0] = 1;
        let mut seed_b = [0u8; 64];
        seed_b[0] = 2;
        let (sk_a, _) = keypair_from_seed(&Seed::from_bytes(seed_a));
        let (_, pk_b) = keypair_from_seed(&Seed::from_bytes(seed_b));

        let expected = shared_secret(&sk_a, &pk_b);

        let pk_b_var = alloc_point_witness(cs.clone(), *pk_b.point()).unwrap();
        let shared_var = shared_secret_var(cs.clone(), *sk_a.scalar(), &pk_b_var).unwrap();

        let expected_var = alloc_point_witness(cs.clone(), expected).unwrap();
        shared_var.enforce_equal(&expected_var).unwrap();
        assert!(cs.is_satisfied().unwrap());
    }

    /// Symmetry: `sk_a · pk_b == sk_b · pk_a`. The fundamental
    /// ECDH property, checked at the gadget level. Both sides
    /// must agree on the shared point or the protocol breaks.
    #[test]
    fn shared_secret_var_is_symmetric() {
        let cs = ConstraintSystem::<Fq>::new_ref();

        let mut seed_a = [0u8; 64];
        seed_a[0] = 1;
        let mut seed_b = [0u8; 64];
        seed_b[0] = 2;
        let (sk_a, pk_a) = keypair_from_seed(&Seed::from_bytes(seed_a));
        let (sk_b, pk_b) = keypair_from_seed(&Seed::from_bytes(seed_b));

        let pk_a_var = alloc_point_witness(cs.clone(), *pk_a.point()).unwrap();
        let pk_b_var = alloc_point_witness(cs.clone(), *pk_b.point()).unwrap();

        let from_a = shared_secret_var(cs.clone(), *sk_a.scalar(), &pk_b_var).unwrap();
        let from_b = shared_secret_var(cs.clone(), *sk_b.scalar(), &pk_a_var).unwrap();

        from_a.enforce_equal(&from_b).unwrap();
        assert!(cs.is_satisfied().unwrap());
    }
}
