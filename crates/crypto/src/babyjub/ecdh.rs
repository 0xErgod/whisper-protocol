//! Baby Jubjub ECDH — shared-point derivation.
//!
//! `shared_secret(sk_self, pk_peer) = sk_self · pk_peer`.
//!
//! The protocol's first multi-party primitive. Symmetry — `sk_a ·
//! (sk_b·G) == sk_b · (sk_a·G)` — is the load-bearing property; the
//! fixture test pins it as a runtime invariant, not just a math claim.
//!
//! ## What this returns, and what it deliberately does NOT
//!
//! This module returns the **raw shared point**, not a derived
//! encryption key. A KDF (Poseidon over the shared point's coordinates
//! plus context like recipient index, suite id, AAD) is what turns the
//! point into per-envelope key material. That KDF belongs to the
//! envelope-suite brick, not here, for two reasons:
//!
//!  - The KDF's domain separation depends on the envelope suite's
//!    identifier and context format, which is its own design surface.
//!  - Keeping ECDH as just the curve operation leaves it composable
//!    for non-envelope uses (PAKEs, equality proofs, blinded
//!    randomness exchange).
//!
//! Consumers that just want bytes for a one-off symmetric key should
//! hash the shared point with Poseidon + their own domain tag; the
//! envelope brick will eventually provide a higher-level helper.
//!
//! ## What about contributory behaviour / small-subgroup attacks?
//!
//! The `PublicKey` type is constructed only via paths that guarantee
//! on-curve + prime-subgroup membership (`keypair_from_seed`'s
//! `from_subgroup_point`, or `point_from_strings` which validates).
//! That means an attacker cannot force a low-order shared secret by
//! handing us a small-order public key — the validation rejected it
//! before it ever reached this function. The shared point this
//! function returns is itself in the prime-order subgroup by closure.

use ark_ec::CurveGroup;

use super::config::EdwardsAffine;
use super::keypair::{PublicKey, SecretKey};

/// Compute the shared point: `sk_self · pk_peer`.
///
/// Two parties calling this on each other's keypairs land on the same
/// point (`Alice.sk · Bob.PK == Bob.sk · Alice.PK`). The result is in
/// affine form, ready to serialize or pass on to a KDF.
pub fn shared_secret(sk_self: &SecretKey, pk_peer: &PublicKey) -> EdwardsAffine {
    // `mul` returns affine; `pk_peer.point()` borrows the validated
    // peer point. No additional checks needed — the `PublicKey` type
    // is the proof of validation.
    use ark_ec::twisted_edwards::Projective;
    (Projective::from(*pk_peer.point()) * sk_self.scalar()).into_affine()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::babyjub::{
        is_in_prime_subgroup, is_on_curve, keypair_from_seed, IDENTITY,
    };
    use crate::babyjub::Seed;

    /// Build a keypair from a single-byte-different seed for readable tests.
    fn seed_with(byte: u8) -> Seed {
        let mut bytes = [0u8; 64];
        bytes[0] = byte;
        Seed::from_bytes(bytes)
    }

    /// The defining ECDH property. If this ever fails, key agreement is
    /// broken and nothing else in this module is meaningful.
    #[test]
    fn ecdh_is_symmetric() {
        let (sk_a, pk_a) = keypair_from_seed(&seed_with(1));
        let (sk_b, pk_b) = keypair_from_seed(&seed_with(2));
        assert_eq!(
            shared_secret(&sk_a, &pk_b),
            shared_secret(&sk_b, &pk_a),
            "ECDH symmetry violated",
        );
    }

    /// The shared point lives on the curve and in the prime subgroup —
    /// the subgroup is closed under scalar multiplication, so this
    /// follows mathematically from valid inputs. Pinning it as a test
    /// catches the case where a future refactor accidentally produces
    /// off-subgroup points (e.g. wrong `mul`).
    #[test]
    fn shared_point_is_valid() {
        let (sk_a, _) = keypair_from_seed(&seed_with(1));
        let (_, pk_b) = keypair_from_seed(&seed_with(2));
        let shared = shared_secret(&sk_a, &pk_b);
        assert!(is_on_curve(&shared));
        assert!(is_in_prime_subgroup(&shared));
    }

    /// Distinct counterparties yield distinct shared points. (Self-ECDH
    /// against a different peer should produce a different result —
    /// otherwise the peer's identity isn't entering the computation.)
    #[test]
    fn distinct_peers_yield_distinct_shared_points() {
        let (sk_a, _) = keypair_from_seed(&seed_with(1));
        let (_, pk_b) = keypair_from_seed(&seed_with(2));
        let (_, pk_c) = keypair_from_seed(&seed_with(3));
        assert_ne!(shared_secret(&sk_a, &pk_b), shared_secret(&sk_a, &pk_c));
    }

    /// Self-ECDH (`sk · PK`, both from the same keypair) is well-defined
    /// — it equals `sk² · G`. We don't pin a specific value here; we
    /// just confirm it is not the identity (would imply `sk² ≡ 0`,
    /// impossible for a non-zero scalar in a prime-order field).
    #[test]
    fn self_ecdh_is_not_identity() {
        let (sk_a, pk_a) = keypair_from_seed(&seed_with(1));
        let shared = shared_secret(&sk_a, &pk_a);
        assert_ne!(shared, IDENTITY);
    }
}
