//! Key derivation function over Baby Jubjub.
//!
//! `derive(shared_point, context) -> Fq`
//!
//! Takes a shared secret curve point (the output of an ECDH exchange)
//! and a caller-supplied context — itself a stream of field elements
//! — and produces one field element suitable as a symmetric key for
//! downstream primitives (stream cipher, MAC, etc.).
//!
//! Built on [`poseidon_hash_fixed`] under a dedicated KDF domain tag,
//! so a Poseidon hash with the same payload but a different domain
//! cannot be misused as a KDF output (and vice versa).
//!
//! ## What this is FOR
//!
//! The canonical use is "I have a shared ECDH point with a peer and
//! want to derive symmetric keys for an envelope." The caller calls
//! `derive` once per *role* that needs its own key, passing a context
//! that distinguishes the roles:
//!
//! ```text
//! shared  = babyjub::shared_secret(my_sk, peer_pk)         // ECDH
//! key_enc = babyjub::kdf::derive(&shared, &[ENC_ROLE_TAG, envelope_id])
//! key_mac = babyjub::kdf::derive(&shared, &[MAC_ROLE_TAG, envelope_id])
//! ```
//!
//! The two keys are unrelated to anyone without the shared point.
//! Learning one tells you nothing about the other, by virtue of the
//! Poseidon hash's preimage resistance and the role-tag domain
//! separation.
//!
//! ## What this is NOT
//!
//! - **A password KDF.** Argon2 / scrypt / bcrypt are for
//!   low-entropy inputs (passwords). This one assumes the input is
//!   already high-entropy: a curve point in the prime-order
//!   subgroup, indistinguishable from a uniformly-random subgroup
//!   element to anyone without one of the ECDH secrets.
//! - **An expander.** The output is always one field element. If a
//!   consumer needs multiple keys, it calls `derive` multiple times
//!   with different contexts. The composition is honest about the
//!   one-key-per-call shape.
//! - **A hash function.** It is one, internally, but the public
//!   name is `derive` because the *contract* is "produce key
//!   material" not "produce a cryptographic hash." The two
//!   contracts collapse for our use, but the name makes the
//!   intended-use explicit so the spec contract pins it.
//!
//! ## Context conventions
//!
//! The `context` slice is free-form — `derive` does not inspect it
//! beyond passing it to Poseidon. Each consumer's spec pins what
//! goes in:
//!
//! - The first element is conventionally a **role tag** that
//!   distinguishes which downstream key is being derived (encryption
//!   vs MAC vs key-confirmation vs ...). The tag is itself derived
//!   from a string via [`poseidon::domain_tag`] so the value is
//!   stable across implementations.
//! - Subsequent elements bind the key to a session, an envelope id,
//!   a recipient index, etc. — whatever the consumer needs to make
//!   the key unique to its context.
//!
//! The protocol's encoding registry (`specs/encodings/README.md`)
//! is the model: this primitive defines the call shape, consumers
//! define what their context fields mean.

use crate::poseidon::{domain_tag, poseidon_hash_fixed, PoseidonError};

use super::config::{EdwardsAffine, Fq};

/// Domain tag for the KDF. Distinguishes this hash from every
/// other Poseidon use in the protocol — even with identical payload,
/// a `poseidon_hash_fixed` call under a different domain produces a
/// different output, so a KDF result cannot be misused as a
/// commitment or a Schnorr challenge.
pub const KDF_DOMAIN: &str = "babyjub-kdf";

/// Maximum supported `context` length. Imposed by
/// `poseidon_hash_fixed`'s arity ceiling: 1 domain tag + 2 point
/// coordinates + `context.len()` payload ≤ 12, so the context can
/// hold up to 9 field elements. The cap is wide enough for every
/// realistic protocol use (a role tag + a few binding fields), but
/// it's checked at runtime to keep the typed error contract honest.
pub const MAX_CONTEXT_LEN: usize = 9;

/// Derive one field element of key material from a shared point and
/// a caller-supplied context.
///
/// ```text
/// key = Poseidon_hash_fixed(kdf_domain, [shared.x, shared.y, ...context])
/// ```
///
/// The shared point is taken **directly** (not as wire-decoded
/// coordinates) — the KDF is defined on the curve, not on the wire.
/// The caller is responsible for getting a valid `EdwardsAffine`
/// (typically via `shared_secret` or `point_from_strings`); the KDF
/// does no validity check itself.
///
/// Returns `Err(MessageTooLong)` (re-exposed as
/// [`PoseidonError::ArityOutOfRange`]) if
/// `context.len() > MAX_CONTEXT_LEN`.
///
/// The output lives in `F_p`. Downstream consumers that need an
/// `F_l` scalar should reduce explicitly — the protocol's existing
/// `F_p → F_l` reduction (serialize bytes, re-parse) lives at each
/// consumer's spec, not in the KDF.
pub fn derive(shared: &EdwardsAffine, context: &[Fq]) -> Result<Fq, PoseidonError> {
    let mut inputs: Vec<Fq> = Vec::with_capacity(2 + context.len());
    inputs.push(shared.x);
    inputs.push(shared.y);
    inputs.extend_from_slice(context);
    poseidon_hash_fixed(domain_tag(KDF_DOMAIN), &inputs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::babyjub::{keypair_from_seed, shared_secret, Seed};

    /// Build a fixed shared point: ECDH between two pinned seeds.
    /// Used as a stable, non-trivial point for the tests below.
    fn fixed_shared_point() -> EdwardsAffine {
        let mut seed_a = [0u8; 64];
        seed_a[0] = 1;
        let mut seed_b = [0u8; 64];
        seed_b[0] = 2;
        let (sk_a, _) = keypair_from_seed(&Seed::from_bytes(seed_a));
        let (_, pk_b) = keypair_from_seed(&Seed::from_bytes(seed_b));
        shared_secret(&sk_a, &pk_b)
    }

    /// Deterministic: same `(shared, context)` always produces the
    /// same key. Foundational property.
    #[test]
    fn derive_is_deterministic() {
        let shared = fixed_shared_point();
        let ctx = [Fq::from(1u64), Fq::from(2u64)];
        let k1 = derive(&shared, &ctx).expect("ok");
        let k2 = derive(&shared, &ctx).expect("ok");
        assert_eq!(k1, k2);
    }

    /// Domain separation by role tag: different first context element
    /// → different key. The protocol's load-bearing property — this
    /// is how two roles (cipher key, MAC key) share an ECDH secret
    /// without one leaking the other.
    #[test]
    fn derive_separates_roles() {
        let shared = fixed_shared_point();
        let envelope_id = Fq::from(42u64);
        let key_enc = derive(&shared, &[Fq::from(0u64), envelope_id]).expect("ok");
        let key_mac = derive(&shared, &[Fq::from(1u64), envelope_id]).expect("ok");
        assert_ne!(key_enc, key_mac);
    }

    /// Different shared points → different keys (even with identical
    /// context). Without this, the ECDH input wouldn't be entering
    /// the derivation.
    #[test]
    fn derive_separates_shared_points() {
        let mut seed_a = [0u8; 64];
        seed_a[0] = 1;
        let mut seed_b = [0u8; 64];
        seed_b[0] = 2;
        let mut seed_c = [0u8; 64];
        seed_c[0] = 3;
        let (sk_a, _) = keypair_from_seed(&Seed::from_bytes(seed_a));
        let (_, pk_b) = keypair_from_seed(&Seed::from_bytes(seed_b));
        let (_, pk_c) = keypair_from_seed(&Seed::from_bytes(seed_c));

        let shared_ab = shared_secret(&sk_a, &pk_b);
        let shared_ac = shared_secret(&sk_a, &pk_c);
        let ctx = [Fq::from(0u64), Fq::from(42u64)];

        let k_ab = derive(&shared_ab, &ctx).expect("ok");
        let k_ac = derive(&shared_ac, &ctx).expect("ok");
        assert_ne!(k_ab, k_ac);
    }

    /// Empty context is well-defined: just `(shared.x, shared.y)` go
    /// in. Useful as a "no binding" baseline. Distinct from any
    /// context with elements.
    #[test]
    fn derive_with_empty_context_is_well_defined() {
        let shared = fixed_shared_point();
        let k_empty = derive(&shared, &[]).expect("empty is in range");
        let k_one = derive(&shared, &[Fq::from(0u64)]).expect("ok");
        assert_ne!(k_empty, k_one);
    }

    /// Context length cap: `MAX_CONTEXT_LEN = 9` fits, 10 errors.
    /// Pins the boundary at the arity ceiling.
    #[test]
    fn derive_respects_context_length_cap() {
        let shared = fixed_shared_point();
        let ctx_9: Vec<Fq> = (0u64..9).map(Fq::from).collect();
        let ctx_10: Vec<Fq> = (0u64..10).map(Fq::from).collect();
        assert!(derive(&shared, &ctx_9).is_ok(), "9-element context fits");
        assert!(
            matches!(
                derive(&shared, &ctx_10),
                Err(PoseidonError::ArityOutOfRange { total_arity: 13 })
            ),
            "10-element context must error (total arity 13 > 12)",
        );
    }
}
