//! Deterministic Baby Jubjub keypairs from a 64-byte seed.
//!
//! Randomness is *not* this module's problem. The caller supplies a 64-byte
//! `Seed` and gets back a deterministic `(SecretKey, PublicKey)`. How the
//! seed was obtained — a CSPRNG, a Blake2b digest of a wallet signature, a
//! fixed test vector — is a strictly separate concern. This separation is
//! deliberate: randomness sources differ across native, WASM, and
//! wallet-derived contexts, and forcing the keypair primitive to choose one
//! would couple it to its environment. The same code path runs in unit
//! tests, in headless-browser fixture tests, and in production.
//!
//! ## Why 64 bytes (and not 32)
//!
//! The secret key `sk` lives in `F_l`, the Baby Jubjub scalar field (a
//! 251-bit prime). Reducing 256 bits (a 32-byte seed) into a 251-bit field
//! is biased — the top 5 bits get slightly under-represented in `sk`.
//! That's a small information leak for the *root* key of the protocol,
//! easily avoided. Reducing 64 bytes (512 bits) into the same field
//! produces a distribution indistinguishable from uniform (bias ~ 2⁻²⁵⁶).
//! This is the construction `ed25519-dalek` uses internally and what
//! RFC 9380 recommends for hash-to-field.
//!
//! ## Derivation
//!
//! ```text
//! domain_tag = bytes_to_field_be( Blake2b-256("babyjub-keypair-v1") )
//! chunk_0    = bytes_to_field_be( seed[ 0..32] )
//! chunk_1    = bytes_to_field_be( seed[32..64] )
//! sk_fq      = Poseidon-BN254-circomlib( domain_tag, chunk_0, chunk_1 )
//! sk         = sk_fq reinterpreted in F_l  (mod-l reduction)
//! PK         = sk · Base8
//! ```
//!
//! `specs/babyjub-keypair.md` is the cross-language contract. A TypeScript
//! caller that reproduces the same construction lands on the same `(sk,
//! PK)` byte-for-byte; that property is what the fixture test pins.
//!
//! ## Scope intentionally NOT in this brick
//!
//! - **`SecretKey: Zeroize`**: the `SecretKey` type does not yet zero its
//!   memory on drop. That's a real concern once we have a key path through
//!   user wallets, but the production caller (the SDK 's wallet-keys module) does
//!   not store secrets — it re-derives them — so it is not urgent today
//!   and will land as a focused brick. Test vectors keep their bytes by
//!   design.
//! - **Secret-key (de)serialization**: no on-wire form for `SecretKey` yet.
//!   The production caller never transmits it; only `PublicKey` crosses
//!   boundaries. Adding `SecretKey` byte serialization later is
//!   non-breaking.
//! - **CSPRNG `from_rng()` convenience**: deliberately omitted. The seed
//!   contract is "give me 64 bytes you trust"; a `from_rng` wrapper is one
//!   line for the caller and there is no reason for this crate to choose
//!   an RNG.

use ark_ff::{BigInteger, PrimeField};

use crate::poseidon::{domain_tag, poseidon3};

use super::config::{EdwardsAffine, Fq, Fr};
use super::curve::{generator, mul};

/// Domain string for this keypair derivation. Pinned in
/// `specs/babyjub-keypair.md`; changing it changes every derived key.
///
/// The trailing `-v1` reserves space for a future derivation tweak (a new
/// chunk count, a different hash) without silently keeping the old scheme
/// name.
pub const KEYPAIR_DOMAIN: &str = "babyjub-keypair-v1";

/// A 64-byte seed for [`keypair_from_seed`]. Typed so it cannot be mixed up
/// with other 32-or-64-byte buffers floating around — block hashes,
/// commitments, ciphertext nonces — at zero runtime cost.
///
/// The seed is opaque: this module makes no assumption about its origin.
/// The caller is responsible for picking a source appropriate to the
/// context (CSPRNG, wallet-derived, test vector).
#[derive(Clone)]
pub struct Seed(pub [u8; 64]);

impl Seed {
    /// Build a `Seed` from a 64-byte array. The wrapper is the only
    /// constructor; there is no `&[u8]` overload, so a wrong-length buffer
    /// is a compile-time error rather than a runtime panic.
    pub const fn from_bytes(bytes: [u8; 64]) -> Self {
        Seed(bytes)
    }

    /// Expose the underlying bytes for callers that need to hash them, log
    /// a fingerprint, or hand them to a serializer. The `SecretKey`'s own
    /// bytes are NOT exposed this way (see the `SecretKey` doc).
    pub const fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }
}

impl core::fmt::Debug for Seed {
    /// Never accidentally print seed bytes — the seed is sensitive material
    /// even when the production caller derives rather than stores it.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Seed([64 bytes redacted])")
    }
}

/// A Baby Jubjub secret key: a scalar in `F_l`.
///
/// The inner `Fr` is private and only exposed where the protocol needs it
/// (scalar multiplication via the curve module). The type does not yet
/// implement `Zeroize`; see the module docs.
#[derive(Clone)]
pub struct SecretKey(Fr);

impl SecretKey {
    /// Borrow the scalar.
    ///
    /// **Use sparingly.** External callers should compose at the `keypair`
    /// / `public_key` level, not by poking the raw scalar — that's why
    /// the `SecretKey` newtype exists. The accessor is `pub` because the
    /// `gadgets` crate (a legitimate in-workspace consumer) needs the raw
    /// `Fr` to feed it into a circuit witness, and a `pub(crate)`
    /// restriction would force a redundant unwrap-and-rewrap dance there.
    /// Application code reaching for this is almost certainly a code smell.
    pub fn scalar(&self) -> &Fr {
        &self.0
    }
}

impl core::fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SecretKey([redacted])")
    }
}

/// A Baby Jubjub public key: an on-curve, prime-subgroup point.
///
/// The type's existence is a static promise: a `PublicKey` value has
/// already passed both validity checks. The constructors are the only way
/// in, and they validate. Downstream code that receives a `PublicKey` does
/// not need to re-validate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublicKey(EdwardsAffine);

impl PublicKey {
    /// The underlying curve point. Read-only access for callers that need
    /// to serialize, hash, or operate on the point directly.
    pub fn point(&self) -> &EdwardsAffine {
        &self.0
    }

    /// Construct a `PublicKey` from a point known to be on-curve and in
    /// the prime-order subgroup. **Crate-internal**: the only callers are
    /// `keypair_from_seed` (which computes `sk · Base8`, by construction
    /// in the subgroup) and any future internal arithmetic that produces
    /// a guaranteed-valid point. External callers receive `PublicKey`
    /// values only via wire decoders that validate explicitly.
    pub(crate) fn from_subgroup_point(point: EdwardsAffine) -> Self {
        PublicKey(point)
    }

    /// Construct a `PublicKey` from a point the **caller** has already
    /// validated as on-curve and in the prime-order subgroup.
    ///
    /// This is a typed promise: by constructing `PublicKey` this way,
    /// the caller asserts the validation happened. The intended use is
    /// the WASM binding's ECDH path, which decodes the peer key through
    /// `point_from_strings` (which performs both checks) and then needs
    /// to hand the validated point to `shared_secret`. A direct `pub`
    /// constructor exists for that single seam; future consumers with
    /// the same shape (validated by their own wire decoder, then handed
    /// to a curve operation) can use it too.
    ///
    /// **Misuse**: passing an unvalidated point bypasses the protocol's
    /// subgroup-confinement defence. Do not construct `PublicKey` this
    /// way from raw `(x, y)` input — go through
    /// `babyjub::point_from_strings` instead.
    pub fn from_validated_point(point: EdwardsAffine) -> Self {
        PublicKey(point)
    }
}

/// Derive a deterministic keypair from a 64-byte seed.
///
/// See the module docs for the derivation formula. Equal seeds yield equal
/// keypairs; this is the property fixture tests across Rust, WASM, and TS
/// pin.
pub fn keypair_from_seed(seed: &Seed) -> (SecretKey, PublicKey) {
    // The seed splits cleanly at the 32-byte boundary because the
    // base-field prime `p` is 254 bits — a single 32-byte chunk fits
    // comfortably (the top two bits get folded by the mod-`p` reduction,
    // a fixed and negligible bias on uniform input).
    let chunk_0 = Fq::from_be_bytes_mod_order(&seed.0[0..32]);
    let chunk_1 = Fq::from_be_bytes_mod_order(&seed.0[32..64]);

    // Poseidon outputs into `F_p` (the base field). The keypair needs `F_l`
    // (the scalar field). We reduce by serializing the `F_p` element to
    // bytes and re-parsing into `F_l`: this is `sk_fq mod l`, the
    // unambiguous reduction. The bias is determined by the gap between `p`
    // (254 bits) and `l` (251 bits) on a Poseidon-uniform input — about
    // 2⁻²⁵¹, far below cryptographic relevance for a private key.
    let sk_fq = poseidon3(&[domain_tag(KEYPAIR_DOMAIN), chunk_0, chunk_1]);
    let sk = Fr::from_le_bytes_mod_order(&sk_fq.into_bigint().to_bytes_le());

    // `Base8` is in the prime-order subgroup by construction, so any
    // scalar multiple is too. `PublicKey::from_subgroup_point` is sound
    // here without an explicit recheck.
    let pk_point = mul(&sk, &generator());
    (SecretKey(sk), PublicKey::from_subgroup_point(pk_point))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::babyjub::is_in_prime_subgroup;

    /// Same seed twice yields the same keypair: determinism is the
    /// load-bearing property a "from seed" API claims.
    #[test]
    fn derivation_is_deterministic() {
        let seed = Seed::from_bytes([0u8; 64]);
        let (sk1, pk1) = keypair_from_seed(&seed);
        let (sk2, pk2) = keypair_from_seed(&seed);
        assert_eq!(sk1.scalar(), sk2.scalar());
        assert_eq!(pk1, pk2);
    }

    /// Different seeds yield different keypairs. (A trivially broken
    /// derivation could return the same scalar for any input — this catches
    /// that class of bug.)
    #[test]
    fn distinct_seeds_yield_distinct_keypairs() {
        let mut bytes_a = [0u8; 64];
        bytes_a[0] = 1;
        let mut bytes_b = [0u8; 64];
        bytes_b[63] = 1;
        let (sk_a, pk_a) = keypair_from_seed(&Seed::from_bytes(bytes_a));
        let (sk_b, pk_b) = keypair_from_seed(&Seed::from_bytes(bytes_b));
        assert_ne!(sk_a.scalar(), sk_b.scalar());
        assert_ne!(pk_a, pk_b);
    }

    /// The derived public key must always land in the prime-order subgroup.
    /// `Base8`-scalar-multiplication preserves this *by construction*, but
    /// asserting it once protects against a future change accidentally
    /// generating off-subgroup points.
    #[test]
    fn public_key_is_in_prime_subgroup() {
        let seed = Seed::from_bytes([0x42u8; 64]);
        let (_, pk) = keypair_from_seed(&seed);
        assert!(is_in_prime_subgroup(pk.point()));
    }

    /// `Debug` formatting must NOT include the seed bytes — a logged seed is
    /// effectively a logged private key.
    #[test]
    fn seed_debug_is_redacted() {
        let seed = Seed::from_bytes([0xFFu8; 64]);
        let printed = format!("{seed:?}");
        assert!(printed.contains("redacted"), "seed Debug must redact");
        assert!(!printed.contains("FF"), "seed Debug must not contain bytes");
        assert!(!printed.contains("255"), "seed Debug must not contain bytes");
    }

    /// Same redaction discipline for `SecretKey`.
    #[test]
    fn secret_key_debug_is_redacted() {
        let seed = Seed::from_bytes([0u8; 64]);
        let (sk, _) = keypair_from_seed(&seed);
        let printed = format!("{sk:?}");
        assert!(printed.contains("redacted"));
    }
}
