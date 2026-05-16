//! Schnorr-style signatures over Baby Jubjub.
//!
//! Sign a *stream* of field elements with a Baby Jubjub keypair.
//! Verify with the matching public key. Composes the existing curve,
//! keypair, and Poseidon-hash-fixed bricks — no new primitives
//! required.
//!
//! ## Construction
//!
//! Sign `message ∈ F_p*` (a stream of at most `MAX_MESSAGE_LEN` field
//! elements) with secret key `sk` (public key `PK = sk · G`):
//!
//! ```text
//! m_hash      = Poseidon_hash_fixed(message_domain, message)
//! k           = Poseidon_hash_fixed(nonce_domain, [sk_as_fq, m_hash]) mod l
//! R           = k · G                                                     // commitment point
//! c           = Poseidon_hash_fixed(challenge_domain, [R.x, R.y, PK.x, PK.y, m_hash]) mod l
//! s           = k + c · sk    mod l
//! signature   = (R, s)
//! ```
//!
//! Verify `(R, s)` against `PK` and `message`:
//!
//! ```text
//! m_hash = Poseidon_hash_fixed(message_domain, message)
//! c      = Poseidon_hash_fixed(challenge_domain, [R.x, R.y, PK.x, PK.y, m_hash]) mod l
//! accept iff   s · G  ==  R + c · PK
//! ```
//!
//! ## Decisions baked in
//!
//! - **Sign a STREAM, not a single field element.** The protocol's
//!   payloads are stream-shaped (the encoding registry's universal
//!   currency); the signature primitive matches. A length-zero
//!   message is supported (signs only the empty hash); a single
//!   `&[m]` is the natural way to sign one field element.
//!
//! - **Hash-then-include.** The message stream is first hashed to a
//!   single field element via `poseidon_hash_fixed(message_domain,
//!   message)`, then that hash enters the nonce and challenge as a
//!   single field. The challenge hash itself stays at fixed arity 6
//!   (1 domain + 5 inputs) regardless of message length, which means
//!   a 9-field message and a 33-field message sign through the *same*
//!   circuit shape — only the message-hash witness changes. Two cheap
//!   Poseidon calls instead of one big one, and the in-circuit
//!   verifier is parametric in message length without changing
//!   constraint shape.
//!
//! - **Stream length capped at `MAX_MESSAGE_LEN = 11`.** Imposed by
//!   `poseidon_hash_fixed`'s arity ceiling (12 total = 1 domain + 11
//!   payload). Beyond that, a future variant would either chunk-and-
//!   chain the message hash or use sponge — both are different
//!   schemes and mint their own spec. Keeping this one ceiling-bound
//!   means the in-circuit hash is one permutation, no branching.
//!
//! - **Deterministic nonce** (RFC 6979 / BIP-340 style). `k` is
//!   derived from `sk` and the message hash via Poseidon with its own
//!   domain tag, *not* sampled randomly. Schnorr's nonce-reuse
//!   failure mode is catastrophic — two signatures sharing a nonce
//!   reveal `sk` instantly — so derandomising eliminates the entire
//!   failure class.
//!
//! - **Domain-separated everything.** Three distinct domain tags —
//!   `message_domain`, `nonce_domain`, `challenge_domain` — so each
//!   internal hash sits in its own slot. No hash output can be
//!   misused as another's, even given a collision in payload.
//!
//! - **`PK` in the challenge.** Standard Schnorr-with-key-prefixing
//!   to thwart related-key attacks. Same reasoning as BIP-340.
//!
//! ## Scope intentionally NOT in this brick
//!
//! - **Sign-arbitrary-bytes.** The caller hashes bytes to field
//!   elements (via an encoding from `crates/encodings/*`) and signs
//!   the resulting stream.
//! - **Long messages** (length > 11). A future
//!   `babyjub-schnorr-long` or similar mints a new spec and is built
//!   on a different message-hash construction (sponge, or chunked
//!   fixed-arity).
//! - **Batch verification.** A few-percent speedup at most for this
//!   small-arity curve, not worth the API complication right now.
//! - **`SecretKey: Zeroize`.** Tracked as a follow-up; will land
//!   before any production caller retains `sk`.
//! - **Signature serialization beyond `(R, s)` decimal strings.** No
//!   on-wire byte format yet; the wire form is the spec's
//!   decimal-string triple `(R.x, R.y, s)`.

use core::fmt;

use ark_ec::{twisted_edwards::Projective, CurveGroup};
use ark_ff::{BigInteger, PrimeField};

use crate::poseidon::{domain_tag, poseidon_hash_fixed};

use super::config::{EdwardsAffine, Fq, Fr};
use super::curve::{generator, mul};
use super::keypair::{PublicKey, SecretKey};

/// Domain tag for the message-hash that collapses a stream into one
/// field element before it enters the nonce and challenge inputs.
pub const MESSAGE_DOMAIN: &str = "babyjub-schnorr-message";

/// Domain tag for the deterministic nonce derivation. Changing it
/// changes which nonce a `(sk, message)` pair produces.
pub const NONCE_DOMAIN: &str = "babyjub-schnorr-nonce";

/// Domain tag for the challenge hash. Changing it changes every
/// signature.
pub const CHALLENGE_DOMAIN: &str = "babyjub-schnorr-challenge";

/// Maximum message-stream length this scheme accepts. Imposed by
/// `poseidon_hash_fixed`'s arity ceiling: 1 domain + 11 inputs = 12
/// total, which is the max width `light-poseidon` ships circomlib
/// parameters for. Longer messages would either need a different
/// message-hash construction (sponge) or chunking — both are different
/// schemes and would mint their own spec.
pub const MAX_MESSAGE_LEN: usize = 11;

/// Why a sign or verify call failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SchnorrError {
    /// The message stream exceeds [`MAX_MESSAGE_LEN`]. The protocol's
    /// stream-shaped encodings (`text-utf8-v1`: 9 fields) all fit
    /// well under this cap; a longer message wants a different
    /// scheme.
    MessageTooLong { len: usize, max: usize },
}

impl fmt::Display for SchnorrError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SchnorrError::MessageTooLong { len, max } => write!(
                f,
                "schnorr message stream length {len} exceeds the cap of {max}; \
                 use a different scheme for longer messages",
            ),
        }
    }
}

impl std::error::Error for SchnorrError {}

/// A Schnorr signature: commitment point `R` and response scalar `s`.
///
/// Both fields are public — there is no sensitive material in a
/// signature, only in the secret key that produced it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Signature {
    /// Commitment point `R = k · G`. Always in the prime-order
    /// subgroup by construction.
    pub r: EdwardsAffine,
    /// Response scalar `s = k + c · sk` in `F_l`.
    pub s: Fr,
}

/// Sign `message` with `sk`. Deterministic: the same `(sk, message)`
/// always produces the same signature.
///
/// Returns `Err(MessageTooLong)` if `message.len() > MAX_MESSAGE_LEN`.
pub fn sign(
    sk: &SecretKey,
    pk: &PublicKey,
    message: &[Fq],
) -> Result<Signature, SchnorrError> {
    // 1. Collapse the message stream into one field element via the
    //    message-domain Poseidon hash. Returns the typed length error
    //    if the stream is too long.
    let m_hash = message_hash(message)?;

    // 2. Deterministic nonce. Two inputs (sk-as-Fq, m_hash) under the
    //    nonce domain. Arity 3 total — no padding, no zero-filler.
    let sk_as_fq = fr_to_fq(sk.scalar());
    let k_fq = poseidon_hash_fixed(
        domain_tag(NONCE_DOMAIN),
        &[sk_as_fq, m_hash],
    )
    .expect("nonce hash arity 3 is in range");
    let k = fq_to_fr(&k_fq);

    // 3. Commitment R = k · G.
    let r = mul(&k, &generator());

    // 4. Challenge c = Poseidon(challenge_domain, R.x, R.y, PK.x, PK.y, m_hash),
    //    reduced into F_l for the scalar arithmetic.
    let c_fq = challenge_inner(&r, pk.point(), m_hash);
    let c = fq_to_fr(&c_fq);

    // 5. Response s = k + c · sk in F_l.
    let s = k + c * sk.scalar();

    Ok(Signature { r, s })
}

/// Verify `sig` against `pk` and `message`. Returns `Ok(true)` if the
/// signature is valid, `Ok(false)` if it is well-formed but invalid,
/// and `Err(MessageTooLong)` if `message.len() > MAX_MESSAGE_LEN`.
///
/// The error distinguishes "valid-but-bad signature" (a possible
/// attacker behavior) from "broken input" (a caller bug). Both yield
/// rejection but the failure modes are different.
pub fn verify(
    pk: &PublicKey,
    message: &[Fq],
    sig: &Signature,
) -> Result<bool, SchnorrError> {
    let m_hash = message_hash(message)?;

    let c_fq = challenge_inner(&sig.r, pk.point(), m_hash);
    let c = fq_to_fr(&c_fq);

    // s · G == R + c · PK in the group.
    let lhs = mul(&sig.s, &generator());
    let rhs = (Projective::from(sig.r) + Projective::from(mul(&c, pk.point()))).into_affine();
    Ok(lhs == rhs)
}

/// The message-hash. Collapses a stream of up to `MAX_MESSAGE_LEN`
/// field elements into one element via `poseidon_hash_fixed` under
/// the message domain. Returns the typed error if the stream is too
/// long.
///
/// A zero-length message hashes to `poseidon_hash_fixed(message_domain,
/// [])` — a well-defined per-domain constant. A single-element message
/// `&[m]` hashes to a domain-distinguished function of `m`, *not* to
/// `m` itself, which means a signature on `&[m]` is not equivalent to
/// a signature on the bare `m` from the previous scheme.
fn message_hash(message: &[Fq]) -> Result<Fq, SchnorrError> {
    if message.len() > MAX_MESSAGE_LEN {
        return Err(SchnorrError::MessageTooLong {
            len: message.len(),
            max: MAX_MESSAGE_LEN,
        });
    }
    Ok(poseidon_hash_fixed(domain_tag(MESSAGE_DOMAIN), message)
        .expect("message len ≤ MAX_MESSAGE_LEN, so total arity is in range"))
}

/// The challenge hash, shared between sign and verify. Takes the
/// commitment point `R`, the verifier's public key, and the
/// already-collapsed message hash, and returns a field element in
/// `F_p`.
///
/// Arity 6 (1 domain + 5 payload) — fixed regardless of message
/// length, by virtue of `message_hash` collapsing the message stream
/// to one element upstream.
fn challenge_inner(r: &EdwardsAffine, pk: &EdwardsAffine, m_hash: Fq) -> Fq {
    poseidon_hash_fixed(
        domain_tag(CHALLENGE_DOMAIN),
        &[r.x, r.y, pk.x, pk.y, m_hash],
    )
    .expect("challenge hash arity 6 is in range")
}

/// Reinterpret an `F_l` scalar in `F_p`. The scalar field order `l`
/// (~251 bits) fits inside the base field `p` (~254 bits), so the
/// reinterpretation is lossless.
fn fr_to_fq(fr: &Fr) -> Fq {
    Fq::from_le_bytes_mod_order(&fr.into_bigint().to_bytes_le())
}

/// Reduce an `F_p` element into `F_l`. The bias from `p` (254 bits)
/// to `l` (251 bits) on Poseidon-uniform input is ~2⁻²⁵¹, far below
/// cryptographic relevance.
fn fq_to_fr(fq: &Fq) -> Fr {
    Fr::from_le_bytes_mod_order(&fq.into_bigint().to_bytes_le())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::babyjub::{is_in_prime_subgroup, keypair_from_seed, Seed};

    fn fixed_keypair() -> (SecretKey, PublicKey) {
        let mut seed = [0u8; 64];
        seed[0] = 7;
        keypair_from_seed(&Seed::from_bytes(seed))
    }

    /// Sign-then-verify on a valid keypair and a non-empty message
    /// accepts. The bread-and-butter property.
    #[test]
    fn sign_then_verify_accepts() {
        let (sk, pk) = fixed_keypair();
        let m = [Fq::from(1u64), Fq::from(2u64), Fq::from(3u64)];
        let sig = sign(&sk, &pk, &m).expect("valid length");
        assert!(verify(&pk, &m, &sig).expect("valid length"));
    }

    /// Sign-then-verify on the empty message also accepts. Length-zero
    /// is a well-defined message in this scheme.
    #[test]
    fn sign_then_verify_accepts_empty_message() {
        let (sk, pk) = fixed_keypair();
        let sig = sign(&sk, &pk, &[]).expect("empty is valid");
        assert!(verify(&pk, &[], &sig).expect("empty is valid"));
    }

    /// Determinism: same `(sk, message)` produces the exact same
    /// signature. Load-bearing for the deterministic-nonce design.
    #[test]
    fn signatures_are_deterministic() {
        let (sk, pk) = fixed_keypair();
        let m = [Fq::from(42u64), Fq::from(99u64)];
        let s1 = sign(&sk, &pk, &m).expect("ok");
        let s2 = sign(&sk, &pk, &m).expect("ok");
        assert_eq!(s1, s2);
    }

    /// Different messages → different signatures.
    #[test]
    fn different_messages_yield_different_signatures() {
        let (sk, pk) = fixed_keypair();
        let s1 = sign(&sk, &pk, &[Fq::from(1u64)]).expect("ok");
        let s2 = sign(&sk, &pk, &[Fq::from(2u64)]).expect("ok");
        assert_ne!(s1.r, s2.r);
        assert_ne!(s1.s, s2.s);
    }

    /// Different message *lengths* with overlapping content → different
    /// signatures. Catches a degenerate scheme that would ignore length
    /// (e.g. if the message hash were `Σ` or `XOR` of the elements).
    #[test]
    fn different_message_lengths_yield_different_signatures() {
        let (sk, pk) = fixed_keypair();
        let s1 = sign(&sk, &pk, &[Fq::from(1u64)]).expect("ok");
        let s2 = sign(&sk, &pk, &[Fq::from(1u64), Fq::from(0u64)]).expect("ok");
        assert_ne!(s1, s2);
    }

    /// `R` is in the prime-order subgroup.
    #[test]
    fn r_lives_in_prime_subgroup() {
        let (sk, pk) = fixed_keypair();
        let sig = sign(&sk, &pk, &[Fq::from(99u64)]).expect("ok");
        assert!(is_in_prime_subgroup(&sig.r));
    }

    /// Tamper with the message: verification rejects.
    #[test]
    fn tampered_message_is_rejected() {
        let (sk, pk) = fixed_keypair();
        let m = [Fq::from(10u64), Fq::from(20u64)];
        let m2 = [Fq::from(10u64), Fq::from(21u64)];
        let sig = sign(&sk, &pk, &m).expect("ok");
        assert!(!verify(&pk, &m2, &sig).expect("ok"));
    }

    /// Tamper with the response scalar `s`: verification rejects.
    #[test]
    fn tampered_s_is_rejected() {
        let (sk, pk) = fixed_keypair();
        let m = [Fq::from(10u64)];
        let mut sig = sign(&sk, &pk, &m).expect("ok");
        sig.s += Fr::from(1u64);
        assert!(!verify(&pk, &m, &sig).expect("ok"));
    }

    /// Tamper with the commitment point `R`: verification rejects.
    /// Use `2 · R` so the tampered point stays in the subgroup —
    /// rules out a "rejected because off-subgroup" false positive.
    #[test]
    fn tampered_r_is_rejected() {
        let (sk, pk) = fixed_keypair();
        let m = [Fq::from(10u64)];
        let sig = sign(&sk, &pk, &m).expect("ok");
        let tampered = Signature {
            r: mul(&Fr::from(2u64), &sig.r),
            s: sig.s,
        };
        assert!(!verify(&pk, &m, &tampered).expect("ok"));
    }

    /// Wrong public key: verification rejects.
    #[test]
    fn verification_under_wrong_pk_is_rejected() {
        let (sk, pk) = fixed_keypair();
        let m = [Fq::from(10u64)];
        let sig = sign(&sk, &pk, &m).expect("ok");

        let mut other_seed = [0u8; 64];
        other_seed[0] = 99;
        let (_, other_pk) = keypair_from_seed(&Seed::from_bytes(other_seed));
        assert!(!verify(&other_pk, &m, &sig).expect("ok"));
    }

    /// A maximum-length message (11 elements) signs and verifies.
    /// Pins the edge of the allowed range.
    #[test]
    fn max_length_message_signs_and_verifies() {
        let (sk, pk) = fixed_keypair();
        let m: Vec<Fq> = (1u64..=11).map(Fq::from).collect();
        let sig = sign(&sk, &pk, &m).expect("11 elements is at the cap");
        assert!(verify(&pk, &m, &sig).expect("ok"));
    }

    /// A 12-element message exceeds the cap; both sign and verify
    /// return the typed length error. Catches the boundary.
    #[test]
    fn over_length_message_is_rejected_by_typed_error() {
        let (sk, pk) = fixed_keypair();
        let m: Vec<Fq> = (1u64..=12).map(Fq::from).collect();
        assert!(matches!(
            sign(&sk, &pk, &m),
            Err(SchnorrError::MessageTooLong { len: 12, max: 11 }),
        ));
        // Use a known-good signature on a different message just to
        // populate the `sig` argument; verify still errors on the
        // length check before any signature math.
        let good_sig = sign(&sk, &pk, &[]).expect("empty fits");
        assert!(matches!(
            verify(&pk, &m, &good_sig),
            Err(SchnorrError::MessageTooLong { len: 12, max: 11 }),
        ));
    }
}
