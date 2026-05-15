//! Schnorr-style signatures over Baby Jubjub.
//!
//! Sign a single field element with a Baby Jubjub keypair. Verify with
//! the matching public key. Composes the existing curve, keypair, and
//! Poseidon bricks — no new primitives required.
//!
//! ## Construction
//!
//! Sign `m ∈ F_p` with secret key `sk` (public key `PK = sk · G`):
//!
//! ```text
//! k          = Poseidon6(nonce_domain, sk_as_fq, m, 0, 0, 0) mod l
//! R          = k · G                                              // commitment point
//! c_fq       = Poseidon6(challenge_domain, R.x, R.y, PK.x, PK.y, m)
//! c          = c_fq mod l                                         // scalar in F_l
//! s          = k + c · sk    mod l                                // response scalar
//! signature  = (R, s)
//! ```
//!
//! Verify `(R, s)` against `PK` and `m`:
//!
//! ```text
//! c = Poseidon6(challenge_domain, R.x, R.y, PK.x, PK.y, m) mod l
//! accept iff   s · G  ==  R + c · PK
//! ```
//!
//! ## Decisions baked in
//!
//! - **Deterministic nonce** (RFC 6979 style). `k` is derived from `sk`
//!   and `m` via Poseidon with its own domain tag, *not* sampled
//!   randomly. Schnorr's nonce-reuse failure mode is catastrophic — two
//!   signatures sharing a nonce reveal `sk` instantly — so derandomising
//!   eliminates the entire failure class. Matches Ed25519 / BIP-340
//!   modern practice.
//! - **Signs ONE field element, not arbitrary bytes.** The composition
//!   "hash bytes to a field element first, then sign" is the caller's
//!   job; it has its own encoding decisions (chunking, length, domain)
//!   that don't belong in the signature primitive.
//! - **Domain-separated challenge.** `Poseidon6(challenge_domain, R, PK,
//!   m)` — the domain tag prevents the same Poseidon hash from being
//!   used as both a signature challenge and, say, a commitment input,
//!   even if the other inputs collide.
//! - **`PK` in the challenge.** Standard Schnorr-with-key-prefixing —
//!   prevents a class of related-key attacks where an attacker tries to
//!   reuse a signature under a different public key. BIP-340 does this
//!   too.
//!
//! ## Scope intentionally NOT in this brick
//!
//! - **Sign-arbitrary-bytes.** Future composition; the caller chooses the
//!   byte → field encoding for their context.
//! - **Batch verification.** A few-percent speedup at most for this
//!   small-arity curve, not worth the API complication right now.
//! - **`SecretKey: Zeroize`.** Same deferral as the keypair brick —
//!   tracked, will land before any production caller retains `sk`.
//! - **Signature serialization beyond `(R, s)` decimal strings.** No
//!   on-wire byte format yet; the wire form is the spec's decimal-string
//!   triple `(R.x, R.y, s)`.

use ark_ec::{twisted_edwards::Projective, CurveGroup};
use ark_ff::{BigInteger, PrimeField};
use ark_std::Zero;

use crate::poseidon::{domain_tag, poseidon6};

use super::config::{EdwardsAffine, Fq, Fr};
use super::curve::{generator, mul};
use super::keypair::{PublicKey, SecretKey};

/// Domain tag for the challenge hash. Pinned in
/// `specs/babyjub-schnorr.md`; changing it changes every signature.
pub const CHALLENGE_DOMAIN: &str = "babyjub-schnorr-challenge-v1";

/// Domain tag for the deterministic nonce derivation. Pinned in the
/// spec; changing it changes which nonce a `(sk, m)` pair produces.
pub const NONCE_DOMAIN: &str = "babyjub-schnorr-nonce-v1";

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

/// Sign `m` with `sk`. Deterministic: the same `(sk, m)` always
/// produces the same signature.
pub fn sign(sk: &SecretKey, pk: &PublicKey, m: Fq) -> Signature {
    // 1. Derive the nonce `k` deterministically. We hash `sk` (in F_l)
    //    into the F_p input by serializing its bytes and re-parsing
    //    into F_p — same boundary trick the keypair derivation uses.
    //    Pad to arity-6 with zeros: arity-6 is the only `poseidon` we
    //    expose (Schnorr also uses it for the challenge), so reusing it
    //    keeps the binary surface small. Padding is fine: the domain
    //    tag distinguishes this hash from the challenge hash, so a
    //    collision in the padding positions cannot induce a collision
    //    across the two uses.
    let sk_as_fq = fr_to_fq(sk.scalar());
    let k_fq = poseidon6(&[
        domain_tag(NONCE_DOMAIN),
        sk_as_fq,
        m,
        Fq::zero(),
        Fq::zero(),
        Fq::zero(),
    ]);
    let k = fq_to_fr(&k_fq);

    // 2. Commitment R = k · G.
    let r = mul(&k, &generator());

    // 3. Challenge c = Poseidon(challenge_domain, R, PK, m), reduced
    //    into F_l for the scalar arithmetic.
    let c_fq = challenge_inner(&r, pk.point(), m);
    let c = fq_to_fr(&c_fq);

    // 4. Response s = k + c · sk in F_l.
    let s = k + c * sk.scalar();

    Signature { r, s }
}

/// Verify `sig` against `pk` and `m`. Returns `true` iff the signature
/// is valid.
pub fn verify(pk: &PublicKey, m: Fq, sig: &Signature) -> bool {
    // Recompute the challenge from the public values only — no secret
    // input crosses this function.
    let c_fq = challenge_inner(&sig.r, pk.point(), m);
    let c = fq_to_fr(&c_fq);

    // Check s · G == R + c · PK in the group. Done in projective
    // coordinates because group addition is cheaper there; converted to
    // affine once for the equality test.
    let lhs = mul(&sig.s, &generator());
    let rhs = (Projective::from(sig.r) + Projective::from(mul(&c, pk.point()))).into_affine();
    lhs == rhs
}

/// The challenge hash, shared between sign and verify. Takes the
/// commitment point `R`, the verifier's public key, and the signed
/// message field element, and returns a field element in `F_p`.
///
/// `R` and `PK` are decomposed into their affine `(x, y)` coordinates
/// — this is what circom-side Schnorr verifiers expect to see in their
/// constraint systems too, so the on-chain / in-circuit story stays
/// straightforward.
fn challenge_inner(r: &EdwardsAffine, pk: &EdwardsAffine, m: Fq) -> Fq {
    poseidon6(&[
        domain_tag(CHALLENGE_DOMAIN),
        r.x,
        r.y,
        pk.x,
        pk.y,
        m,
    ])
}

/// Reinterpret an `F_l` scalar in `F_p`. The scalar field order `l`
/// (~251 bits) fits inside the base field `p` (~254 bits), so the
/// reinterpretation is lossless: the same integer just lives in a
/// larger field.
fn fr_to_fq(fr: &Fr) -> Fq {
    Fq::from_le_bytes_mod_order(&fr.into_bigint().to_bytes_le())
}

/// Reduce an `F_p` element into `F_l`. Used to fold a Poseidon output
/// (in `F_p`) into a scalar suitable for scalar multiplication. The
/// bias from this 254→251-bit reduction is ~2⁻²⁵¹ on Poseidon-uniform
/// input — far below cryptographic relevance.
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

    /// The bread-and-butter test: sign-then-verify on a valid keypair
    /// and message must accept.
    #[test]
    fn sign_then_verify_accepts() {
        let (sk, pk) = fixed_keypair();
        let m = Fq::from(123456u64);
        let sig = sign(&sk, &pk, m);
        assert!(verify(&pk, m, &sig));
    }

    /// Determinism: same `(sk, m)` produces the exact same signature.
    /// The load-bearing property of the deterministic-nonce design — if
    /// this ever fails, nonce-reuse vulnerabilities walk in immediately.
    #[test]
    fn signatures_are_deterministic() {
        let (sk, pk) = fixed_keypair();
        let m = Fq::from(42u64);
        let s1 = sign(&sk, &pk, m);
        let s2 = sign(&sk, &pk, m);
        assert_eq!(s1, s2);
    }

    /// Different messages → different signatures (different `R` and
    /// different `s`). Catches a degenerate construction that doesn't
    /// actually bind the message.
    #[test]
    fn different_messages_yield_different_signatures() {
        let (sk, pk) = fixed_keypair();
        let s1 = sign(&sk, &pk, Fq::from(1u64));
        let s2 = sign(&sk, &pk, Fq::from(2u64));
        assert_ne!(s1.r, s2.r, "different m must yield different R");
        assert_ne!(s1.s, s2.s, "different m must yield different s");
    }

    /// `R` is in the prime-order subgroup. Follows from `R = k · G`
    /// where `G` is `Base8`; pinning it as a runtime check catches any
    /// future refactor that produces off-subgroup commitments.
    #[test]
    fn r_lives_in_prime_subgroup() {
        let (sk, pk) = fixed_keypair();
        let sig = sign(&sk, &pk, Fq::from(99u64));
        assert!(is_in_prime_subgroup(&sig.r));
    }

    /// Tamper with the message: verification must reject.
    #[test]
    fn tampered_message_is_rejected() {
        let (sk, pk) = fixed_keypair();
        let m = Fq::from(10u64);
        let sig = sign(&sk, &pk, m);
        assert!(!verify(&pk, Fq::from(11u64), &sig));
    }

    /// Tamper with the response scalar `s`: verification must reject.
    #[test]
    fn tampered_s_is_rejected() {
        let (sk, pk) = fixed_keypair();
        let m = Fq::from(10u64);
        let mut sig = sign(&sk, &pk, m);
        sig.s += Fr::from(1u64);
        assert!(!verify(&pk, m, &sig));
    }

    /// Tamper with the commitment point `R`: verification must reject.
    /// We use `2 · R` as a deterministic tamper — guaranteed in the
    /// subgroup so it can't be rejected by a future on-the-wire
    /// subgroup check ahead of verification.
    #[test]
    fn tampered_r_is_rejected() {
        let (sk, pk) = fixed_keypair();
        let m = Fq::from(10u64);
        let sig = sign(&sk, &pk, m);
        let tampered_r = mul(&Fr::from(2u64), &sig.r);
        let tampered = Signature {
            r: tampered_r,
            s: sig.s,
        };
        assert!(!verify(&pk, m, &tampered));
    }

    /// Wrong public key: verification must reject. (Otherwise the
    /// signature isn't actually binding the signer.)
    #[test]
    fn verification_under_wrong_pk_is_rejected() {
        let (sk, pk) = fixed_keypair();
        let m = Fq::from(10u64);
        let sig = sign(&sk, &pk, m);

        let mut other_seed = [0u8; 64];
        other_seed[0] = 99;
        let (_, other_pk) = keypair_from_seed(&Seed::from_bytes(other_seed));
        assert!(!verify(&other_pk, m, &sig));
    }
}
