//! In-circuit Baby Jubjub Schnorr signature verification.
//!
//! Mirrors `crypto::babyjub::schnorr::verify` against the circuit
//! world. The native equation:
//!
//! ```text
//! m_hash = poseidon_hash_fixed(message_domain, message)
//! c_fq   = poseidon_hash_fixed(challenge_domain, [R.x, R.y, PK.x, PK.y, m_hash])
//! c_fr   = c_fq mod l
//! accept iff   s · G  ==  R + c · PK
//! ```
//!
//! The gadget enforces the acceptance equation as a circuit
//! constraint. There is no returned boolean: a circuit using
//! `verify_var` for an unsatisfiable signature will produce a
//! constraint system that does not satisfy.
//!
//! ## What this gadget is FOR
//!
//! Standalone verification is wasted constraints — the verifier
//! sees the message, R, s, and PK directly, so native verify is
//! cheaper. The in-circuit version unlocks **compositions**:
//!
//! - **"I have a Schnorr signature from a member of this set."**
//!   The signer's `PK` is a witness, plus a Merkle-membership
//!   proof against a public root.
//! - **"I signed a message whose content stays hidden."** The
//!   message is a witness, plus a commitment to it that the
//!   verifier sees.
//! - **"I hold a signature on a value committed in this Pedersen
//!   commitment."** Composes `verify_var` with `commit_var`.
//!
//! In all three, the public input is some derived value (a root,
//! a commitment, a hash) and the signature itself is the
//! witness-side credential.
//!
//! ## Why no `sign_var`
//!
//! In-circuit signing would require the secret key as a witness
//! and a deterministic-nonce derivation in-circuit. The latter
//! is straightforward (`poseidon_hash_fixed_var` on
//! `[sk, m_hash]`); the former turns the proof itself into a
//! signing oracle for the prover's key. That's a worse property
//! than "the verifier can reconstruct what the prover signed"
//! offers — every real use case is "I, the prover, hold a
//! signature; convince the verifier I do without revealing
//! something." So we ship verify_var only. A consumer that
//! genuinely needs in-circuit signing can add it later as a
//! separate brick.

use ark_ed_on_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::boolean::Boolean;
use ark_r1cs_std::convert::ToBitsGadget;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::fields::FieldVar;
use ark_r1cs_std::groups::CurveVar;
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};

use crypto::babyjub::Fq;
use crypto::babyjub::{CHALLENGE_DOMAIN, MESSAGE_DOMAIN};
use crypto::poseidon::domain_tag;

use super::{generator_constant, BabyJubAffineVar};
use crate::poseidon::poseidon_hash_fixed_var;

/// Compute the Schnorr message-hash in-circuit. Mirrors the
/// private `message_hash` helper in `crypto::babyjub::schnorr`.
///
/// One `poseidon_hash_fixed_var` call under the
/// `babyjub-schnorr-message` domain tag. The message stream is
/// generic over `const M: usize` because — like Pedersen — the
/// circuit must pin its length at design time.
///
/// `M` must satisfy `1 + M ≤ 12`, i.e. `M ≤ 11`, matching the
/// native `MAX_MESSAGE_LEN`. Larger messages require a different
/// signing scheme (sponge-based, or chunked); see the native
/// module's "Scope intentionally NOT in this brick" section.
///
/// **Why expose this as its own function:** circuits that bind
/// the signed message to a commitment, an encryption, or some
/// other downstream object want to compute `m_hash` once and
/// reuse it for both the binding and the verification.
pub fn message_hash_var<const M: usize>(
    cs: ConstraintSystemRef<Fq>,
    message: &[FpVar<Fq>; M],
) -> Result<FpVar<Fq>, SynthesisError> {
    let tag = FpVar::<Fq>::constant(domain_tag(MESSAGE_DOMAIN));
    poseidon_hash_fixed_var(cs, &tag, message)
}

/// In-circuit Schnorr verification. Enforces:
///
/// ```text
///     s · G  ==  R + c · PK
/// ```
///
/// where `c = poseidon_hash_fixed(challenge_domain, [R.x, R.y,
/// PK.x, PK.y, message_hash_var(message)])`, mod `l` (implicit via
/// the bit decomposition feeding scalar-mul on `PK`, which has
/// order `l`).
///
/// Returns `Ok(())` on successful constraint construction.
/// Verification ACCEPTANCE is a constraint assertion — a circuit
/// that calls `verify_var(...).unwrap()` for an invalid signature
/// will succeed at constraint construction but
/// `cs.is_satisfied()` will return `false`.
///
/// `pk`, `r` are curve gadget points (typically witnesses).
/// `message` is the stream, fixed at length `M`. `s` is the
/// signature's response scalar, allocated as bits inside the
/// gadget.
///
/// ## Subgroup-membership caveat
///
/// Soundness depends on `pk` and `r` being in the prime-order
/// subgroup. The native side enforces this at the wire decoder.
/// In-circuit, if `pk` or `r` come from a witness without
/// subgroup-check constraints, a malicious prover could supply
/// a point of small order and forge verification. Add a
/// subgroup-check gadget at the call site when the points come
/// from untrusted sources. (That gadget is not yet built; file
/// a TODO at the call site until it lands.)
pub fn verify_var<const M: usize>(
    cs: ConstraintSystemRef<Fq>,
    pk: &BabyJubAffineVar,
    message: &[FpVar<Fq>; M],
    r: &BabyJubAffineVar,
    s: Fr,
) -> Result<(), SynthesisError> {
    // 1. m_hash = Poseidon(message_domain, message).
    let m_hash = message_hash_var(cs.clone(), message)?;

    // 2. c_fq = Poseidon(challenge_domain, [R.x, R.y, PK.x, PK.y, m_hash]).
    //    Arity 6 (1 domain + 5 payload) — fixed regardless of
    //    message length.
    let challenge_tag = FpVar::<Fq>::constant(domain_tag(CHALLENGE_DOMAIN));
    let c_fq = poseidon_hash_fixed_var(
        cs.clone(),
        &challenge_tag,
        &[r.x.clone(), r.y.clone(), pk.x.clone(), pk.y.clone(), m_hash],
    )?;

    // 3. c · PK. The "c_fq mod l" reduction collapses into the
    //    bit decomposition: decompose c_fq to its full 254 bits,
    //    feed to scalar_mul_le on PK (which has order l). The
    //    double-and-add naturally computes (c_fq mod l) · PK.
    let c_bits = c_fq.to_bits_le()?;
    let c_pk = pk.scalar_mul_le(c_bits.iter())?;

    // 4. R + c · PK.
    let rhs = r + &c_pk;

    // 5. s · G. The generator is a circuit constant.
    let g = generator_constant();
    let s_bigint = s.into_bigint();
    let s_bit_len = Fr::MODULUS_BIT_SIZE as usize;
    let mut s_bits: Vec<Boolean<Fq>> = Vec::with_capacity(s_bit_len);
    for i in 0..s_bit_len {
        s_bits.push(Boolean::<Fq>::new_witness(cs.clone(), || {
            Ok(s_bigint.get_bit(i))
        })?);
    }
    let lhs = g.scalar_mul_le(s_bits.iter())?;

    // 6. Enforce s · G == R + c · PK.
    lhs.enforce_equal(&rhs)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::babyjub::alloc_point_witness;
    use ark_relations::r1cs::ConstraintSystem;
    use crypto::babyjub::{keypair_from_seed, sign as native_sign, Seed};
    use crypto::poseidon::poseidon_hash_fixed;

    /// Helper to compute the native message-hash, since the
    /// crypto crate keeps that function private.
    fn native_message_hash(message: &[Fq]) -> Fq {
        poseidon_hash_fixed(domain_tag(MESSAGE_DOMAIN), message)
            .expect("message len in range")
    }

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

    /// Native↔circuit equivalence for message_hash on a small
    /// message. The gadget's m_hash must agree with the native
    /// helper's, otherwise the challenge — and the entire
    /// verification — drift.
    #[test]
    fn message_hash_var_matches_native() {
        let cs = ConstraintSystem::<Fq>::new_ref();

        let message: [Fq; 3] = [Fq::from(1u64), Fq::from(2u64), Fq::from(3u64)];
        let expected = native_message_hash(&message);

        let msg_vars = alloc_array(cs.clone(), &message).unwrap();
        let got_var = message_hash_var(cs.clone(), &msg_vars).unwrap();

        let expected_var = FpVar::<Fq>::new_input(cs.clone(), || Ok(expected)).unwrap();
        got_var.enforce_equal(&expected_var).unwrap();
        assert!(cs.is_satisfied().unwrap());
    }

    /// The load-bearing test: a native signature on a real
    /// keypair verifies in-circuit. Sign natively, allocate the
    /// signature components as witnesses, run verify_var,
    /// `cs.is_satisfied()` must hold.
    #[test]
    fn verify_var_accepts_valid_signature() {
        let cs = ConstraintSystem::<Fq>::new_ref();

        let mut seed = [0u8; 64];
        seed[0] = 7;
        let (sk, pk) = keypair_from_seed(&Seed::from_bytes(seed));

        let message: [Fq; 3] = [Fq::from(10u64), Fq::from(20u64), Fq::from(30u64)];
        let sig = native_sign(&sk, &pk, &message).expect("ok");

        let pk_var = alloc_point_witness(cs.clone(), *pk.point()).unwrap();
        let msg_vars = alloc_array(cs.clone(), &message).unwrap();
        let r_var = alloc_point_witness(cs.clone(), sig.r).unwrap();

        verify_var(cs.clone(), &pk_var, &msg_vars, &r_var, sig.s).unwrap();

        assert!(cs.is_satisfied().unwrap());
    }

    /// Verification on a different message MUST fail. The
    /// integrity property at the gadget level.
    #[test]
    fn verify_var_rejects_wrong_message() {
        let cs = ConstraintSystem::<Fq>::new_ref();

        let mut seed = [0u8; 64];
        seed[0] = 7;
        let (sk, pk) = keypair_from_seed(&Seed::from_bytes(seed));

        let message: [Fq; 3] = [Fq::from(10u64), Fq::from(20u64), Fq::from(30u64)];
        let sig = native_sign(&sk, &pk, &message).expect("ok");

        // Verify against a different message.
        let tampered: [Fq; 3] = [Fq::from(10u64), Fq::from(20u64), Fq::from(99u64)];

        let pk_var = alloc_point_witness(cs.clone(), *pk.point()).unwrap();
        let msg_vars = alloc_array(cs.clone(), &tampered).unwrap();
        let r_var = alloc_point_witness(cs.clone(), sig.r).unwrap();

        verify_var(cs.clone(), &pk_var, &msg_vars, &r_var, sig.s).unwrap();

        assert!(!cs.is_satisfied().unwrap());
    }

    /// Verification with a wrong `s` (off by one) MUST fail.
    /// Catches the lhs/rhs asymmetry at the gadget level.
    #[test]
    fn verify_var_rejects_wrong_s() {
        let cs = ConstraintSystem::<Fq>::new_ref();

        let mut seed = [0u8; 64];
        seed[0] = 7;
        let (sk, pk) = keypair_from_seed(&Seed::from_bytes(seed));

        let message: [Fq; 3] = [Fq::from(10u64), Fq::from(20u64), Fq::from(30u64)];
        let sig = native_sign(&sk, &pk, &message).expect("ok");

        let pk_var = alloc_point_witness(cs.clone(), *pk.point()).unwrap();
        let msg_vars = alloc_array(cs.clone(), &message).unwrap();
        let r_var = alloc_point_witness(cs.clone(), sig.r).unwrap();

        let wrong_s = sig.s + Fr::from(1u64);
        verify_var(cs.clone(), &pk_var, &msg_vars, &r_var, wrong_s).unwrap();

        assert!(!cs.is_satisfied().unwrap());
    }

    /// Verification on the empty message accepts (an empty
    /// message is a valid native input, distinct from non-empty
    /// messages via domain-separated message-hash).
    #[test]
    fn verify_var_accepts_empty_message() {
        let cs = ConstraintSystem::<Fq>::new_ref();

        let mut seed = [0u8; 64];
        seed[0] = 7;
        let (sk, pk) = keypair_from_seed(&Seed::from_bytes(seed));

        let message: [Fq; 0] = [];
        let sig = native_sign(&sk, &pk, &message).expect("ok");

        let pk_var = alloc_point_witness(cs.clone(), *pk.point()).unwrap();
        let msg_vars: [FpVar<Fq>; 0] = [];
        let r_var = alloc_point_witness(cs.clone(), sig.r).unwrap();

        verify_var(cs.clone(), &pk_var, &msg_vars, &r_var, sig.s).unwrap();

        assert!(cs.is_satisfied().unwrap());
    }

    /// A signature from a different signer's keypair MUST fail
    /// verification against the wrong PK. Pins that the gadget
    /// is actually using `pk` in the challenge.
    #[test]
    fn verify_var_rejects_wrong_pk() {
        let cs = ConstraintSystem::<Fq>::new_ref();

        let mut seed_a = [0u8; 64];
        seed_a[0] = 7;
        let (sk_a, pk_a) = keypair_from_seed(&Seed::from_bytes(seed_a));

        let mut seed_b = [0u8; 64];
        seed_b[0] = 8;
        let (_, pk_b) = keypair_from_seed(&Seed::from_bytes(seed_b));

        let message: [Fq; 2] = [Fq::from(1u64), Fq::from(2u64)];
        let sig = native_sign(&sk_a, &pk_a, &message).expect("ok");

        // Try to verify Alice's signature against Bob's PK.
        let pk_var = alloc_point_witness(cs.clone(), *pk_b.point()).unwrap();
        let msg_vars = alloc_array(cs.clone(), &message).unwrap();
        let r_var = alloc_point_witness(cs.clone(), sig.r).unwrap();

        verify_var(cs.clone(), &pk_var, &msg_vars, &r_var, sig.s).unwrap();

        assert!(!cs.is_satisfied().unwrap());
    }
}
