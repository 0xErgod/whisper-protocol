//! In-circuit Baby Jubjub stream cipher.
//!
//! Mirrors `crypto::babyjub::cipher::{encrypt, decrypt}` against
//! `FpVar<Fq>`. The native construction:
//!
//! ```text
//! keystream_i = poseidon_hash_fixed(cipher_domain, [key, i_as_field])
//! ciphertext_i = plaintext_i + keystream_i   (mod p)
//! plaintext_i  = ciphertext_i - keystream_i  (mod p)
//! ```
//!
//! Field arithmetic over `Fq` — one constraint per element for the
//! addition (subtraction), plus the Poseidon-hash-fixed gadget's
//! cost per position for the keystream. ZK-native by construction:
//! the per-position keystream is addressable from a single
//! `poseidon_hash_fixed_var` call.
//!
//! ## What the gadget is FOR
//!
//! Proving statements about ciphertext / plaintext pairs without
//! revealing them. The canonical use cases:
//!
//! - **Selective decryption proofs.** Prove "the i-th plaintext
//!   element of this ciphertext equals X under the held key,"
//!   leaking only X and the index.
//! - **Re-encryption proofs.** Prove the ciphertext is the encryption
//!   of a witness plaintext under a witness key, without revealing
//!   either — for an envelope-validity claim that doesn't require
//!   decryption.
//!
//! ## Counter encoding
//!
//! The counter `i` is encoded as `Fq::from(i as u64)`, the same as
//! the native side. In a circuit, that means each position's
//! counter is a *constant* (`FpVar::constant`), not a witness —
//! position indices are fixed at circuit-design time. A future
//! variable-length cipher gadget would need to thread the counter
//! as a witness, but no current use case wants that.

use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::fields::FieldVar;
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};

use crypto::babyjub::Fq;
use crypto::babyjub::CIPHER_DOMAIN;
use crypto::poseidon::domain_tag;

use crate::poseidon::poseidon_hash_fixed_var;

/// Compute the per-position keystream element. Internal helper;
/// public callers use [`encrypt_var`] / [`decrypt_var`].
///
/// Construction:
/// `Poseidon-hash-fixed(cipher_domain, [key, position_as_field])`.
/// Mirrors `crypto::babyjub::cipher`'s private `keystream_at`.
fn keystream_at_var(
    cs: ConstraintSystemRef<Fq>,
    key: &FpVar<Fq>,
    position: usize,
) -> Result<FpVar<Fq>, SynthesisError> {
    let tag = FpVar::<Fq>::constant(domain_tag(CIPHER_DOMAIN));
    let position_var = FpVar::<Fq>::constant(Fq::from(position as u64));
    poseidon_hash_fixed_var(cs, &tag, &[key.clone(), position_var])
}

/// Encrypt a plaintext stream under a key, in-circuit. Mirrors
/// `crypto::babyjub::cipher::encrypt`.
///
/// Returns a length-matched ciphertext stream as `FpVar`s. Same
/// shape in and out — the cipher is length-preserving.
///
/// `cs` is threaded through every Poseidon call; allocate it once
/// per circuit instance and pass it down.
pub fn encrypt_var(
    cs: ConstraintSystemRef<Fq>,
    key: &FpVar<Fq>,
    plaintext: &[FpVar<Fq>],
) -> Result<Vec<FpVar<Fq>>, SynthesisError> {
    let mut out: Vec<FpVar<Fq>> = Vec::with_capacity(plaintext.len());
    for (i, p) in plaintext.iter().enumerate() {
        let k = keystream_at_var(cs.clone(), key, i)?;
        out.push(p + &k);
    }
    Ok(out)
}

/// Decrypt a ciphertext stream under the same key used to encrypt
/// it. Mirrors `crypto::babyjub::cipher::decrypt`.
///
/// Like the native side, this never errors on cryptographic
/// grounds — wrong key produces garbage of the right length, and
/// detecting that is the MAC's job (see [`crate::babyjub::mac`]
/// once it lands).
pub fn decrypt_var(
    cs: ConstraintSystemRef<Fq>,
    key: &FpVar<Fq>,
    ciphertext: &[FpVar<Fq>],
) -> Result<Vec<FpVar<Fq>>, SynthesisError> {
    let mut out: Vec<FpVar<Fq>> = Vec::with_capacity(ciphertext.len());
    for (i, c) in ciphertext.iter().enumerate() {
        let k = keystream_at_var(cs.clone(), key, i)?;
        out.push(c - &k);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_r1cs_std::alloc::AllocVar;
    use ark_r1cs_std::eq::EqGadget;
    use ark_relations::r1cs::ConstraintSystem;
    use crypto::babyjub::{decrypt as native_decrypt, encrypt as native_encrypt};

    /// Allocate `xs` as witness `FpVar`s.
    fn alloc_witnesses(
        cs: ConstraintSystemRef<Fq>,
        xs: &[Fq],
    ) -> Result<Vec<FpVar<Fq>>, SynthesisError> {
        xs.iter()
            .map(|x| FpVar::<Fq>::new_witness(cs.clone(), || Ok(*x)))
            .collect()
    }

    /// Enforce element-wise equality between two `FpVar` streams.
    fn enforce_stream_equal(
        got: &[FpVar<Fq>],
        expected: &[FpVar<Fq>],
    ) -> Result<(), SynthesisError> {
        assert_eq!(got.len(), expected.len(), "stream lengths must match");
        for (g, e) in got.iter().zip(expected.iter()) {
            g.enforce_equal(e)?;
        }
        Ok(())
    }

    /// Native↔circuit equivalence for encryption on a canonical
    /// 4-element stream. The load-bearing test: it pins the
    /// per-position keystream construction (counter encoding,
    /// domain tag, key placement) against the native cipher and
    /// against `specs/babyjub-cipher.md § Vector 3` transitively
    /// — the native function we're matching here IS what produces
    /// the spec's pinned ciphertext.
    #[test]
    fn encrypt_var_matches_native() {
        let cs = ConstraintSystem::<Fq>::new_ref();

        // Arbitrary key and plaintext; specific values not the point
        // — the equivalence is what's load-bearing.
        let key = Fq::from(42u64);
        let plaintext = [
            Fq::from(1u64),
            Fq::from(2u64),
            Fq::from(3u64),
            Fq::from(4u64),
        ];
        let expected = native_encrypt(key, &plaintext);

        let key_var = FpVar::<Fq>::new_witness(cs.clone(), || Ok(key)).unwrap();
        let pt_vars = alloc_witnesses(cs.clone(), &plaintext).unwrap();
        let ct_vars = encrypt_var(cs.clone(), &key_var, &pt_vars).unwrap();

        let expected_vars = alloc_witnesses(cs.clone(), &expected).unwrap();
        enforce_stream_equal(&ct_vars, &expected_vars).unwrap();
        assert!(cs.is_satisfied().unwrap());
    }

    /// Equivalence on the empty stream. The cipher is
    /// length-preserving and the gadget MUST return the empty
    /// ciphertext on the empty plaintext — no Poseidon calls, no
    /// constraints from the cipher itself.
    #[test]
    fn encrypt_var_matches_native_empty() {
        let cs = ConstraintSystem::<Fq>::new_ref();

        let key = Fq::from(42u64);
        let plaintext: Vec<Fq> = vec![];
        let expected = native_encrypt(key, &plaintext);
        assert!(expected.is_empty());

        let key_var = FpVar::<Fq>::new_witness(cs.clone(), || Ok(key)).unwrap();
        let ct_vars = encrypt_var(cs.clone(), &key_var, &[]).unwrap();
        assert!(ct_vars.is_empty());
        assert!(cs.is_satisfied().unwrap());
    }

    /// Equivalence for decryption — completes the round-trip
    /// contract at the gadget level. `decrypt(encrypt(p)) == p`
    /// must hold in-circuit as well as natively.
    #[test]
    fn decrypt_var_matches_native() {
        let cs = ConstraintSystem::<Fq>::new_ref();

        let key = Fq::from(42u64);
        let plaintext = [
            Fq::from(1u64),
            Fq::from(2u64),
            Fq::from(3u64),
            Fq::from(4u64),
        ];
        let ciphertext = native_encrypt(key, &plaintext);
        let expected = native_decrypt(key, &ciphertext);
        assert_eq!(expected, plaintext);

        let key_var = FpVar::<Fq>::new_witness(cs.clone(), || Ok(key)).unwrap();
        let ct_vars = alloc_witnesses(cs.clone(), &ciphertext).unwrap();
        let pt_vars = decrypt_var(cs.clone(), &key_var, &ct_vars).unwrap();

        let expected_vars = alloc_witnesses(cs.clone(), &expected).unwrap();
        enforce_stream_equal(&pt_vars, &expected_vars).unwrap();
        assert!(cs.is_satisfied().unwrap());
    }

    /// Round-trip in-circuit: encrypt then decrypt, assert the
    /// recovered plaintext equals the original. Pins the cipher's
    /// defining property at the gadget level without going through
    /// the native side as a reference.
    #[test]
    fn encrypt_then_decrypt_var_roundtrips() {
        let cs = ConstraintSystem::<Fq>::new_ref();

        let key = Fq::from(42u64);
        let plaintext = [
            Fq::from(10u64),
            Fq::from(20u64),
            Fq::from(30u64),
        ];

        let key_var = FpVar::<Fq>::new_witness(cs.clone(), || Ok(key)).unwrap();
        let pt_vars = alloc_witnesses(cs.clone(), &plaintext).unwrap();
        let ct_vars = encrypt_var(cs.clone(), &key_var, &pt_vars).unwrap();
        let recovered = decrypt_var(cs.clone(), &key_var, &ct_vars).unwrap();

        enforce_stream_equal(&recovered, &pt_vars).unwrap();
        assert!(cs.is_satisfied().unwrap());
    }

    /// Negative-direction confirmation: a deliberately wrong
    /// expected ciphertext unsatisfies the constraint system.
    #[test]
    fn encrypt_var_rejects_wrong_expected() {
        let cs = ConstraintSystem::<Fq>::new_ref();

        let key = Fq::from(42u64);
        let plaintext = [Fq::from(1u64), Fq::from(2u64)];

        let key_var = FpVar::<Fq>::new_witness(cs.clone(), || Ok(key)).unwrap();
        let pt_vars = alloc_witnesses(cs.clone(), &plaintext).unwrap();
        let ct_vars = encrypt_var(cs.clone(), &key_var, &pt_vars).unwrap();

        let wrong_expected = [Fq::from(999u64), Fq::from(999u64)];
        let wrong_vars = alloc_witnesses(cs.clone(), &wrong_expected).unwrap();
        enforce_stream_equal(&ct_vars, &wrong_vars).unwrap();
        assert!(!cs.is_satisfied().unwrap());
    }
}
