//! Authenticated, confidential message envelope.
//!
//! Implements [`specs/protocol-envelope.md`](../../specs/protocol-envelope.md):
//! the canonical encrypt-then-MAC composition of ECDH, KDF,
//! stream cipher, and MAC into a single typed bundle.
//!
//! ## Shape
//!
//! ```text
//! envelope = {
//!     sender_pk     : EdwardsAffine,
//!     recipient_pk  : EdwardsAffine,
//!     envelope_id   : Fq,
//!     ciphertext    : Vec<Fq>,
//!     mac_tag       : Fq,
//! }
//! ```
//!
//! Two free functions:
//!
//! - [`seal`] — sender side. Takes plaintext, returns an
//!   [`Envelope`].
//! - [`open`] — recipient side. Takes an [`Envelope`], returns
//!   the plaintext or a typed error.
//!
//! Both functions are thin compositions of `crypto::babyjub::*`
//! primitives. The spec's construction rules — encrypt-then-MAC
//! order, role-tagged KDF keys, MAC-before-decrypt on the
//! recipient side — are encoded in the function bodies and
//! pinned by the integration fixture in `tests/envelope.rs`.

use crypto::babyjub::{
    decrypt, encrypt, kdf_derive, mac_compute, mac_verify, shared_secret, EdwardsAffine, Fq,
    PublicKey, SecretKey,
};
use crypto::poseidon::domain_tag;

/// Encryption-key role tag.
///
/// Re-derived here as `domain_tag("envelope-cipher-key")`. The
/// resulting `Fq` value is pinned in
/// [`specs/babyjub-kdf.md`](../../specs/babyjub-kdf.md) and
/// reused by [`specs/protocol-envelope.md`](../../specs/protocol-envelope.md).
/// A drift in either spec's pinned decimal surfaces as the
/// fixture test failing, not silent incompatibility.
pub const CIPHER_ROLE: &str = "envelope-cipher-key";

/// MAC-key role tag. See [`CIPHER_ROLE`] for the same
/// derivation discipline.
pub const MAC_ROLE: &str = "envelope-mac-key";

/// An authenticated envelope. Five fields, all public; nothing
/// in here is sensitive on its own. The sender's `sk_a` and the
/// recipient's `sk_b` are the only things that can recover the
/// plaintext, and neither is part of the struct.
///
/// ## On `Vec<Fq>` for ciphertext
///
/// The cipher is length-preserving; `ciphertext.len() ==
/// plaintext.len()`. We use `Vec<Fq>` rather than a fixed-size
/// array because envelope plaintexts have variable length —
/// `text-utf8-v1` is 9 elements today, but future encodings
/// will produce different shapes, and the envelope must accept
/// any of them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Envelope {
    /// The sender's public key. Public; allows the recipient
    /// to verify the envelope came from a specific sender (in
    /// the sense that the MAC verifies only under the shared
    /// point of that exact `(sender_pk, recipient_pk)` pair).
    pub sender_pk: EdwardsAffine,
    /// The intended recipient's public key. The recipient
    /// rejects envelopes whose `recipient_pk` doesn't match
    /// their own — see [`OpenError::WrongRecipient`].
    pub recipient_pk: EdwardsAffine,
    /// Per-envelope binding scalar. Must be unique per
    /// `(sender, recipient)` pair to preserve confidentiality;
    /// see the spec's [§ Composition order] for the
    /// uniqueness rationale.
    pub envelope_id: Fq,
    /// The cipher's output. Length matches the plaintext's
    /// length.
    pub ciphertext: Vec<Fq>,
    /// The MAC tag over `ciphertext` under the MAC-role key.
    /// One field element; one Poseidon sponge call to verify.
    pub mac_tag: Fq,
}

/// Why [`open`] rejected an envelope.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum OpenError {
    /// The envelope's `recipient_pk` does not match the
    /// recipient's own `pk`. The envelope is for someone else
    /// (or is malformed); no cryptographic operation was
    /// attempted.
    #[error("envelope's recipient_pk does not match this recipient")]
    WrongRecipient,

    /// The MAC tag does not verify under the derived MAC key.
    /// The envelope is corrupt, was forged, or its
    /// `envelope_id` / `sender_pk` were tampered with. The
    /// plaintext was NOT decrypted (`open` checks the MAC
    /// before attempting decryption, per the spec).
    #[error("envelope MAC verification failed: corrupt or forged")]
    MacFailure,
}

/// Seal a plaintext into an envelope.
///
/// Mirrors [`specs/protocol-envelope.md § Sealing`](../../specs/protocol-envelope.md):
///
/// ```text
/// shared       = ecdh(sender_sk, recipient_pk)
/// key_enc      = kdf(shared, [ENC_ROLE_TAG, envelope_id])
/// key_mac      = kdf(shared, [MAC_ROLE_TAG, envelope_id])
/// ciphertext   = cipher.encrypt(key_enc, plaintext)
/// mac_tag      = mac.mac(key_mac, ciphertext)
/// ```
///
/// `sender_pk` is taken as a parameter (rather than derived from
/// `sender_sk` inside) because the caller already has it — the
/// keypair-derivation path produces both halves together — and
/// re-deriving would mean one extra scalar-mul per seal.
///
/// `envelope_id` MUST be unique per `(sender, recipient)` pair.
/// Reusing an id with the same shared point yields the same
/// cipher key, which leaks plaintext-difference information.
/// The spec recommends Sui object ids, monotonic counters, or
/// fresh randomness.
pub fn seal(
    sender_sk: &SecretKey,
    sender_pk: &PublicKey,
    recipient_pk: &PublicKey,
    envelope_id: Fq,
    plaintext: &[Fq],
) -> Envelope {
    let shared = shared_secret(sender_sk, recipient_pk);

    let key_enc = kdf_derive(&shared, &[domain_tag(CIPHER_ROLE), envelope_id])
        .expect("envelope kdf context has length 2, well within MAX_CONTEXT_LEN");
    let key_mac = kdf_derive(&shared, &[domain_tag(MAC_ROLE), envelope_id])
        .expect("envelope kdf context has length 2, well within MAX_CONTEXT_LEN");

    let ciphertext = encrypt(key_enc, plaintext);
    let mac_tag = mac_compute(key_mac, &ciphertext);

    Envelope {
        sender_pk: *sender_pk.point(),
        recipient_pk: *recipient_pk.point(),
        envelope_id,
        ciphertext,
        mac_tag,
    }
}

/// Open an envelope, recovering the plaintext.
///
/// Mirrors [`specs/protocol-envelope.md § Opening`](../../specs/protocol-envelope.md):
///
/// 1. Recipient check: `envelope.recipient_pk == recipient_pk`,
///    else [`OpenError::WrongRecipient`].
/// 2. Derive `shared = ecdh(recipient_sk, sender_pk)`.
/// 3. Derive `key_mac`.
/// 4. MAC verify; on failure, [`OpenError::MacFailure`] (the
///    decryption step is NOT run).
/// 5. Derive `key_enc`, decrypt, return the plaintext.
///
/// **MAC before decrypt.** The discipline pinned in
/// `babyjub-mac.md`. A recipient that decrypts first has
/// voluntarily exposed itself to chosen-ciphertext attacks;
/// `open` enforces the safe order.
pub fn open(
    recipient_sk: &SecretKey,
    recipient_pk: &PublicKey,
    envelope: &Envelope,
) -> Result<Vec<Fq>, OpenError> {
    // 1. Routing check.
    if envelope.recipient_pk != *recipient_pk.point() {
        return Err(OpenError::WrongRecipient);
    }

    // 2. Reconstruct the shared point from the recipient's
    //    side: `sk_b · sender_pk == sk_a · pk_b == shared`.
    //    ECDH symmetry; no need to handle the sender's
    //    secret here. The wrap below is sound because
    //    `envelope.sender_pk` came in across the wire and the
    //    caller is responsible for having validated it (the
    //    typical path is a wire decoder upstream of `open`).
    let sender_pk_wrapped = PublicKey::from_validated_point(envelope.sender_pk);
    let shared = shared_secret(recipient_sk, &sender_pk_wrapped);

    // 3 + 4. Derive the MAC key and verify the tag before
    //        touching the ciphertext.
    let key_mac = kdf_derive(&shared, &[domain_tag(MAC_ROLE), envelope.envelope_id])
        .expect("envelope kdf context has length 2, well within MAX_CONTEXT_LEN");
    if !mac_verify(key_mac, &envelope.ciphertext, envelope.mac_tag) {
        return Err(OpenError::MacFailure);
    }

    // 5. MAC passed — derive the cipher key and decrypt.
    let key_enc = kdf_derive(&shared, &[domain_tag(CIPHER_ROLE), envelope.envelope_id])
        .expect("envelope kdf context has length 2, well within MAX_CONTEXT_LEN");
    Ok(decrypt(key_enc, &envelope.ciphertext))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto::babyjub::{keypair_from_seed, Seed};

    fn alice_bob() -> ((SecretKey, PublicKey), (SecretKey, PublicKey)) {
        let mut seed_a = [0u8; 64];
        seed_a[0] = 1;
        let mut seed_b = [0u8; 64];
        seed_b[0] = 2;
        (
            keypair_from_seed(&Seed::from_bytes(seed_a)),
            keypair_from_seed(&Seed::from_bytes(seed_b)),
        )
    }

    /// Round-trip: Alice seals a plaintext to Bob; Bob opens
    /// and recovers it. The defining property.
    #[test]
    fn seal_then_open_roundtrips() {
        let ((sk_a, pk_a), (sk_b, pk_b)) = alice_bob();
        let plaintext = vec![
            Fq::from(1u64),
            Fq::from(2u64),
            Fq::from(3u64),
            Fq::from(4u64),
        ];

        let envelope = seal(&sk_a, &pk_a, &pk_b, Fq::from(42u64), &plaintext);
        let recovered = open(&sk_b, &pk_b, &envelope).expect("ok");
        assert_eq!(recovered, plaintext);
    }

    /// An empty plaintext seals and opens correctly. Edge case
    /// inherited from the cipher.
    #[test]
    fn seal_then_open_empty_plaintext() {
        let ((sk_a, pk_a), (sk_b, pk_b)) = alice_bob();
        let envelope = seal(&sk_a, &pk_a, &pk_b, Fq::from(42u64), &[]);
        assert!(envelope.ciphertext.is_empty());
        let recovered = open(&sk_b, &pk_b, &envelope).expect("ok");
        assert!(recovered.is_empty());
    }

    /// An envelope addressed to Eve (not Bob) is rejected
    /// before any cryptographic operation runs. Pins
    /// `WrongRecipient`.
    #[test]
    fn open_rejects_wrong_recipient() {
        let ((sk_a, pk_a), (_sk_b, pk_b)) = alice_bob();
        let mut seed_e = [0u8; 64];
        seed_e[0] = 3;
        let (sk_e, pk_e) = keypair_from_seed(&Seed::from_bytes(seed_e));

        // Alice seals for Bob.
        let envelope = seal(&sk_a, &pk_a, &pk_b, Fq::from(42u64), &[Fq::from(1u64)]);
        // Eve tries to open it.
        let err = open(&sk_e, &pk_e, &envelope).unwrap_err();
        assert_eq!(err, OpenError::WrongRecipient);
    }

    /// A tampered ciphertext element fails the MAC verify. The
    /// integrity property.
    #[test]
    fn open_rejects_tampered_ciphertext() {
        let ((sk_a, pk_a), (sk_b, pk_b)) = alice_bob();
        let mut envelope = seal(
            &sk_a,
            &pk_a,
            &pk_b,
            Fq::from(42u64),
            &[Fq::from(1u64), Fq::from(2u64), Fq::from(3u64)],
        );

        envelope.ciphertext[1] += Fq::from(1u64);
        let err = open(&sk_b, &pk_b, &envelope).unwrap_err();
        assert_eq!(err, OpenError::MacFailure);
    }

    /// A tampered MAC tag fails the verify. Catches a different
    /// failure mode than ciphertext tampering — the ciphertext
    /// is untouched but the tag is wrong.
    #[test]
    fn open_rejects_tampered_mac_tag() {
        let ((sk_a, pk_a), (sk_b, pk_b)) = alice_bob();
        let mut envelope = seal(&sk_a, &pk_a, &pk_b, Fq::from(42u64), &[Fq::from(1u64)]);

        envelope.mac_tag += Fq::from(1u64);
        let err = open(&sk_b, &pk_b, &envelope).unwrap_err();
        assert_eq!(err, OpenError::MacFailure);
    }

    /// A tampered `envelope_id` fails the verify. Confirms the
    /// id is bound into the keys: the recipient derives keys
    /// from the envelope's stated id, and a mismatch with the
    /// id the sender used yields different keys and a failed
    /// MAC check.
    #[test]
    fn open_rejects_tampered_envelope_id() {
        let ((sk_a, pk_a), (sk_b, pk_b)) = alice_bob();
        let mut envelope = seal(&sk_a, &pk_a, &pk_b, Fq::from(42u64), &[Fq::from(1u64)]);

        envelope.envelope_id = Fq::from(43u64);
        let err = open(&sk_b, &pk_b, &envelope).unwrap_err();
        assert_eq!(err, OpenError::MacFailure);
    }

    /// Substituting a different sender's `sender_pk` field
    /// fails the verify: the shared point on Bob's side is
    /// `sk_b · forged_sender_pk`, which differs from the real
    /// shared point under which the MAC was computed.
    #[test]
    fn open_rejects_tampered_sender_pk() {
        let ((sk_a, pk_a), (sk_b, pk_b)) = alice_bob();
        let mut seed_e = [0u8; 64];
        seed_e[0] = 3;
        let (_sk_e, pk_e) = keypair_from_seed(&Seed::from_bytes(seed_e));

        let mut envelope = seal(&sk_a, &pk_a, &pk_b, Fq::from(42u64), &[Fq::from(1u64)]);

        // Replace sender_pk with Eve's. Bob still sees the
        // envelope addressed to himself (recipient_pk
        // unchanged), so the routing check passes; the MAC
        // check fails because the shared point is now
        // sk_b · pk_e, not sk_b · pk_a.
        envelope.sender_pk = *pk_e.point();
        let err = open(&sk_b, &pk_b, &envelope).unwrap_err();
        assert_eq!(err, OpenError::MacFailure);
    }

    /// Different envelope ids yield different ciphertexts even
    /// for the same plaintext, sender, recipient. Pins
    /// per-envelope keying.
    #[test]
    fn different_envelope_ids_yield_different_ciphertexts() {
        let ((sk_a, pk_a), (_sk_b, pk_b)) = alice_bob();
        let plaintext = vec![Fq::from(1u64), Fq::from(2u64)];
        let env1 = seal(&sk_a, &pk_a, &pk_b, Fq::from(42u64), &plaintext);
        let env2 = seal(&sk_a, &pk_a, &pk_b, Fq::from(43u64), &plaintext);
        assert_ne!(env1.ciphertext, env2.ciphertext);
        assert_ne!(env1.mac_tag, env2.mac_tag);
    }
}
