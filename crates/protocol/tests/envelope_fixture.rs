//! Cross-language compatibility fixture for
//! [`specs/protocol-envelope.md § Worked Example`](../../specs/protocol-envelope.md).
//!
//! The spec's worked example chains through every underlying
//! primitive's already-pinned vectors: the ECDH shared point
//! from `babyjub-ecdh.md`, the KDF keys from `babyjub-kdf.md`
//! (Vectors 2 and 3), and the ciphertext from `babyjub-cipher.md`
//! (Vector 3). The MAC tag is NO LONGER `babyjub-mac.md` Vector 5
//! directly, because the envelope now MACs `[encoding_id,
//! ...ciphertext]` (the Option-A encoding-id binding), not the
//! bare ciphertext — so the tag is pinned here against the
//! augmented MAC input under the `text-utf8-v1` encoding id.
//!
//! If any of these decimals drift, every conformant
//! implementation (Rust, future Move, future TS) is producing
//! an envelope that won't interoperate with the spec.
//! Integration test (in `tests/`) by design.

use ark_ff::PrimeField;

use crypto::babyjub::{keypair_from_seed, point_to_strings, Fq, Seed};
use crypto::encoding::{id::encoding_id, Payload};
use protocol::envelope::{open, seal, Envelope};

/// The text-utf8-v1 encoding id — the fixture's chosen encoding
/// for the 4-element payload `[1,2,3,4]`. Pinned across
/// payload.md and protocol-commitment.md too.
const TEXT_UTF8_V1_ID: &str =
    "10251905648233427808659162032937842155138269080868533503078341140126603942221";

/// The spec's pinned Alice/Bob fixture. Same seeds the
/// underlying `babyjub-*` specs use for their worked
/// examples — so this fixture chains cleanly through every
/// upstream pinned vector.
fn alice_bob_envelope_42() -> Envelope {
    let mut seed_a = [0u8; 64];
    seed_a[0] = 1;
    let mut seed_b = [0u8; 64];
    seed_b[0] = 2;
    let (sk_a, pk_a) = keypair_from_seed(&Seed::from_bytes(seed_a));
    let (_, pk_b) = keypair_from_seed(&Seed::from_bytes(seed_b));

    let payload = Payload::new(
        encoding_id("specs/encodings/text-utf8-v1.md"),
        vec![
            Fq::from(1u64),
            Fq::from(2u64),
            Fq::from(3u64),
            Fq::from(4u64),
        ],
    );

    seal(&sk_a, &pk_a, &pk_b, Fq::from(42u64), &payload)
}

fn dec(f: Fq) -> String {
    f.into_bigint().to_string()
}

/// Spec: the envelope's `ciphertext` MUST equal
/// [`babyjub-cipher.md § Vector 3`](../../specs/babyjub-cipher.md).
/// The encoding-id binding does NOT touch the cipher — only the
/// MAC input — so this vector is unchanged from the pre-Payload
/// envelope.
#[test]
fn envelope_ciphertext_matches_cipher_spec_vector_3() {
    let envelope = alice_bob_envelope_42();
    let ct: Vec<String> = envelope.ciphertext.iter().map(|f| dec(*f)).collect();
    assert_eq!(
        ct,
        vec![
            "10787321779190226554676337514347691875659477298610453494316095697639731105525",
            "11005131623232030623906867189653141067415173065234117331769608574160093139922",
            "11791314040563090199526129580738560103220176213914809365331933459954108858858",
            "7865039964291077852173468667319105421171640084683400461629880408575490986497",
        ],
    );
}

/// Spec: the envelope's `mac_tag` is the MAC over `[encoding_id,
/// ...ciphertext]` (Option-A binding). Pinned here. Distinct
/// from `babyjub-mac.md` Vector 5 (which MACs the bare
/// ciphertext) — the difference IS the encoding-id binding.
#[test]
fn envelope_mac_tag_matches_augmented_input() {
    let envelope = alice_bob_envelope_42();
    assert_eq!(
        dec(envelope.mac_tag),
        "10617735897557692178614481311515068866203189059565568446474293383244412682151",
    );
}

/// Spec § Worked Example: the envelope carries the payload's
/// `encoding_id` as a public field, equal to the text-utf8-v1
/// id.
#[test]
fn envelope_carries_text_utf8_v1_encoding_id() {
    let envelope = alice_bob_envelope_42();
    assert_eq!(dec(envelope.encoding_id), TEXT_UTF8_V1_ID);
}

/// Spec § Worked Example: `envelope_id` is part of the
/// envelope's public state. Trivial check but pins that the
/// field carries the caller's input unchanged. Note it is
/// distinct from `encoding_id`.
#[test]
fn envelope_id_is_preserved() {
    let envelope = alice_bob_envelope_42();
    assert_eq!(envelope.envelope_id, Fq::from(42u64));
}

/// Spec § Worked Example: `sender_pk` and `recipient_pk` are
/// the Alice/Bob keypair public halves derived from the pinned
/// seeds.
#[test]
fn envelope_identifies_alice_to_bob() {
    let envelope = alice_bob_envelope_42();

    let mut seed_a = [0u8; 64];
    seed_a[0] = 1;
    let mut seed_b = [0u8; 64];
    seed_b[0] = 2;
    let (_, pk_a) = keypair_from_seed(&Seed::from_bytes(seed_a));
    let (_, pk_b) = keypair_from_seed(&Seed::from_bytes(seed_b));

    assert_eq!(envelope.sender_pk, *pk_a.point());
    assert_eq!(envelope.recipient_pk, *pk_b.point());

    // Wire-form decimals exist for a future Move-side verifier.
    let sender = point_to_strings(&envelope.sender_pk);
    let recipient = point_to_strings(&envelope.recipient_pk);
    assert!(!sender.x.is_empty());
    assert!(!sender.y.is_empty());
    assert!(!recipient.x.is_empty());
    assert!(!recipient.y.is_empty());
}

/// Round-trip across the full spec's worked example: Bob's
/// `open` recovers the payload — the `[1,2,3,4]` stream paired
/// with the text-utf8-v1 encoding id. Pins that the
/// construction rule's reverse direction works on the exact
/// same vectors.
#[test]
fn fixture_envelope_opens_to_pinned_payload() {
    let envelope = alice_bob_envelope_42();

    let mut seed_b = [0u8; 64];
    seed_b[0] = 2;
    let (sk_b, pk_b) = keypair_from_seed(&Seed::from_bytes(seed_b));

    let recovered = open(&sk_b, &pk_b, &envelope).expect("open ok");
    assert_eq!(
        recovered.stream,
        vec![
            Fq::from(1u64),
            Fq::from(2u64),
            Fq::from(3u64),
            Fq::from(4u64),
        ],
    );
    assert_eq!(dec(recovered.encoding_id), TEXT_UTF8_V1_ID);
}

/// ECDH symmetry at the envelope layer: sealing Alice→Bob
/// produces the same ciphertext and MAC tag as sealing Bob→Alice
/// under the same envelope_id, same payload — because the shared
/// point (and therefore both derived keys) match. Only the
/// sender/recipient labels swap.
#[test]
fn ecdh_symmetric_envelope_roles() {
    let mut seed_a = [0u8; 64];
    seed_a[0] = 1;
    let mut seed_b = [0u8; 64];
    seed_b[0] = 2;
    let (sk_a, pk_a) = keypair_from_seed(&Seed::from_bytes(seed_a));
    let (sk_b, pk_b) = keypair_from_seed(&Seed::from_bytes(seed_b));

    let payload = Payload::new(
        encoding_id("specs/encodings/text-utf8-v1.md"),
        vec![Fq::from(1u64), Fq::from(2u64)],
    );

    let a_to_b = seal(&sk_a, &pk_a, &pk_b, Fq::from(42u64), &payload);
    let b_to_a = seal(&sk_b, &pk_b, &pk_a, Fq::from(42u64), &payload);

    assert_eq!(a_to_b.ciphertext, b_to_a.ciphertext);
    assert_eq!(a_to_b.mac_tag, b_to_a.mac_tag);
    assert_eq!(a_to_b.sender_pk, b_to_a.recipient_pk);
    assert_eq!(a_to_b.recipient_pk, b_to_a.sender_pk);
}
