//! Cross-language compatibility fixture for `babyjub-mac`.
//!
//! Executable form of `specs/babyjub-mac.md § Worked Example`. If
//! anything drifts — domain tag, key placement, sponge parameters,
//! Poseidon round constants — these fail. Integration test (in
//! `tests/`) by design.
//!
//! Pinning strategy: chain from KDF Vector 3 (mac-role key for
//! envelope 42), then assert every tag matches the spec's exact
//! decimal.

use ark_ff::PrimeField;

use crypto::babyjub::{
    encrypt, kdf_derive, keypair_from_seed, mac_compute, mac_verify, shared_secret, Fq, Seed,
};
use crypto::poseidon::domain_tag;

fn alice_bob_mac_key() -> Fq {
    let mut seed_a = [0u8; 64];
    seed_a[0] = 1;
    let mut seed_b = [0u8; 64];
    seed_b[0] = 2;
    let (sk_a, _) = keypair_from_seed(&Seed::from_bytes(seed_a));
    let (_, pk_b) = keypair_from_seed(&Seed::from_bytes(seed_b));
    let shared = shared_secret(&sk_a, &pk_b);
    kdf_derive(
        &shared,
        &[domain_tag("envelope-mac-key"), Fq::from(42u64)],
    )
    .expect("ok")
}

fn alice_bob_cipher_key() -> Fq {
    let mut seed_a = [0u8; 64];
    seed_a[0] = 1;
    let mut seed_b = [0u8; 64];
    seed_b[0] = 2;
    let (sk_a, _) = keypair_from_seed(&Seed::from_bytes(seed_a));
    let (_, pk_b) = keypair_from_seed(&Seed::from_bytes(seed_b));
    let shared = shared_secret(&sk_a, &pk_b);
    kdf_derive(
        &shared,
        &[domain_tag("envelope-cipher-key"), Fq::from(42u64)],
    )
    .expect("ok")
}

fn dec(f: Fq) -> String {
    f.into_bigint().to_string()
}

/// Sanity: the MAC key used by this fixture must equal the one
/// `specs/babyjub-kdf.md` Vector 3 pins.
#[test]
fn mac_key_matches_kdf_spec() {
    assert_eq!(
        dec(alice_bob_mac_key()),
        "5302105009719633730025155498822445041452574923386899996802294480945238328306",
    );
}

/// Vector 1: empty message.
#[test]
fn fixture_vector_1_empty_message() {
    let key = alice_bob_mac_key();
    let tag = mac_compute(key, &[]);
    assert_eq!(
        dec(tag),
        "13976129352745355852952122427372408395772002964442343488572190579262395794749",
    );
    assert!(mac_verify(key, &[], tag));
}

/// Vector 2: single zero element.
#[test]
fn fixture_vector_2_single_zero() {
    let key = alice_bob_mac_key();
    let m = [Fq::from(0u64)];
    let tag = mac_compute(key, &m);
    assert_eq!(
        dec(tag),
        "83483476632619605001810600041749983961166824905670904509823254115267351440",
    );
    assert!(mac_verify(key, &m, tag));
}

/// Vector 3: small structured message `[1, 2, 3, 4]`.
#[test]
fn fixture_vector_3_small_message() {
    let key = alice_bob_mac_key();
    let m = [
        Fq::from(1u64),
        Fq::from(2u64),
        Fq::from(3u64),
        Fq::from(4u64),
    ];
    let tag = mac_compute(key, &m);
    assert_eq!(
        dec(tag),
        "19959040651903833489024164256692762142561345502386131858898218371248838287538",
    );
    assert!(mac_verify(key, &m, tag));
}

/// Vector 4: 9-element message `[1..=9]`.
#[test]
fn fixture_vector_4_nine_element_message() {
    let key = alice_bob_mac_key();
    let m: Vec<Fq> = (1u64..=9).map(Fq::from).collect();
    let tag = mac_compute(key, &m);
    assert_eq!(
        dec(tag),
        "21372504646644668171584038078143205540789048079810990041830821947945838102294",
    );
    assert!(mac_verify(key, &m, tag));
}

/// Vector 5: MAC over the canonical ciphertext from
/// `babyjub-cipher.md` Vector 3 — the encrypt-then-MAC envelope.
#[test]
fn fixture_vector_5_encrypt_then_mac() {
    let cipher_key = alice_bob_cipher_key();
    let mac_key = alice_bob_mac_key();
    let pt = [
        Fq::from(1u64),
        Fq::from(2u64),
        Fq::from(3u64),
        Fq::from(4u64),
    ];
    let ct = encrypt(cipher_key, &pt);
    let tag = mac_compute(mac_key, &ct);
    assert_eq!(
        dec(tag),
        "16162720997808794646235033165738484245710842752524771795771394985271256269398",
    );
    assert!(mac_verify(mac_key, &ct, tag));
}

/// Vector 6: same message as Vector 3, but under the cipher-role
/// key. MUST differ from Vector 3 — pins key-dependence.
#[test]
fn fixture_vector_6_cipher_role_key() {
    let key = alice_bob_cipher_key();
    let m = [
        Fq::from(1u64),
        Fq::from(2u64),
        Fq::from(3u64),
        Fq::from(4u64),
    ];
    let tag = mac_compute(key, &m);
    assert_eq!(
        dec(tag),
        "4052831540585470231953709742711952097170537538075536978551751398089530481570",
    );
    assert!(mac_verify(key, &m, tag));
}

/// Cross-construction: tag under MAC-role key vs cipher-role key
/// on same message MUST differ.
#[test]
fn mac_and_cipher_role_tags_diverge() {
    let m = [
        Fq::from(1u64),
        Fq::from(2u64),
        Fq::from(3u64),
        Fq::from(4u64),
    ];
    let t_mac = mac_compute(alice_bob_mac_key(), &m);
    let t_enc = mac_compute(alice_bob_cipher_key(), &m);
    assert_ne!(t_mac, t_enc);
}

/// Tampering with the message under the correct key fails to
/// verify. The integrity property.
#[test]
fn verify_rejects_tampered_message() {
    let key = alice_bob_mac_key();
    let m = [
        Fq::from(1u64),
        Fq::from(2u64),
        Fq::from(3u64),
        Fq::from(4u64),
    ];
    let tag = mac_compute(key, &m);
    let tampered = [
        Fq::from(1u64),
        Fq::from(2u64),
        Fq::from(3u64),
        Fq::from(5u64),
    ];
    assert!(!mac_verify(key, &tampered, tag));
}
