//! Cross-language compatibility fixture for `babyjub-kdf`.
//!
//! Executable form of `specs/babyjub-kdf.md § Worked Example`. If
//! anything drifts — domain tag, role-tag construction, point
//! decomposition, Poseidon parameters — these fail. Integration
//! test (in `tests/`) by design.
//!
//! Pinning strategy: pin the shared point (chained from the existing
//! ECDH fixture), then for each vector assert the derived key matches
//! the spec's exact decimal.

use ark_ff::PrimeField;

use crypto::babyjub::{
    kdf_derive, keypair_from_seed, point_to_strings, shared_secret, Fq, Seed,
};
use crypto::poseidon::domain_tag;

fn alice_bob_shared() -> crypto::babyjub::EdwardsAffine {
    let mut seed_a = [0u8; 64];
    seed_a[0] = 1;
    let mut seed_b = [0u8; 64];
    seed_b[0] = 2;
    let (sk_a, _) = keypair_from_seed(&Seed::from_bytes(seed_a));
    let (_, pk_b) = keypair_from_seed(&Seed::from_bytes(seed_b));
    shared_secret(&sk_a, &pk_b)
}

fn dec(f: Fq) -> String {
    f.into_bigint().to_string()
}

/// Sanity: the shared point used by this fixture must equal the one
/// `specs/babyjub-ecdh.md` already pins. If it drifts, every KDF
/// vector below is computed against the wrong input.
#[test]
fn shared_point_matches_ecdh_spec() {
    let s = point_to_strings(&alice_bob_shared());
    assert_eq!(
        s.x,
        "4441722070262887487676852990759346353102280890264110527729805261601919952792",
    );
    assert_eq!(
        s.y,
        "18505774984025635106527431283405915983682689754171973024874112571296549171475",
    );
}

/// The role tags pinned in the spec.
#[test]
fn role_tags_match_spec() {
    assert_eq!(
        dec(domain_tag("envelope-cipher-key")),
        "1509687719585944131241352475068886393759608140501623646780323187386706626075",
    );
    assert_eq!(
        dec(domain_tag("envelope-mac-key")),
        "5516219051016623209397290384142210256012461986142239137807233927652814454837",
    );
}

/// Vector 1: empty context.
#[test]
fn fixture_vector_1_empty_context() {
    let key = kdf_derive(&alice_bob_shared(), &[]).expect("empty fits");
    assert_eq!(
        dec(key),
        "17636122932579740171900542371485785762200772773883779227467254854068102551698",
    );
}

/// Vector 2: cipher-key role, envelope id 42.
#[test]
fn fixture_vector_2_cipher_key_envelope_42() {
    let ctx = [domain_tag("envelope-cipher-key"), Fq::from(42u64)];
    let key = kdf_derive(&alice_bob_shared(), &ctx).expect("ok");
    assert_eq!(
        dec(key),
        "9799522521534548758133939899702695884003167902663631833387651174524282263857",
    );
}

/// Vector 3: mac-key role, envelope id 42. MUST differ from vector
/// 2 — the load-bearing role-separation property.
#[test]
fn fixture_vector_3_mac_key_envelope_42() {
    let ctx = [domain_tag("envelope-mac-key"), Fq::from(42u64)];
    let key = kdf_derive(&alice_bob_shared(), &ctx).expect("ok");
    assert_eq!(
        dec(key),
        "5302105009719633730025155498822445041452574923386899996802294480945238328306",
    );
}

/// The explicit cross-check: vectors 2 and 3 share everything except
/// the role tag, and they MUST produce distinct keys.
#[test]
fn cipher_and_mac_keys_for_same_envelope_are_distinct() {
    let shared = alice_bob_shared();
    let k_enc = kdf_derive(
        &shared,
        &[domain_tag("envelope-cipher-key"), Fq::from(42u64)],
    )
    .expect("ok");
    let k_mac = kdf_derive(
        &shared,
        &[domain_tag("envelope-mac-key"), Fq::from(42u64)],
    )
    .expect("ok");
    assert_ne!(k_enc, k_mac, "cipher and mac keys MUST differ");
}

/// Vector 4: cipher-key role, envelope id 43. Same role as vector 2,
/// different envelope.
#[test]
fn fixture_vector_4_cipher_key_envelope_43() {
    let ctx = [domain_tag("envelope-cipher-key"), Fq::from(43u64)];
    let key = kdf_derive(&alice_bob_shared(), &ctx).expect("ok");
    assert_eq!(
        dec(key),
        "3185156709054186265396033369944106490450552430667171551230702264382884908002",
    );
}

/// Vector 5: max-length context (9 elements).
#[test]
fn fixture_vector_5_max_length_context() {
    let ctx: Vec<Fq> = (1u64..=9).map(Fq::from).collect();
    let key = kdf_derive(&alice_bob_shared(), &ctx).expect("9-element context fits");
    assert_eq!(
        dec(key),
        "14698107046409286502950871063352220665802808368062148839547149322586317350782",
    );
}

/// Over-length context: typed error from the underlying Poseidon
/// fixed-arity call. Pins the boundary.
#[test]
fn over_length_context_returns_typed_error() {
    let ctx: Vec<Fq> = (1u64..=10).map(Fq::from).collect();
    assert!(
        kdf_derive(&alice_bob_shared(), &ctx).is_err(),
        "10-element context must error",
    );
}
