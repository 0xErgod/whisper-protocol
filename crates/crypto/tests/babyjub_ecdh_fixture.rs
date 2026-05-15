//! Cross-language compatibility fixture for `babyjub-ecdh-v1`.
//!
//! Executable form of `specs/babyjub-ecdh.md § Worked Example`. The
//! pinned shared-point decimals are what conformant implementations in
//! any language (Rust, future Rust circuit, TypeScript via WASM) must
//! reproduce.
//!
//! As with the other fixtures, this lives in `tests/` and goes through
//! the crate's public API — exactly the surface the WASM boundary
//! exercises.

use crypto::babyjub::{keypair_from_seed, point_to_strings, shared_secret, Seed};

/// Build the spec's Alice / Bob seeds (one-byte-different from all
/// zeros). Single helper for clarity.
fn seed_with_byte_zero(byte: u8) -> Seed {
    let mut bytes = [0u8; 64];
    bytes[0] = byte;
    Seed::from_bytes(bytes)
}

/// Both `sk_Alice · PK_Bob` and `sk_Bob · PK_Alice` must land on the
/// exact decimal coordinates pinned by `specs/babyjub-ecdh.md`. This is
/// the load-bearing test: if the shared point drifts from these
/// decimals, no JS-side counterpart will agree.
#[test]
fn ecdh_shared_point_matches_spec() {
    let (sk_a, pk_a) = keypair_from_seed(&seed_with_byte_zero(1));
    let (sk_b, pk_b) = keypair_from_seed(&seed_with_byte_zero(2));

    let shared_ab = point_to_strings(&shared_secret(&sk_a, &pk_b));
    let shared_ba = point_to_strings(&shared_secret(&sk_b, &pk_a));

    let want_x =
        "4441722070262887487676852990759346353102280890264110527729805261601919952792";
    let want_y =
        "18505774984025635106527431283405915983682689754171973024874112571296549171475";

    assert_eq!(shared_ab.x, want_x, "sk_A · PK_B x drifted from spec");
    assert_eq!(shared_ab.y, want_y, "sk_A · PK_B y drifted from spec");
    assert_eq!(shared_ba.x, want_x, "sk_B · PK_A x drifted from spec");
    assert_eq!(shared_ba.y, want_y, "sk_B · PK_A y drifted from spec");
}

/// The spec's Alice public key must match its pinned decimals. The
/// keypair fixture already covers all-zero / all-0x42 / increasing
/// seeds; this adds the `[0x01, 0, ..., 0]` and `[0x02, 0, ..., 0]`
/// seeds used by ECDH, so the ECDH fixture is internally consistent
/// with the public keys it implicitly depends on.
#[test]
fn ecdh_alice_and_bob_public_keys_match_spec() {
    let (_, pk_a) = keypair_from_seed(&seed_with_byte_zero(1));
    let (_, pk_b) = keypair_from_seed(&seed_with_byte_zero(2));
    let pa = point_to_strings(pk_a.point());
    let pb = point_to_strings(pk_b.point());

    assert_eq!(
        pa.x,
        "5973620972294513314673339121277153508734624544832413721485350068184114274974",
    );
    assert_eq!(
        pa.y,
        "17578450795250715997356049057547570616306557704415636814477109373899234445795",
    );
    assert_eq!(
        pb.x,
        "10663274534402736726963618346545626675833419329443596343571402089744699622013",
    );
    assert_eq!(
        pb.y,
        "17118641971790752267450378861266165944315881057953088539621212593641527445102",
    );
}
