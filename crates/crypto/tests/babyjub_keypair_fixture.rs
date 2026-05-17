//! Cross-language compatibility fixture for `babyjub-keypair-v1`.
//!
//! These tests are the executable form of `specs/babyjub-keypair.md §
//! Worked Example`. If the derivation drifts — wrong domain tag, wrong
//! chunking, wrong Poseidon parameters, wrong field reduction — these
//! fail. As with the curve fixture, they live in `tests/` (an integration
//! test) and exercise the crate through its public API exactly as the WASM
//! binding will.
//!
//! The fixture asserts `PK` only: `Base8` is injective on `F_l`, so a
//! matching public key uniquely pins the secret scalar (the discrete log
//! in the prime-order subgroup is unique). Asserting `sk` would require
//! exposing it through the public API, which the current scope does not
//! want — production never reads `sk` back, it only ever uses it to
//! sign/decrypt.

use crypto::babyjub::{
    is_in_prime_subgroup, is_on_curve, keypair_from_seed, point_to_strings, Seed,
};

/// Build an "increasing" 64-byte seed: `[0x01, 0x02, ..., 0x40]`.
fn increasing_seed() -> [u8; 64] {
    let mut b = [0u8; 64];
    for (i, byte) in b.iter_mut().enumerate() {
        *byte = (i + 1) as u8;
    }
    b
}

/// Seed of all zeros. Spec § Worked Example, vector 1.
#[test]
fn fixture_all_zero_seed() {
    let (_, pk) = keypair_from_seed(&Seed::from_bytes([0u8; 64]));
    let s = point_to_strings(pk.point());
    assert_eq!(
        s.x,
        "9052145210158052161818611168469442415783119048928084171117132839267951576749",
    );
    assert_eq!(
        s.y,
        "15138733388225546515036950290042250293266309799081989529651843475752774394912",
    );
}

/// Seed of `0x42 × 64`. Spec § Worked Example, vector 2.
#[test]
fn fixture_all_0x42_seed() {
    let (_, pk) = keypair_from_seed(&Seed::from_bytes([0x42u8; 64]));
    let s = point_to_strings(pk.point());
    assert_eq!(
        s.x,
        "10242056643687748052026914853801031667608768151841054399444813507230536137636",
    );
    assert_eq!(
        s.y,
        "17209935276727295699825960001966777169457960631433628415363271904988532178005",
    );
}

/// Seed `[0x01, 0x02, ..., 0x40]`. Spec § Worked Example, vector 3.
/// Catches a byte-order mistake in the chunking (e.g. reading
/// `seed[32..64]` as `seed[0..32]`) that a single-symbol fixture would not.
#[test]
fn fixture_increasing_seed() {
    let (_, pk) = keypair_from_seed(&Seed::from_bytes(increasing_seed()));
    let s = point_to_strings(pk.point());
    assert_eq!(
        s.x,
        "20850129809617136780643076514291815738908181923486074779130442852041357820493",
    );
    assert_eq!(
        s.y,
        "6638083023153244747644631095237619826300111037602892009430291132442244811183",
    );
}

/// Every derived public key must be on-curve and in the prime-order
/// subgroup. The keypair construction guarantees this by computing
/// `PK = sk · Base8`; this test pins it as a property an external auditor
/// can verify without trusting the construction.
#[test]
fn derived_public_key_is_valid() {
    for seed_bytes in [[0u8; 64], [0x42u8; 64], increasing_seed()] {
        let (_, pk) = keypair_from_seed(&Seed::from_bytes(seed_bytes));
        assert!(is_on_curve(pk.point()), "derived PK must be on-curve");
        assert!(
            is_in_prime_subgroup(pk.point()),
            "derived PK must be in the prime-order subgroup",
        );
    }
}
