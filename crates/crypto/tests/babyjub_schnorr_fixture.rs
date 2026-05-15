//! Cross-language compatibility fixture for `babyjub-schnorr-v1`.
//!
//! Executable form of `specs/babyjub-schnorr.md § Worked Example`. If
//! anything drifts — domain tags, nonce derivation, challenge inputs,
//! field reductions — these tests fail.
//!
//! Pinning strategy: pin the **signer's `PK`** and assert that signing
//! the spec's message vectors produces the exact `(R, s)` decimals.
//! Then for every vector, separately assert `verify` accepts the
//! pinned signature. The two halves catch different drifts: sign
//! drifts change the signature output, verify drifts (e.g. wrong
//! challenge inputs) would accept a now-wrong signature or reject the
//! pinned one.

use ark_ff::Field;

use crypto::babyjub::{
    keypair_from_seed, point_from_strings, point_to_strings, scalar_from_decimal,
    scalar_to_decimal, sign, verify, Fq, Seed, Signature,
};

fn signer_seed() -> Seed {
    let mut s = [0u8; 64];
    s[0] = 7;
    Seed::from_bytes(s)
}

/// The pinned `PK` from the spec. Anchors the seed→PK chain at this
/// fixture; if `keypair_from_seed` were to drift, the schnorr fixture
/// would still catch it here before any signature math runs.
#[test]
fn signer_pk_matches_spec() {
    let (_, pk) = keypair_from_seed(&signer_seed());
    let s = point_to_strings(pk.point());
    assert_eq!(
        s.x,
        "11164399029837664407055359313997844806901732622806579156125419783739925007983",
    );
    assert_eq!(
        s.y,
        "14592084695496273113419456967406390983505872435887630137749651140392618556302",
    );
}

/// Vector 1: `m = 1`. The pinned `(R, s)` must be exactly what `sign`
/// produces, and `verify` must accept it.
#[test]
fn fixture_vector_1_sign_matches_and_verifies() {
    let (sk, pk) = keypair_from_seed(&signer_seed());
    let m = Fq::from(1u64);
    let sig = sign(&sk, &pk, m);

    let r = point_to_strings(&sig.r);
    assert_eq!(
        r.x,
        "11632351294401981618034412607960018633759132523604891111145083805962634408526",
    );
    assert_eq!(
        r.y,
        "16437810892664933023884131539764605025844133936197983566486350081488662891513",
    );
    assert_eq!(
        scalar_to_decimal(&sig.s),
        "1812749329934557351717178747835822339686472044802696027660553171848252014907",
    );

    assert!(verify(&pk, m, &sig), "spec vector 1 must verify");
}

/// Vector 2: `m = 123456789`.
#[test]
fn fixture_vector_2_sign_matches_and_verifies() {
    let (sk, pk) = keypair_from_seed(&signer_seed());
    let m = Fq::from(123_456_789u64);
    let sig = sign(&sk, &pk, m);

    let r = point_to_strings(&sig.r);
    assert_eq!(
        r.x,
        "6375882820815417677096742276733849921405984769193898132545252656057555844260",
    );
    assert_eq!(
        r.y,
        "3047706727927232926540757222837094987678920983781058568722301670558932589075",
    );
    assert_eq!(
        scalar_to_decimal(&sig.s),
        "1672146590325984867501175997505308325917192911330920320014368257217536359444",
    );

    assert!(verify(&pk, m, &sig));
}

/// Vector 3: `m = 2^240`. Confirms a large-message-field-element
/// signature survives byte-for-byte; catches off-by-one bugs in field
/// reductions that small `m` values wouldn't exercise.
#[test]
fn fixture_vector_3_sign_matches_and_verifies() {
    let (sk, pk) = keypair_from_seed(&signer_seed());
    let m = Fq::from(2u64).pow([240]);
    let sig = sign(&sk, &pk, m);

    let r = point_to_strings(&sig.r);
    assert_eq!(
        r.x,
        "1395873755850300180104726848613996444071352053794302031425716596821856303738",
    );
    assert_eq!(
        r.y,
        "20526401082777560701041724606565419033104885953699580911324980591395500280786",
    );
    assert_eq!(
        scalar_to_decimal(&sig.s),
        "2581033176336945103238693484339366247360111711785418479474279938072861984860",
    );

    assert!(verify(&pk, m, &sig));
}

/// Reconstruct vector 1's signature from its pinned decimal strings —
/// exactly the path the WASM boundary takes — and assert `verify`
/// accepts it. Catches drifts in the wire decoders (`point_from_strings`,
/// `scalar_from_decimal`) that would corrupt a JS-supplied signature
/// before it reaches `verify`.
#[test]
fn fixture_vector_1_verify_via_wire_form() {
    let (_, pk) = keypair_from_seed(&signer_seed());
    let m = Fq::from(1u64);

    let r = point_from_strings(
        "11632351294401981618034412607960018633759132523604891111145083805962634408526",
        "16437810892664933023884131539764605025844133936197983566486350081488662891513",
    )
    .expect("R is a valid subgroup point");
    let s = scalar_from_decimal(
        "1812749329934557351717178747835822339686472044802696027660553171848252014907",
    )
    .expect("s parses as a scalar");

    assert!(verify(&pk, m, &Signature { r, s }));
}
