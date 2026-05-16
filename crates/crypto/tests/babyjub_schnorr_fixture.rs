//! Cross-language compatibility fixture for `babyjub-schnorr`.
//!
//! Executable form of `specs/babyjub-schnorr.md § Worked Example`.
//! If anything drifts — domain tags, message-hash construction,
//! nonce derivation, challenge inputs, field reductions — these
//! fail. Integration tests (in `tests/`) by design — exercise the
//! crate's public API exactly as the WASM boundary will.
//!
//! Pinning strategy: pin the **signer's `PK`** and assert that
//! signing each spec message stream produces the exact pinned
//! `(R, s)` decimals. Then for every vector, separately assert that
//! `verify` accepts the pinned signature. The two halves catch
//! different drifts.

use crypto::babyjub::{
    keypair_from_seed, point_from_strings, point_to_strings, scalar_from_decimal,
    scalar_to_decimal, sign, verify, Fq, SchnorrError, Seed, Signature,
};

fn signer_seed() -> Seed {
    let mut s = [0u8; 64];
    s[0] = 7;
    Seed::from_bytes(s)
}

/// Pinned PK from the spec. Anchors the seed → PK chain here, so a
/// keypair drift would surface before any signature math runs.
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

/// Vector 1: empty message.
#[test]
fn fixture_vector_1_empty_sign_matches_and_verifies() {
    let (sk, pk) = keypair_from_seed(&signer_seed());
    let message: &[Fq] = &[];
    let sig = sign(&sk, &pk, message).expect("empty is valid");

    let r = point_to_strings(&sig.r);
    assert_eq!(
        r.x,
        "19672181936203324131656225559501475555772993461869651448031019731729494125516",
    );
    assert_eq!(
        r.y,
        "13566859200123542336948177722573650541027744755873253525080581171534205128273",
    );
    assert_eq!(
        scalar_to_decimal(&sig.s),
        "585729486597474274390090641694341699325329864890452131536921756383744534588",
    );

    assert!(verify(&pk, message, &sig).expect("ok"));
}

/// Vector 2: single-element message `[42]`. Demonstrates this is a
/// different scheme from signing the bare field element `42`.
#[test]
fn fixture_vector_2_single_element_sign_matches_and_verifies() {
    let (sk, pk) = keypair_from_seed(&signer_seed());
    let message = [Fq::from(42u64)];
    let sig = sign(&sk, &pk, &message).expect("ok");

    let r = point_to_strings(&sig.r);
    assert_eq!(
        r.x,
        "14463837123490585712352081519964757127730117503535410223157071561987752976040",
    );
    assert_eq!(
        r.y,
        "14835801757202602810496014359609043970705906585033731611275274330266563989628",
    );
    assert_eq!(
        scalar_to_decimal(&sig.s),
        "1470727944428070892525141747972223984368576545003202506760627628426109537509",
    );

    assert!(verify(&pk, &message, &sig).expect("ok"));
}

/// Vector 3: `[1, 2, 3]`.
#[test]
fn fixture_vector_3_three_element_sign_matches_and_verifies() {
    let (sk, pk) = keypair_from_seed(&signer_seed());
    let message = [Fq::from(1u64), Fq::from(2u64), Fq::from(3u64)];
    let sig = sign(&sk, &pk, &message).expect("ok");

    let r = point_to_strings(&sig.r);
    assert_eq!(
        r.x,
        "4421583882441814884919433367012339810780463461595955860104800629341428551515",
    );
    assert_eq!(
        r.y,
        "685556324815791047742857456106268926562746442722529319403820029970894328632",
    );
    assert_eq!(
        scalar_to_decimal(&sig.s),
        "2480202173437343318607319337411596044484259619894416475763013773164119271331",
    );

    assert!(verify(&pk, &message, &sig).expect("ok"));
}

/// Vector 4: `[0, 1, …, 8]` — the canonical `text-utf8-v1`-shaped
/// 9-element message. This is the production-use case: a
/// `text-utf8-v1` encoded payload signed directly without an
/// external collapse step.
#[test]
fn fixture_vector_4_text_utf8_shape_sign_matches_and_verifies() {
    let (sk, pk) = keypair_from_seed(&signer_seed());
    let message: Vec<Fq> = (0u64..9).map(Fq::from).collect();
    let sig = sign(&sk, &pk, &message).expect("ok");

    let r = point_to_strings(&sig.r);
    assert_eq!(
        r.x,
        "9907919187759728836420608685439673743018415908584274981339045984432314418876",
    );
    assert_eq!(
        r.y,
        "14320670493132427095800905404319123040028993772245066136630070019717299866336",
    );
    assert_eq!(
        scalar_to_decimal(&sig.s),
        "690166825546950374194223969053258468670318750960230750355004980014353065874",
    );

    assert!(verify(&pk, &message, &sig).expect("ok"));
}

/// Vector 5: 11 elements (the maximum allowed). Pins the boundary
/// at the arity ceiling.
#[test]
fn fixture_vector_5_max_length_sign_matches_and_verifies() {
    let (sk, pk) = keypair_from_seed(&signer_seed());
    let message: Vec<Fq> = (1u64..=11).map(Fq::from).collect();
    let sig = sign(&sk, &pk, &message).expect("ok");

    let r = point_to_strings(&sig.r);
    assert_eq!(
        r.x,
        "19963310545348971650786133235255750555652125687870187620843360496751874600702",
    );
    assert_eq!(
        r.y,
        "1299550255739614117019408363067734689527566129196823495220357367769924437828",
    );
    assert_eq!(
        scalar_to_decimal(&sig.s),
        "531332205057006653850069745815249283082797922145794081647360253109887423674",
    );

    assert!(verify(&pk, &message, &sig).expect("ok"));
}

/// Vector 4 reconstructed from its pinned decimal strings via the
/// wire decoders — exactly the path the WASM boundary takes — and
/// asserts `verify` accepts. Catches drifts in `point_from_strings`
/// or `scalar_from_decimal` that would corrupt a JS-supplied
/// signature before it reaches `verify`.
#[test]
fn fixture_vector_4_verify_via_wire_form() {
    let (_, pk) = keypair_from_seed(&signer_seed());
    let message: Vec<Fq> = (0u64..9).map(Fq::from).collect();

    let r = point_from_strings(
        "9907919187759728836420608685439673743018415908584274981339045984432314418876",
        "14320670493132427095800905404319123040028993772245066136630070019717299866336",
    )
    .expect("R is a valid subgroup point");
    let s = scalar_from_decimal(
        "690166825546950374194223969053258468670318750960230750355004980014353065874",
    )
    .expect("s parses as scalar");

    assert!(verify(&pk, &message, &Signature { r, s }).expect("ok"));
}

/// Message at the cap + 1: typed error from both `sign` and
/// `verify`. Pins the API contract for the over-length case at the
/// integration level.
#[test]
fn over_length_message_returns_typed_error() {
    let (sk, pk) = keypair_from_seed(&signer_seed());
    let message: Vec<Fq> = (1u64..=12).map(Fq::from).collect();
    assert!(matches!(
        sign(&sk, &pk, &message),
        Err(SchnorrError::MessageTooLong { len: 12, max: 11 }),
    ));

    // Use any well-formed signature for the verify call; the length
    // check fires before signature math.
    let placeholder = sign(&sk, &pk, &[]).expect("empty fits");
    assert!(matches!(
        verify(&pk, &message, &placeholder),
        Err(SchnorrError::MessageTooLong { len: 12, max: 11 }),
    ));
}
