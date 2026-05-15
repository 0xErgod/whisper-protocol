//! Cross-language compatibility fixture for `babyjub-pedersen-v1`.
//!
//! Executable form of `specs/babyjub-pedersen.md § Worked Example`. If
//! `H` drifts, or the commitment construction changes, or the field
//! scalar reduction shifts, these tests fail. Integration test (in
//! `tests/`) by design — exercises the crate's public API exactly the
//! way the WASM boundary will.

use ark_ec::CurveGroup;
use ark_ec::twisted_edwards::Projective;

use crypto::babyjub::{
    commit, h_generator, point_to_strings, Fr,
};

/// The pinned `H` decimals from `specs/babyjub-pedersen.md § Derivation
/// (result)`. If the derivation procedure drifts — wrong domain string,
/// wrong sign-bit convention, wrong cofactor-clearing — these change
/// and the test fails.
#[test]
fn h_matches_spec() {
    let h = point_to_strings(&h_generator());
    assert_eq!(
        h.x,
        "841592716755229802932648006577806087532565884664794707633999447952449024030",
    );
    assert_eq!(
        h.y,
        "21165608275098473985804540174915770236470038226241417420449949757110115410790",
    );
}

/// Vector 1: `value = 1, blinding = 2`.
#[test]
fn fixture_vector_1() {
    let c = point_to_strings(&commit(Fr::from(1u64), Fr::from(2u64)));
    assert_eq!(
        c.x,
        "19911656000857052962597456184037789990217243984679140824149869840037557852443",
    );
    assert_eq!(
        c.y,
        "34605269953567020705948092501852398380697724299788400696888085852242656086",
    );
}

/// Vector 2: same value, different blinding -> different commitment.
#[test]
fn fixture_vector_2() {
    let c = point_to_strings(&commit(Fr::from(1u64), Fr::from(3u64)));
    assert_eq!(
        c.x,
        "9723198969615360247427292934898140973342948570751173978342403991207916323546",
    );
    assert_eq!(
        c.y,
        "19044047517359543872210876966731992607318248008643325810704580417544715049471",
    );
}

/// Vector 3: `value = 42, blinding = 2`.
#[test]
fn fixture_vector_3() {
    let c = point_to_strings(&commit(Fr::from(42u64), Fr::from(2u64)));
    assert_eq!(
        c.x,
        "1804774864997895270957637913205168337534034589478355406223869248964063078669",
    );
    assert_eq!(
        c.y,
        "17220584685130698597038207882485107316548594410613344843261730748713825165424",
    );
}

/// Vector 4: `value = 43, blinding = 5`.
#[test]
fn fixture_vector_4() {
    let c = point_to_strings(&commit(Fr::from(43u64), Fr::from(5u64)));
    assert_eq!(
        c.x,
        "9316700122791050606807820069898233419825981554378647093992330639267548556400",
    );
    assert_eq!(
        c.y,
        "8709108737583240974862181978592935408278162780419237157205423253882576286426",
    );
}

/// Vector 5: `commit(85, 7)` as both an explicit commitment AND the
/// group sum of vectors 3 + 4. This is the spec's worked-example proof
/// of the additive-homomorphism property: a conformant implementation
/// MUST produce the same point both ways.
#[test]
fn fixture_vector_5_via_explicit_commitment() {
    let c = point_to_strings(&commit(Fr::from(85u64), Fr::from(7u64)));
    assert_eq!(
        c.x,
        "6870881176262591255209957784559476352128178258958653506281010548778139552124",
    );
    assert_eq!(
        c.y,
        "21358251945557300339181094850512781582761528410355366539487020884672487905717",
    );
}

#[test]
fn fixture_vector_5_via_group_sum() {
    let c3 = commit(Fr::from(42u64), Fr::from(2u64));
    let c4 = commit(Fr::from(43u64), Fr::from(5u64));
    let sum = (Projective::from(c3) + Projective::from(c4)).into_affine();
    let c5_explicit = commit(Fr::from(85u64), Fr::from(7u64));
    assert_eq!(
        sum, c5_explicit,
        "additive homomorphism: commit(a, r_a) + commit(b, r_b) must equal \
         commit(a+b, r_a+r_b)",
    );
}
