//! Cross-language compatibility fixture for
//! [`specs/protocol-commitment.md § Worked Example`](../../specs/protocol-commitment.md).
//!
//! Pins the commitment point a `text-utf8-v1` payload `[1,2,3,4]`
//! under blinding 12345 produces. The encoding id at position 0
//! makes this point distinct from a bare babyjub-pedersen commit
//! to the same `[1,2,3,4]` stream — that distinctness IS the
//! cross-encoding binding, and the pinned decimals lock it.
//!
//! If these drift, every conformant implementation (Rust, future
//! Move, future TS) is producing a commitment that won't
//! interoperate. Integration test (in `tests/`) by design.

use ark_ff::PrimeField;

use crypto::babyjub::{point_to_strings, Fq, Fr};
use crypto::encoding::{id::encoding_id, Payload};
use protocol::commitment::{commit, verify_opening};

/// The spec's pinned text-utf8-v1 payload [1,2,3,4].
fn fixture_payload() -> Payload {
    Payload::new(
        encoding_id("specs/encodings/text-utf8-v1.md"),
        vec![
            Fq::from(1u64),
            Fq::from(2u64),
            Fq::from(3u64),
            Fq::from(4u64),
        ],
    )
}

const BLINDING: u64 = 12345;

/// Sanity: the text-utf8-v1 encoding id matches the decimal
/// pinned in both `specs/encodings/payload.md` and
/// `specs/protocol-commitment.md`. If this drifts, the spec
/// path changed or the id construction changed — either way the
/// worked examples below are computed against the wrong id.
#[test]
fn text_utf8_v1_encoding_id_matches_spec() {
    let eid = encoding_id("specs/encodings/text-utf8-v1.md");
    assert_eq!(
        eid.into_bigint().to_string(),
        "10251905648233427808659162032937842155138269080868533503078341140126603942221",
    );
}

/// The commitment point matches the spec's worked example
/// byte-for-byte. A function of the augmented stream
/// `[encoding_id, 1, 2, 3, 4]` and the protocol's pinned
/// Pedersen generators.
#[test]
fn commitment_point_matches_spec() {
    let c = commit(&fixture_payload(), Fr::from(BLINDING));
    let s = point_to_strings(&c.point);
    assert_eq!(
        s.x,
        "8508428564166497174489599186311549407051130495712383842299767402731906828819",
    );
    assert_eq!(
        s.y,
        "3553708636932923270760553972757244610543695524520017929354621266609419728587",
    );
}

/// The commitment carries the payload's encoding id as public
/// metadata.
#[test]
fn commitment_carries_encoding_id() {
    let c = commit(&fixture_payload(), Fr::from(BLINDING));
    assert_eq!(
        c.encoding_id.into_bigint().to_string(),
        "10251905648233427808659162032937842155138269080868533503078341140126603942221",
    );
}

/// Round trip: the fixture commitment verifies against the
/// fixture payload + blinding.
#[test]
fn fixture_commitment_verifies() {
    let p = fixture_payload();
    let c = commit(&p, Fr::from(BLINDING));
    assert!(verify_opening(&c, &p, Fr::from(BLINDING)));
}

/// Cross-encoding defense at the fixture level: the same stream
/// `[1,2,3,4]` under a DIFFERENT encoding id produces a
/// different point than the pinned one. Confirms the id is bound
/// into the committed value, not just attached.
#[test]
fn different_encoding_id_changes_the_pinned_point() {
    // A made-up encoding id distinct from text-utf8-v1's.
    let other = Payload::new(
        encoding_id("specs/encodings/some-other-encoding-v1.md"),
        vec![
            Fq::from(1u64),
            Fq::from(2u64),
            Fq::from(3u64),
            Fq::from(4u64),
        ],
    );
    let c_other = commit(&other, Fr::from(BLINDING));
    let s_other = point_to_strings(&c_other.point);
    // Must NOT equal the pinned text-utf8-v1 point.
    assert_ne!(
        s_other.x,
        "8508428564166497174489599186311549407051130495712383842299767402731906828819",
    );
}
