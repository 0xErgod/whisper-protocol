//! Vector Pedersen commitment to a payload, with the payload's
//! encoding id cryptographically bound.
//!
//! Implements [`specs/protocol-commitment.md`](../../specs/protocol-commitment.md).
//!
//! ## Shape
//!
//! ```text
//! commitment = { encoding_id, point }
//! point      = commit([encoding_id, ...stream], blinding)
//! ```
//!
//! The encoding id is committed as the **first element** (slot
//! `G_0`), so the payload elements shift to `G_1..G_n`. This binds
//! the id by the same binding property that protects every payload
//! element — a commitment cannot be opened to a different encoding
//! without breaking binding. See the spec's "Why the encoding id is
//! bound (Option 2), not attached" for the rationale (informative,
//! expressive, and enabling vs. an unauthenticated label or a
//! bespoke tag point).
//!
//! Two free functions:
//!
//! - [`commit`] — payload + blinding → [`Commitment`].
//! - [`verify_opening`] — does this commitment open to this payload
//!   under this blinding?
//!
//! Both are thin compositions of `crypto::babyjub::commit`. The
//! construction rule (id-at-position-0) is the only protocol claim
//! they add over the bare Pedersen primitive.

use crypto::babyjub::{commit as pedersen_commit, EdwardsAffine, Fq, Fr};
use crypto::encoding::Payload;

/// A binding, hiding commitment to a payload.
///
/// `encoding_id` is public metadata AND bound inside `point` (it's
/// the position-0 committed element). Equality compares both
/// fields.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Commitment {
    /// The registry id of the payload's encoding. Public; also the
    /// position-0 committed element inside `point`.
    pub encoding_id: Fq,
    /// The Pedersen commitment point: `commit([encoding_id,
    /// ...stream], blinding)`.
    pub point: EdwardsAffine,
}

/// Build the augmented stream `[encoding_id, ...stream]` that the
/// commitment actually commits to. Internal helper shared by
/// [`commit`] and [`verify_opening`] so the id-prepend rule lives
/// in exactly one place.
fn augmented_stream(payload: &Payload) -> Vec<Fq> {
    let mut augmented = Vec::with_capacity(1 + payload.stream.len());
    augmented.push(payload.encoding_id);
    augmented.extend_from_slice(&payload.stream);
    augmented
}

/// Commit to a payload under a blinding scalar.
///
/// Mirrors [`specs/protocol-commitment.md § Committing`](../../specs/protocol-commitment.md):
/// prepends the encoding id to the stream, runs the vector Pedersen
/// commitment over the augmented stream.
///
/// Total — any payload, any blinding. Does NOT validate that the
/// payload's stream is a well-formed output of its encoding; a
/// malformed payload commits fine but won't decode (validity is the
/// encoding's concern, checked at decode time).
///
/// **The caller is responsible for `blinding`.** Sample it from a
/// CSPRNG; never reuse it across commitments to different payloads.
pub fn commit(payload: &Payload, blinding: Fr) -> Commitment {
    let point = pedersen_commit(&augmented_stream(payload), blinding);
    Commitment {
        encoding_id: payload.encoding_id,
        point,
    }
}

/// Verify that `commitment` opens to `payload` under `blinding`.
///
/// Recomputes the commitment and compares — same discipline as the
/// underlying `babyjub-pedersen` (no separate verify machinery,
/// just recompute-and-compare). Both the point AND the encoding id
/// must match; the explicit id check defends against a malformed
/// `Commitment` whose metadata id disagrees with its committed id.
pub fn verify_opening(commitment: &Commitment, payload: &Payload, blinding: Fr) -> bool {
    let expected = commit(payload, blinding);
    expected.point == commitment.point && expected.encoding_id == commitment.encoding_id
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto::babyjub::Fq;

    fn payload(encoding_id: u64, stream: &[u64]) -> Payload {
        Payload::new(
            Fq::from(encoding_id),
            stream.iter().map(|&x| Fq::from(x)).collect(),
        )
    }

    /// commit then verify_opening with the same payload + blinding
    /// accepts. The defining property.
    #[test]
    fn commit_then_verify_accepts() {
        let p = payload(7, &[1, 2, 3, 4]);
        let blinding = Fr::from(12345u64);
        let c = commit(&p, blinding);
        assert!(verify_opening(&c, &p, blinding));
    }

    /// The committed point binds the encoding id: a commitment to
    /// the same stream under a different encoding id is a different
    /// point. The cross-encoding defense at the commitment layer.
    #[test]
    fn different_encoding_id_yields_different_point() {
        let blinding = Fr::from(7u64);
        let c_a = commit(&payload(100, &[1, 2, 3]), blinding);
        let c_b = commit(&payload(200, &[1, 2, 3]), blinding);
        assert_ne!(c_a.point, c_b.point);
    }

    /// verify_opening rejects a payload claiming a different
    /// encoding id, even with the same stream and blinding. Pins
    /// that the id is part of what's verified.
    #[test]
    fn verify_rejects_wrong_encoding_id() {
        let blinding = Fr::from(7u64);
        let c = commit(&payload(100, &[1, 2, 3]), blinding);
        // Same stream, same blinding, different claimed id.
        let wrong = payload(200, &[1, 2, 3]);
        assert!(!verify_opening(&c, &wrong, blinding));
    }

    /// verify_opening rejects a tampered stream element.
    #[test]
    fn verify_rejects_wrong_stream() {
        let blinding = Fr::from(7u64);
        let c = commit(&payload(7, &[1, 2, 3, 4]), blinding);
        let tampered = payload(7, &[1, 2, 3, 5]);
        assert!(!verify_opening(&c, &tampered, blinding));
    }

    /// verify_opening rejects a wrong blinding.
    #[test]
    fn verify_rejects_wrong_blinding() {
        let p = payload(7, &[1, 2, 3, 4]);
        let c = commit(&p, Fr::from(7u64));
        assert!(!verify_opening(&c, &p, Fr::from(8u64)));
    }

    /// The empty-stream payload commits and verifies: the point is
    /// `encoding_id · G_0 + blinding · H` — a "no content" payload
    /// commitment that still binds its encoding id.
    #[test]
    fn empty_stream_commits_and_verifies() {
        let p = payload(7, &[]);
        let blinding = Fr::from(99u64);
        let c = commit(&p, blinding);
        assert!(verify_opening(&c, &p, blinding));
    }

    /// The commitment's encoding_id field equals the payload's.
    #[test]
    fn commitment_carries_payload_encoding_id() {
        let p = payload(42, &[1]);
        let c = commit(&p, Fr::from(1u64));
        assert_eq!(c.encoding_id, Fq::from(42u64));
    }
}
