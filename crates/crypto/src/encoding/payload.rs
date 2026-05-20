//! The payload: an encoded field-element stream paired with the
//! id of the encoding that produced it.
//!
//! Implements [`specs/encodings/payload.md`](../../../specs/encodings/payload.md).
//!
//! A [`Payload`] is the unit envelopes seal, commitments commit to,
//! and circuits prove statements about. It makes explicit the
//! "plaintext + encoding" pairing the codebase had been passing
//! around as a bare `Vec<Fq>` with the encoding tracked only by
//! convention.
//!
//! - `stream` is the "plaintext on the curve" — the field elements
//!   an encoding's `encode` produced.
//! - `encoding_id` is "how it was put on the curve, and how to
//!   recover the original form" — the registry id that names the
//!   encoding, so a consumer can dispatch to the right decoder.
//!
//! The `encoding_id` is **public metadata** (see the spec's privacy
//! section): it travels in the clear with ciphertexts and
//! commitments, authenticated but not encrypted, because a
//! recipient must know the encoding before decrypting in order to
//! pick a decoder.

use crate::babyjub::Fq;

use super::{BytePayloadEncoding, EncodingError, FieldStream};

/// An encoded payload: a field-element stream tagged with the id of
/// the encoding that produced it.
///
/// The pairing is a pure bundling — no hashing, no transformation.
/// Equality compares both the id and the stream, so two payloads
/// are equal iff they're the same stream under the same encoding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Payload {
    /// The registry id of the encoding that produced `stream`.
    /// Public metadata.
    pub encoding_id: Fq,
    /// The encoded field-element stream — the plaintext on the
    /// curve.
    pub stream: Vec<Fq>,
}

impl Payload {
    /// Bundle an encoding id and a stream into a payload.
    ///
    /// Does not validate that `stream` is actually a well-formed
    /// output of the encoding named by `encoding_id` — that's
    /// checked by decoding, not by construction. A payload built
    /// with a mismatched id/stream pair will fail to decode under
    /// the encoding its id names.
    pub fn new(encoding_id: Fq, stream: Vec<Fq>) -> Self {
        Payload {
            encoding_id,
            stream,
        }
    }

    /// Encode `input` via the encoding `E`, tagging the result with
    /// `E`'s registry id.
    ///
    /// The canonical way to produce a payload: the id and the stream
    /// come from the same encoding by construction, so the pairing
    /// is guaranteed consistent.
    pub fn encode<E: BytePayloadEncoding>(input: &[u8]) -> Result<Self, EncodingError> {
        let stream = E::encode(input)?;
        Ok(Payload {
            encoding_id: E::id(),
            stream: stream.fields().to_vec(),
        })
    }

    /// Decode this payload's stream via the encoding `E`, recovering
    /// the original bytes.
    ///
    /// **Errors with [`EncodingError::WrongEncoding`] if `E::id()`
    /// does not match `self.encoding_id`.** This is the type-level
    /// cross-encoding-confusion defense: you cannot decode a
    /// `text-utf8-v1` payload by passing the `KvPairsV1` type,
    /// because the ids won't match. The check happens before any
    /// decode work, so a mismatched encoding can't even attempt to
    /// reinterpret the stream.
    pub fn decode<E: BytePayloadEncoding>(&self) -> Result<Vec<u8>, EncodingError> {
        if E::id() != self.encoding_id {
            use ark_ff::PrimeField;
            return Err(EncodingError::WrongEncoding {
                payload: self.encoding_id.into_bigint().to_string(),
                decoder: E::id().into_bigint().to_string(),
            });
        }
        let stream = FieldStream::from_vec(self.stream.clone());
        E::decode(&stream)
    }

    /// Borrow the stream as a slice — the form the protocol's
    /// primitives (cipher, MAC, commitment) consume.
    pub fn fields(&self) -> &[Fq] {
        &self.stream
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encoding::id::encoding_id;

    // A minimal in-test encoding so the payload tests don't depend
    // on the `text-utf8-v1` crate (which would be a dependency cycle:
    // text-utf8-v1 depends on crypto). This mirrors just enough of
    // BytePayloadEncoding to exercise Payload's id-matching logic.
    struct FakeEncodingA;
    struct FakeEncodingB;

    impl BytePayloadEncoding for FakeEncodingA {
        const FIELD_COUNT: usize = 2;
        fn id() -> Fq {
            encoding_id("specs/encodings/fake-a-v1.md")
        }
        fn encode(input: &[u8]) -> Result<FieldStream, EncodingError> {
            // Trivial: one field for the length, one for the first
            // byte (or zero). Enough to round-trip a 0- or 1-byte
            // input deterministically.
            if input.len() > 1 {
                return Err(EncodingError::InvalidInput("fake-a accepts <= 1 byte"));
            }
            let len = Fq::from(input.len() as u64);
            let byte = Fq::from(input.first().copied().unwrap_or(0) as u64);
            Ok(FieldStream::from_vec(vec![len, byte]))
        }
        fn decode(stream: &FieldStream) -> Result<Vec<u8>, EncodingError> {
            use ark_ff::PrimeField;
            let fields = stream.fields();
            if fields.len() != Self::FIELD_COUNT {
                return Err(EncodingError::WrongFieldCount {
                    expected: Self::FIELD_COUNT,
                    actual: fields.len(),
                });
            }
            let len = fields[0].into_bigint().0[0];
            if len == 0 {
                Ok(vec![])
            } else {
                Ok(vec![fields[1].into_bigint().0[0] as u8])
            }
        }
        fn validate_structural(stream: &FieldStream) -> bool {
            stream.fields().len() == Self::FIELD_COUNT
        }
    }

    impl BytePayloadEncoding for FakeEncodingB {
        const FIELD_COUNT: usize = 2;
        fn id() -> Fq {
            encoding_id("specs/encodings/fake-b-v1.md")
        }
        fn encode(input: &[u8]) -> Result<FieldStream, EncodingError> {
            FakeEncodingA::encode(input)
        }
        fn decode(stream: &FieldStream) -> Result<Vec<u8>, EncodingError> {
            FakeEncodingA::decode(stream)
        }
        fn validate_structural(stream: &FieldStream) -> bool {
            FakeEncodingA::validate_structural(stream)
        }
    }

    /// Encoding via `Payload::encode` tags the stream with the
    /// encoding's id and round-trips through `decode`.
    #[test]
    fn encode_then_decode_roundtrips() {
        let payload = Payload::encode::<FakeEncodingA>(b"x").expect("encode ok");
        assert_eq!(payload.encoding_id, FakeEncodingA::id());
        let recovered = payload.decode::<FakeEncodingA>().expect("decode ok");
        assert_eq!(recovered, b"x");
    }

    /// The empty input round-trips too.
    #[test]
    fn empty_input_roundtrips() {
        let payload = Payload::encode::<FakeEncodingA>(b"").expect("encode ok");
        let recovered = payload.decode::<FakeEncodingA>().expect("decode ok");
        assert!(recovered.is_empty());
    }

    /// Decoding a payload under the WRONG encoding fails with
    /// `WrongEncoding`, before any decode work runs. The
    /// cross-encoding-confusion defense.
    ///
    /// FakeEncodingA and FakeEncodingB have identical stream shapes
    /// (both 2 fields, same layout) but different ids — exactly the
    /// dangerous case where confusion would otherwise succeed.
    #[test]
    fn decode_under_wrong_encoding_rejected() {
        let payload = Payload::encode::<FakeEncodingA>(b"x").expect("encode ok");
        // The stream IS structurally decodable as FakeEncodingB
        // (same shape), but the id guard catches it first.
        let err = payload.decode::<FakeEncodingB>().unwrap_err();
        assert!(matches!(err, EncodingError::WrongEncoding { .. }));
    }

    /// `Payload::new` with a mismatched id/stream pair builds, but
    /// fails to decode under the named encoding. Pins that `new`
    /// does not validate the pairing (by design) and that `decode`
    /// is where the id check lives.
    #[test]
    fn new_with_mismatched_id_fails_to_decode() {
        let stream = FakeEncodingA::encode(b"x").unwrap().fields().to_vec();
        // Tag the FakeEncodingA stream with FakeEncodingB's id.
        let payload = Payload::new(FakeEncodingB::id(), stream);
        // Decoding as A fails (id mismatch); decoding as B "works"
        // structurally because the shapes match, which is exactly
        // why the id binding matters — without it, this confusion
        // would be silent.
        let err = payload.decode::<FakeEncodingA>().unwrap_err();
        assert!(matches!(err, EncodingError::WrongEncoding { .. }));
    }

    /// `fields()` exposes the stream as a slice for the protocol's
    /// primitives.
    #[test]
    fn fields_exposes_stream() {
        let payload = Payload::encode::<FakeEncodingA>(b"x").expect("encode ok");
        assert_eq!(payload.fields().len(), FakeEncodingA::FIELD_COUNT);
    }
}
