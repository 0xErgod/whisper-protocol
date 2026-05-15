//! `text-utf8-v1`: UTF-8 byte payload encoding.
//!
//! Encodes a UTF-8 byte string of at most [`MAX_BYTES`] bytes into a
//! fixed-arity stream of 9 BN254 field elements: a length prefix
//! followed by 8 chunks of 31 bytes each, zero-padded after the
//! payload. See [`specs/encodings/text-utf8-v1.md`](../../specs/encodings/text-utf8-v1.md)
//! for the canonical definition.
//!
//! NOTE(name): scheme tag `text-utf8-v1` and crate name `text-utf8-v1`
//! are working names following the path-id discipline. A breaking
//! change mints `text-utf8-v2` as a new spec + new crate; this crate
//! stays in place so old payloads remain decodable.

use ark_ff::PrimeField;

use crypto::babyjub::Fq;
use crypto::encoding::id::encoding_id;
use crypto::encoding::{BytePayloadEncoding, EncodingError, FieldStream};

/// Canonical spec path for this encoding. Used both as the
/// authoritative reference and as the input to the encoding-id
/// derivation; changing this string mints a different encoding.
pub const SPEC_PATH: &str = "specs/encodings/text-utf8-v1.md";

/// Maximum byte length of an encoded payload. 248 bytes = 8 chunks ×
/// 31 bytes; payloads of this length fit exactly into `f_1..f_8`
/// without any zero-padding bytes.
pub const MAX_BYTES: usize = 248;

/// Number of bytes per chunk. 31 because a 31-byte big-endian
/// unsigned integer always fits in BN254's 254-bit base field with
/// room to spare (the top 6 bits are always zero), so chunk-to-field
/// reduction is unambiguous and lossless.
const CHUNK_BYTES: usize = 31;

/// Number of chunks. `MAX_BYTES / CHUNK_BYTES = 248 / 31 = 8`.
const CHUNKS: usize = MAX_BYTES / CHUNK_BYTES;

/// The encoding type. Zero-sized; everything lives on the trait
/// impl.
pub struct TextUtf8V1;

impl BytePayloadEncoding for TextUtf8V1 {
    /// 1 length prefix + 8 byte chunks = 9 field elements.
    const FIELD_COUNT: usize = 1 + CHUNKS;

    fn id() -> Fq {
        encoding_id(SPEC_PATH)
    }

    fn encode(input: &[u8]) -> Result<FieldStream, EncodingError> {
        if input.len() > MAX_BYTES {
            return Err(EncodingError::InvalidInput(
                "payload exceeds MAX_BYTES (248)",
            ));
        }
        // UTF-8 validity is a *semantic* precondition of this
        // encoding. Native-side we check eagerly; the structural
        // validator does not.
        if std::str::from_utf8(input).is_err() {
            return Err(EncodingError::InvalidInput("payload is not valid UTF-8"));
        }

        // Zero-pad to MAX_BYTES so chunks always cover the full
        // 8 × 31 grid. The bytes past `input.len()` are guaranteed
        // zero by initialization.
        let mut padded = [0u8; MAX_BYTES];
        padded[..input.len()].copy_from_slice(input);

        // Pack: length prefix in f_0, then 8 chunks in f_1..f_8.
        // `FIELD_COUNT - 1 == CHUNKS`; we allocate `FIELD_COUNT`
        // directly to make the relationship explicit.
        let mut fields: Vec<Fq> = Vec::with_capacity(Self::FIELD_COUNT);
        fields.push(Fq::from(input.len() as u64));
        for chunk in padded.chunks_exact(CHUNK_BYTES) {
            fields.push(Fq::from_be_bytes_mod_order(chunk));
        }
        debug_assert_eq!(fields.len(), Self::FIELD_COUNT);
        Ok(FieldStream::from_vec(fields))
    }

    fn decode(stream: &FieldStream) -> Result<Vec<u8>, EncodingError> {
        // Structural check first. `validate_structural` catches
        // wrong arity, out-of-range length prefix, and (in this
        // encoding's case) the chunks-don't-fit-in-31-bytes class.
        if !Self::validate_structural(stream) {
            return Err(EncodingError::StructuralInvalid(
                "field stream is not a structurally-valid text-utf8-v1 stream",
            ));
        }

        let fields = stream.fields();
        // SAFETY (logical, not unsafe): `validate_structural` already
        // confirmed the length prefix fits in `u64` and is `<= MAX_BYTES`.
        let len = field_to_usize_unchecked(&fields[0]);

        // Reconstruct the byte sequence: 8 chunks × 31 bytes, reading
        // the *low* 31 bytes of each field element. We took the field
        // element via `from_be_bytes_mod_order` on 31 bytes, so the
        // top 6 bits of its 32-byte little-endian representation are
        // always zero; reversing that gets us back to the original
        // 31 bytes.
        let mut padded = Vec::with_capacity(MAX_BYTES);
        for f in &fields[1..] {
            let mut be = field_to_be_32(f);
            // Drop the leading 0x00 byte from the 32→31 conversion.
            // It MUST be zero on a structurally-valid stream; we
            // re-check defensively.
            if be[0] != 0 {
                return Err(EncodingError::StructuralInvalid(
                    "chunk does not fit in 31 bytes (top byte non-zero)",
                ));
            }
            padded.extend_from_slice(&be[1..]);
            // Zeroize `be` after we're done with it. Defensive; the
            // chunk bytes themselves aren't sensitive.
            be.fill(0);
        }
        debug_assert_eq!(padded.len(), MAX_BYTES);

        // Strict zero-padding: every byte past `len` MUST be zero.
        // This is what makes `(encode, decode)` a bijection on
        // accepted inputs; without it, multiple field-streams would
        // decode to the same bytes.
        if padded[len..].iter().any(|&b| b != 0) {
            return Err(EncodingError::StructuralInvalid(
                "non-zero padding bytes after declared length",
            ));
        }

        let bytes = padded[..len].to_vec();
        // Semantic check: the bytes must be valid UTF-8. A field
        // stream can be structurally well-formed (right shape, right
        // padding) but decode to invalid UTF-8 — the structural
        // validator deliberately does not check this.
        if std::str::from_utf8(&bytes).is_err() {
            return Err(EncodingError::SemanticInvalid(
                "decoded bytes are not valid UTF-8",
            ));
        }
        Ok(bytes)
    }

    fn validate_structural(stream: &FieldStream) -> bool {
        if stream.len() != Self::FIELD_COUNT {
            return false;
        }
        let fields = stream.fields();

        // Length prefix must be a small non-negative integer ≤ MAX_BYTES.
        // We check by round-tripping through bigint and inspecting the
        // limbs — `Fq::from(u64)` and back, for valid lengths, lands
        // unchanged. For "lengths" larger than u64 (impossible for an
        // honest encoder, but possible for a forged stream), the high
        // limbs are non-zero and we reject.
        let len_bigint = fields[0].into_bigint();
        let len_limbs = len_bigint.0; // [u64; 4] for BN254
        if len_limbs[1] != 0 || len_limbs[2] != 0 || len_limbs[3] != 0 {
            return false;
        }
        let len = len_limbs[0] as usize;
        if len > MAX_BYTES {
            return false;
        }

        // Each chunk MUST fit in 31 bytes: its 32-byte big-endian
        // representation has a zero top byte. Without this check, a
        // forged chunk could have set high bits that survive
        // mod-`p` reduction and confuse downstream consumers.
        for f in &fields[1..] {
            let be = field_to_be_32(f);
            if be[0] != 0 {
                return false;
            }
        }
        true
    }
}

/// Render an `Fq` as its 32-byte big-endian unsigned representation,
/// padded on the left with zeros.
fn field_to_be_32(f: &Fq) -> [u8; 32] {
    use ark_ff::BigInteger;
    let bytes_le = f.into_bigint().to_bytes_le();
    let mut be = [0u8; 32];
    // `to_bytes_le()` returns exactly 32 bytes for BN254. Reverse
    // for big-endian.
    debug_assert_eq!(bytes_le.len(), 32);
    for (i, b) in bytes_le.iter().enumerate() {
        be[31 - i] = *b;
    }
    be
}

/// Extract a `usize` from a length-prefix field element under the
/// precondition that `validate_structural` has already verified the
/// element fits in `u64` and is ≤ `MAX_BYTES`.
fn field_to_usize_unchecked(f: &Fq) -> usize {
    f.into_bigint().0[0] as usize
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Empty input encodes to `[0, 0, 0, 0, 0, 0, 0, 0, 0]` — length
    /// zero, eight zero-padding chunks. Decoding returns the empty
    /// vec.
    #[test]
    fn empty_input_roundtrips() {
        let stream = TextUtf8V1::encode(&[]).expect("empty is valid");
        assert_eq!(stream.len(), TextUtf8V1::FIELD_COUNT);
        assert_eq!(stream.fields()[0], Fq::from(0u64));
        let decoded = TextUtf8V1::decode(&stream).expect("decode");
        assert_eq!(decoded, Vec::<u8>::new());
    }

    /// A short ASCII string round-trips.
    #[test]
    fn short_ascii_roundtrips() {
        let s = b"hello, world!";
        let stream = TextUtf8V1::encode(s).expect("encode");
        assert_eq!(stream.fields()[0], Fq::from(s.len() as u64));
        let decoded = TextUtf8V1::decode(&stream).expect("decode");
        assert_eq!(decoded, s);
    }

    /// A multi-byte UTF-8 string round-trips and the length prefix is
    /// in *bytes*, not characters — the encoding doesn't promise
    /// grapheme awareness.
    #[test]
    fn multibyte_utf8_roundtrips() {
        let s = "こんにちは世界".as_bytes(); // 7 chars × 3 bytes = 21 bytes
        assert_eq!(s.len(), 21);
        let stream = TextUtf8V1::encode(s).expect("encode");
        assert_eq!(stream.fields()[0], Fq::from(21u64));
        let decoded = TextUtf8V1::decode(&stream).expect("decode");
        assert_eq!(decoded, s);
    }

    /// A full-length 248-byte payload round-trips.
    #[test]
    fn full_length_payload_roundtrips() {
        let s = vec![b'x'; MAX_BYTES];
        let stream = TextUtf8V1::encode(&s).expect("encode");
        assert_eq!(stream.fields()[0], Fq::from(MAX_BYTES as u64));
        let decoded = TextUtf8V1::decode(&stream).expect("decode");
        assert_eq!(decoded, s);
    }

    /// An over-length payload is rejected by `encode`.
    #[test]
    fn over_length_rejected() {
        let s = vec![b'x'; MAX_BYTES + 1];
        assert!(matches!(
            TextUtf8V1::encode(&s),
            Err(EncodingError::InvalidInput(_)),
        ));
    }

    /// Non-UTF-8 bytes are rejected by `encode` (semantic
    /// precondition).
    #[test]
    fn non_utf8_rejected_by_encode() {
        let bad = [0xC3u8, 0x28]; // 0xC3 0x28 is invalid UTF-8
        assert!(matches!(
            TextUtf8V1::encode(&bad),
            Err(EncodingError::InvalidInput(_)),
        ));
    }

    /// A field stream with the wrong arity is rejected structurally.
    #[test]
    fn wrong_arity_rejected_structurally() {
        let too_short = FieldStream::from_vec(vec![Fq::from(0u64); 5]);
        assert!(!TextUtf8V1::validate_structural(&too_short));
        let too_long = FieldStream::from_vec(vec![Fq::from(0u64); 20]);
        assert!(!TextUtf8V1::validate_structural(&too_long));
    }

    /// A length prefix > MAX_BYTES is structurally invalid.
    #[test]
    fn oversized_length_prefix_rejected() {
        let mut fields = vec![Fq::from(MAX_BYTES as u64 + 1)];
        for _ in 0..CHUNKS {
            fields.push(Fq::from(0u64));
        }
        let stream = FieldStream::from_vec(fields);
        assert!(!TextUtf8V1::validate_structural(&stream));
    }

    /// Non-zero padding past the declared length is structurally
    /// valid (the chunks are well-shaped) but decode rejects it.
    /// Demonstrates that `validate_structural` is a proper subset of
    /// `decode`'s acceptance set.
    #[test]
    fn non_zero_padding_passes_structural_fails_decode() {
        // Length 3, "abc" in the first chunk, but the chunk *also*
        // has trailing non-zero bytes (so the padding is wrong).
        let mut padded = [0u8; MAX_BYTES];
        padded[..3].copy_from_slice(b"abc");
        padded[10] = 0xFF; // garbage past the declared length
        let mut fields = vec![Fq::from(3u64)];
        for chunk in padded.chunks_exact(CHUNK_BYTES) {
            fields.push(Fq::from_be_bytes_mod_order(chunk));
        }
        let stream = FieldStream::from_vec(fields);
        assert!(
            TextUtf8V1::validate_structural(&stream),
            "stream is structurally well-shaped",
        );
        assert!(
            matches!(
                TextUtf8V1::decode(&stream),
                Err(EncodingError::StructuralInvalid(_)),
            ),
            "decode rejects because the trailing bytes are non-zero",
        );
    }

    /// `id()` is deterministic and matches the path-based derivation.
    #[test]
    fn id_is_stable() {
        use crypto::encoding::id::encoding_id;
        assert_eq!(TextUtf8V1::id(), encoding_id(SPEC_PATH));
    }
}
