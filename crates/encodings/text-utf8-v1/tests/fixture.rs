//! Cross-language compatibility fixture for `text-utf8-v1`.
//!
//! Executable form of [`specs/encodings/text-utf8-v1.md § Worked
//! Example`](../../../../specs/encodings/text-utf8-v1.md#worked-example).
//! If any pinned field-element value drifts, these fail. Integration
//! test (in `tests/`) by design — exercises the encoding through its
//! public trait surface exactly as a WASM consumer or third-party
//! crate would.

use ark_ff::PrimeField;

use crypto::babyjub::Fq;
use crypto::encoding::BytePayloadEncoding;
use text_utf8_v1::TextUtf8V1;

/// `encoding_id` pinned by the spec. If the spec path changes, this
/// value changes; that's the whole point of path-based identity.
#[test]
fn encoding_id_matches_spec() {
    let id_decimal = TextUtf8V1::id().into_bigint().to_string();
    assert_eq!(
        id_decimal,
        "10251905648233427808659162032937842155138269080868533503078341140126603942221",
    );
}

/// Vector 1: empty payload encodes to nine zero field elements.
#[test]
fn fixture_vector_1_empty() {
    let stream = TextUtf8V1::encode(&[]).expect("empty is valid");
    assert_eq!(stream.len(), 9);
    for (i, f) in stream.fields().iter().enumerate() {
        assert_eq!(*f, Fq::from(0u64), "f_{i} expected zero");
    }
    assert_eq!(
        TextUtf8V1::decode(&stream).expect("decode empty"),
        Vec::<u8>::new(),
    );
}

/// Vector 2: `"hello, world!"`. Catches a wrong chunking direction or
/// a wrong byte→field reduction — both would change `f_1` while
/// leaving the other vectors looking plausible.
#[test]
fn fixture_vector_2_hello() {
    let s = b"hello, world!";
    let stream = TextUtf8V1::encode(s).expect("encode hello");
    let fields = stream.fields();
    assert_eq!(fields[0], Fq::from(13u64));
    assert_eq!(
        fields[1].into_bigint().to_string(),
        "184452094211679030227880241948843765817935618364777678222724444834882387968",
    );
    for (i, f) in fields[2..].iter().enumerate() {
        assert_eq!(*f, Fq::from(0u64), "f_{} expected zero", i + 2);
    }
    assert_eq!(TextUtf8V1::decode(&stream).expect("decode hello"), s);
}

/// Vector 3: multibyte UTF-8. The length prefix is in bytes, not
/// characters — three-byte CJK characters mean `len = 3 * num_chars`.
#[test]
fn fixture_vector_3_multibyte() {
    let s = "こんにちは世界".as_bytes();
    assert_eq!(s.len(), 21);
    let stream = TextUtf8V1::encode(s).expect("encode multibyte");
    let fields = stream.fields();
    assert_eq!(fields[0], Fq::from(21u64));
    assert_eq!(
        fields[1].into_bigint().to_string(),
        "401968596055196051537592476051840533583207957312700825760665297196064702464",
    );
    for (i, f) in fields[2..].iter().enumerate() {
        assert_eq!(*f, Fq::from(0u64), "f_{} expected zero", i + 2);
    }
    assert_eq!(TextUtf8V1::decode(&stream).expect("decode multibyte"), s);
}

/// Vector 4: a max-length payload of 248 `'x'` bytes. Every chunk
/// reads the same `0x78 * 31`, so every `f_i` (for `i ≥ 1`) equals
/// the same pinned constant. Catches off-by-one errors in chunk
/// indexing that smaller vectors wouldn't surface.
#[test]
fn fixture_vector_4_full_length() {
    let s = vec![b'x'; 248];
    let stream = TextUtf8V1::encode(&s).expect("encode full");
    let fields = stream.fields();
    assert_eq!(fields[0], Fq::from(248u64));
    let chunk_x =
        "212853105215654770999211369501264536494981589458898095660767617661605017720";
    for (i, f) in fields[1..].iter().enumerate() {
        assert_eq!(
            f.into_bigint().to_string(),
            chunk_x,
            "f_{} mismatched", i + 1,
        );
    }
    assert_eq!(TextUtf8V1::decode(&stream).expect("decode full"), s);
}

/// Round-trip the whole suite of vectors as one sanity sweep — small
/// shotgun catching regressions that change the encoding semantics in
/// some narrow way that one vector misses.
#[test]
fn all_vectors_round_trip() {
    let inputs: Vec<Vec<u8>> = vec![
        vec![],
        b"hello, world!".to_vec(),
        "こんにちは世界".as_bytes().to_vec(),
        vec![b'x'; 248],
    ];
    for input in inputs {
        let stream = TextUtf8V1::encode(&input).expect("encode");
        let decoded = TextUtf8V1::decode(&stream).expect("decode");
        assert_eq!(decoded, input, "round-trip mismatch");
    }
}

/// `validate_structural` accepts streams `decode` accepts. The
/// universal subset relation between the two validation layers.
#[test]
fn validate_structural_accepts_all_encoded() {
    let inputs: Vec<&[u8]> = vec![&[], b"hello", "こんにちは".as_bytes()];
    for input in inputs {
        let stream = TextUtf8V1::encode(input).expect("encode");
        assert!(
            TextUtf8V1::validate_structural(&stream),
            "validate_structural must accept every encode() output",
        );
    }
}
