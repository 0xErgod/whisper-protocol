# `text-utf8-v1` — UTF-8 byte payload encoding

This document specifies the `text-utf8-v1` payload encoding. It is the
cross-language compatibility contract between the Rust
[`text-utf8-v1`](../../crates/encodings/text-utf8-v1) crate, the WASM
binding, and any TypeScript or circuit-side counterpart. Built on
[`encodings/README.md`](./README.md).

> **NOTE(name):** scheme tag `text-utf8-v1` and crate name `text-utf8-v1`
> are working names following the registry's path-id discipline. A
> breaking change mints `text-utf8-v2`.

**Any implementation that does not reproduce the exact field-stream
values in [§ Worked Example](#worked-example) is incompatible with this
encoding and will not interoperate.**

## Purpose

Carry a UTF-8 byte string of up to 248 bytes into a fixed-arity
sequence of 9 BN254 field elements. The simplest "real" encoding: just
text, no schema, no parsing. Reference implementation of the
`BytePayloadEncoding` pattern.

## Definition

### Identity

```text
encoding_id = bytes_to_field_be(Blake2b-256("specs/encodings/text-utf8-v1.md"))
            = 10251905648233427808659162032937842155138269080868533503078341140126603942221
```

### Shape

- **`FIELD_COUNT = 9`** — exactly 9 field elements per encoded payload,
  always. `text-utf8-v1` is fixed-arity.
- **`MAX_BYTES = 248`** — payloads longer than this are rejected at
  encode time. Chosen because `248 = 8 × 31` (eight 31-byte chunks) and
  31 bytes fits comfortably in BN254's 254-bit field with the top
  6 bits guaranteed zero.

### Layout

```text
f_0 = length of payload in bytes, as a field element in [0, 248]
f_1 = bytes 0..31  of zero-padded payload, big-endian
f_2 = bytes 31..62 of zero-padded payload, big-endian
f_3 = bytes 62..93 ...
f_4 = bytes 93..124
f_5 = bytes 124..155
f_6 = bytes 155..186
f_7 = bytes 186..217
f_8 = bytes 217..248
```

The payload is zero-padded on the right to exactly `MAX_BYTES` before
chunking. The padded bytes (the bytes past `f_0`) MUST be exactly
zero — this is what makes `(encode, decode)` a bijection.

### Encode

```text
encode(input: bytes) -> FieldStream:
    if len(input) > MAX_BYTES: reject InvalidInput
    if not is_valid_utf8(input): reject InvalidInput
    padded = input ++ [0x00] * (MAX_BYTES - len(input))
    return FieldStream([
        Fq(len(input)),
        Fq.from_be_bytes(padded[0..31]),
        Fq.from_be_bytes(padded[31..62]),
        ...
        Fq.from_be_bytes(padded[217..248]),
    ])
```

### Decode

```text
decode(stream: FieldStream) -> bytes:
    if not validate_structural(stream): reject StructuralInvalid
    len = stream.f_0 as integer
    padded = []
    for i in 1..=8:
        be32 = stream.f_i as 32-byte big-endian unsigned integer
        if be32[0] != 0: reject StructuralInvalid    # chunk doesn't fit in 31 bytes
        padded ++= be32[1..32]
    if any byte in padded[len..] is non-zero: reject StructuralInvalid
    bytes = padded[..len]
    if not is_valid_utf8(bytes): reject SemanticInvalid
    return bytes
```

### Structural validation

```text
validate_structural(stream: FieldStream) -> bool:
    return stream.len() == 9
        and stream.f_0 fits in u64 and is in [0, 248]
        and every f_i for i in 1..=8 fits in 31 bytes
```

Note what structural validation does **not** check:
- It does not check that the bytes past `f_0` are zero. A stream with
  non-zero "padding" is structurally well-shaped; only `decode`
  rejects it.
- It does not check UTF-8 validity of the decoded bytes. Same
  reasoning: a structurally well-shaped stream can decode to bytes
  that aren't valid UTF-8; `decode` catches that.

This split is deliberate. `validate_structural` mirrors what a cheap
in-circuit validator would prove; full `decode` validity is more
expensive both to compute and (later) to prove.

## Provability

`text-utf8-v1` is the reference byte-input encoding, and its primary
job is round-trip fidelity, not provability. But several predicates
*are* cheap to prove over its field stream, and consumers should know
what they are.

### Cheap predicates (recommended)

| Predicate | Constraint estimate (BN254 Groth16) | Notes |
|---|---|---|
| `length_equals(payload, n)` | ~1 | Just `f_0 == n`. |
| `length_in_range(payload, lo, hi)` | ~16 | Two range proofs on `f_0`. |
| `length_at_most(payload, n)` | ~8 | One range proof on `f_0`. |
| `poseidon_hash_equals(payload, h)` | ~250 | One Poseidon hash over the 9 fields. |
| `payload_equals(payload_a, payload_b)` | ~9 | Field-wise equality. |
| `prefix_equals(payload, prefix_bytes)` | ~300 (for ≤31-byte prefix) | Decompose `f_1` to bytes, equate first `len(prefix)`. |
| `encoding_valid_structural(payload)` | ~500–3000 | The full structural check; see registry README. |

### Moderate predicates

| Predicate | Constraint estimate | Notes |
|---|---|---|
| `substring_contains(payload, needle)` | ~50–500 per needle | Prover-supplied position hint + equality check at that position. Limited to needles ≤ 31 bytes for the simple variant. |
| `suffix_equals(payload, suffix_bytes)` | ~300 | Like prefix, but reads from the chunk containing `f_0 - len(suffix)`. Cheap when length is known; more constraints when not. |

### Out of scope (not part of this encoding's supported predicates)

| Predicate | Reason |
|---|---|
| `is_valid_utf8(stream)` | UTF-8 validation in circuit is a branchy state machine over bytes; ~tens of thousands of constraints. Don't prove; assume the encoder enforced it native-side and ensure the predicate consumers only operate on `decode`-accepted streams (e.g. via a `is_valid_utf8_or_payload_zero` flag). |
| `byte_hash_equals(payload, h)` for SHA-256, Blake2 | ~30K constraints per 64-byte block. Use Poseidon hash for protocol-internal use cases. Only reach for byte hashes when interoperating with an external system that already uses one. |
| Regex matching | General regex in zk circuits is an active research area. Not supported by this encoding's predicate set; if a use case needs it, build it as a separate proof primitive that consumes this encoding's bytes. |
| Locale-aware / Unicode-normalization predicates | Out of scope; would require Unicode tables in-circuit. |
| Semantic NLP predicates ("the text mentions a location") | Not feasible in ZK at any practical cost. |

### Open-ended

The predicate table is **recommended**, not exhaustive. Anything
provable over the 9 field elements is fair game; the table names what's
cheap so consumers don't pay for things they don't need. A consumer
that wants to prove a custom predicate writes its own circuit and
references this encoding's field-layout from this spec.

## Worked Example

A conformant implementation reproduces every value below exactly.

### `encoding_id`

```text
10251905648233427808659162032937842155138269080868533503078341140126603942221
```

### Vector 1 — empty payload

```text
input = []                  (0 bytes)
f_0 = 0
f_1 = 0
f_2 = 0
f_3 = 0
f_4 = 0
f_5 = 0
f_6 = 0
f_7 = 0
f_8 = 0
```

### Vector 2 — "hello, world!"

```text
input = "hello, world!"     (13 ASCII bytes)
f_0 = 13
f_1 = 184452094211679030227880241948843765817935618364777678222724444834882387968
f_2 = 0
f_3 = 0
f_4 = 0
f_5 = 0
f_6 = 0
f_7 = 0
f_8 = 0
```

The non-zero `f_1` decodes to bytes `[0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x2c,
0x20, 0x77, 0x6f, 0x72, 0x6c, 0x64, 0x21, 0x00, 0x00, ..., 0x00]`
(13 content bytes + 18 zero-padding bytes inside the chunk).

### Vector 3 — "こんにちは世界" (multibyte UTF-8)

Seven characters × 3 bytes each = 21 bytes:

```text
input = "こんにちは世界"      (21 UTF-8 bytes)
f_0 = 21
f_1 = 401968596055196051537592476051840533583207957312700825760665297196064702464
f_2 = 0
f_3 = 0
f_4 = 0
f_5 = 0
f_6 = 0
f_7 = 0
f_8 = 0
```

Length prefix is in **bytes**, not characters; `text-utf8-v1` does not
promise grapheme awareness.

### Vector 4 — full-length 248 × `'x'`

A payload that exactly fills `MAX_BYTES` with the ASCII byte `0x78`:

```text
input = "xxxxxxxx... (×248)"
f_0 = 248
f_1 = 212853105215654770999211369501264536494981589458898095660767617661605017720
f_2 = 212853105215654770999211369501264536494981589458898095660767617661605017720
f_3 = 212853105215654770999211369501264536494981589458898095660767617661605017720
f_4 = 212853105215654770999211369501264536494981589458898095660767617661605017720
f_5 = 212853105215654770999211369501264536494981589458898095660767617661605017720
f_6 = 212853105215654770999211369501264536494981589458898095660767617661605017720
f_7 = 212853105215654770999211369501264536494981589458898095660767617661605017720
f_8 = 212853105215654770999211369501264536494981589458898095660767617661605017720
```

Every chunk reads as 31 copies of `0x78`, so every `f_i` (for `i ≥ 1`)
is the same field element — `bytes_to_field_be([0x78] * 31)`.

## Validity contracts

A conformant implementation MUST:

- **Reject inputs longer than `MAX_BYTES`** at encode time. No
  silent truncation.
- **Reject non-UTF-8 inputs** at encode time. `encode` is *not* a
  general byte encoder; the UTF-8 contract is what distinguishes
  `text-utf8-v1` from a future `bytes-opaque-v1`.
- **Reject streams whose decoded bytes are not valid UTF-8** at
  decode time. A consumer of `decode` can assume the returned bytes
  are valid UTF-8.
- **Reject streams whose non-payload chunks are non-zero** at decode
  time. The bijection requires strict zero-padding.
- **Treat `validate_structural` as a proper subset of `decode`.**
  Any stream `decode` accepts, `validate_structural` MUST accept;
  the reverse need not hold.

## References

- [`encodings/README.md`](./README.md) — registry taxonomy and the
  byte/typed split this encoding sits inside.
- [`babyjub-curve.md`](../babyjub-curve.md) — the field `Fq` this
  encoding outputs into.
- [`poseidon-commitment-format.md`](../poseidon-commitment-format.md) —
  same 31-byte-big-endian chunking convention.
