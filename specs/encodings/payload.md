# Payload (`payload`)

This document specifies the **payload** — the protocol's pairing of
an encoded field-element stream with the identity of the encoding
that produced it. A payload is the unit that envelopes seal,
commitments commit to, and circuits prove statements about.

Foundation document for the encoding registry's downstream
consumers (`protocol-envelope.md`, `protocol-commitment.md`, the
ZK circuit specs). Built on
[`encodings/README.md`](./README.md) and the encoding-id
construction it pins.

> **NOTE(name):** type name `Payload` and crate name `crypto` are
> working names. No product name baked in.

## What this is

```text
payload = {
    encoding_id : Fq,        // which encoding produced the stream
    stream      : Vec<Fq>,   // the encoded field-element stream
}
```

A payload bundles two things that the codebase had been passing
around separately and pairing only by convention:

- **`stream`** — the "plaintext on the curve." A fixed-arity
  sequence of BN254 base-field elements, the output of some
  encoding's `encode`. This is what the cipher encrypts, what
  Pedersen commits to, what circuits read.
- **`encoding_id`** — the registry id of the encoding that
  produced `stream`, derived from the encoding's canonical spec
  path via `bytes_to_field_be(Blake2b-256(spec_path))` (see
  [`encodings/README.md § Identity`](./README.md#identity-path-based-encoding-ids)).
  This is "how it was put on the curve, and how to recover the
  original form": given `encoding_id`, a consumer dispatches to
  the right decoder and recovers the original bytes (or typed
  value).

Without the pairing, a bare `stream` is ambiguous: `[10, 20, 30,
…]` could be UTF-8 text, a future `kv-pairs-v1` structure, or a
raw `Vec<u64>`. The `encoding_id` resolves the ambiguity and is
the protocol's standard defense against cross-encoding confusion
(see [§ Why the id is load-bearing](#why-the-id-is-load-bearing)).

## What this is FOR

The payload is the seam between application content and the
protocol's curve-shaped primitives. Application code produces a
payload (encode bytes/values → stream, tag with encoding id);
the protocol's compositions consume it:

```text
payload  = encode("hello")          // text-utf8-v1 → (id, [f_0..f_8])
envelope = seal(sk, pk, id, payload) // envelope carries encoding_id as public metadata
commit   = commit(payload, blinding) // commitment carries encoding_id as public metadata
```

On the recipient / verifier side, the encoding id travels with
the ciphertext or commitment so the consumer knows how to
interpret the recovered stream.

## What this is NOT

- **Not the encoding itself.** The encoding (`text-utf8-v1`,
  etc.) is the *function* `bytes ↔ stream`. The payload is one
  *instance* of that function's output, labeled with which
  function produced it. The encoding lives in
  `crates/encodings/<name>/`; the `Payload` type lives in
  `crypto::encoding` next to the encoding trait.
- **Not a typed value.** `stream` is always `Vec<Fq>`,
  regardless of whether the encoding was byte-input or
  (future) typed-input. The payload doesn't know the original
  shape — only the encoding, retrieved via `encoding_id`, does.
- **Not secret.** The `encoding_id` is public metadata. See
  [§ Privacy: the encoding id is public](#privacy-the-encoding-id-is-public).

## Privacy: the encoding id is public

**Decision: `encoding_id` is PUBLIC metadata, carried in the
clear alongside the ciphertext / commitment, not encrypted.**

Rationale:

- `protocol-invariants.md § 1` already lists "suite identifiers"
  and "schema/context metadata" among the things the chain may
  legitimately store in the clear. The encoding id is exactly
  that category: it tells a consumer how to interpret the
  payload, not what the payload says.
- A recipient must know the encoding *before* decrypting in
  order to dispatch to the right decoder. Encrypting the id
  would create a chicken-and-egg problem (you'd need a
  meta-encoding to decode the id).
- The privacy leak is small and bounded: the encoding id reveals
  the *shape class* of the message (text vs. structured record),
  not its content. An application that considers even the shape
  class sensitive can use a single catch-all encoding for all
  its messages, collapsing the distinction.

The trade-off is explicit: confidentiality covers the *content*
(`stream`, via the cipher), integrity covers the *whole envelope
including the encoding id* (via the MAC and, in circuits, the
signal hash). The encoding id is authenticated but not hidden.

## Why the id is load-bearing

The `encoding_id` is not bookkeeping — it closes a real attack
class and strengthens circuit claims.

### Cross-encoding confusion

Suppose a future `kv-pairs-v1` encoding also produces 9 field
elements. Without the id bound to the payload, a stream sealed
as `text-utf8-v1` could be opened and interpreted as
`kv-pairs-v1`, decoding to a structurally-different,
attacker-influenced value. Binding `encoding_id` into the
envelope's MAC and the commitment's domain means a payload can
only be interpreted under the encoding it was sealed with.

### Circuit claim honesty

A circuit that proves "plaintext[0] == X" about a bare stream
proves a weaker statement than one that proves "the
`text-utf8-v1`-labeled plaintext[0] == X." The id makes the
claim's interpretation unambiguous: the verifier knows which
encoding's semantics the positional claim refers to.

This labeling is **mandatory** (every consumer binds the id).
It is distinct from *structural enforcement* — proving the
stream is a well-formed instance of its encoding — which is
**optional** and composable; see
[§ Two levels of circuit binding](#two-levels-of-circuit-binding).

## Two levels of circuit binding

When a circuit operates on a payload, there are two separable
notions of "binding to the encoding," with very different
expressiveness consequences. The protocol pins **mandatory
labeling, optional structural enforcement.**

### Level A — encoding-id labeling (MANDATORY)

The circuit records *which* encoding the stream claims to be:
`encoding_id` enters the circuit's public inputs (directly or
via the signal hash). The circuit does NOT check that the
stream is structurally valid under that encoding — it just
carries the label so a verifier cannot reinterpret the same
field elements under a different encoding.

Cost: one extra field in a hash. ~0 constraints. Limits
nothing.

Benefit: closes the cross-encoding confusion gap at the proof
layer. A proof about a `text-utf8-v1` payload cannot be
replayed as a proof about a `kv-pairs-v1` payload.

**Every circuit that operates on a payload MUST bind the
encoding id (Level A).**

### Level B — structural-validity enforcement (OPTIONAL)

The circuit additionally proves the stream IS a well-formed
instance of its encoding — `text-utf8-v1`'s length prefix is
correct, padding is zero, chunks fit, etc. This is the encoding
registry's `validate_structural` lifted into R1CS as a
composable gadget (`validate_structural_var`, a future brick).

Cost: the encoding's structural validator's constraints.

Benefit: semantic honesty — the claim "the message's first
character is X" is only meaningful if the stream actually
decodes to a message.

**Structural enforcement is OPTIONAL and composable. It MUST
NOT be welded into the base circuit.** Reasons:

- Some claims don't need it (proving recipiency — "I can open
  this envelope" — doesn't require the plaintext to be valid
  text).
- Welding structure into every circuit forces a circuit per
  (claim × encoding) instead of (claim) + (encoding-validator),
  a combinatorial explosion.
- The most expressive relationships (range proofs, set
  membership, homomorphic relations, cross-stream equality)
  treat the stream as raw field elements; structural validity
  is a presentation concern at the edges, not in the middle.

The encoding registry already anticipated this split: its
trait keeps `validate_structural` distinct from `decode`
precisely because "the in-circuit validator mirrors
`validate_structural`" — a standalone, composable predicate,
not a mandatory gate.

## Construction

### Building a payload

```text
payload = Payload {
    encoding_id: <Encoding>::id(),
    stream: <Encoding>::encode(input)?.into_fields(),
}
```

The `encoding_id` is the encoding's registry id; `stream` is
the `FieldStream`'s field elements. The pairing is purely a
bundling — no hashing, no transformation. A `Payload` is valid
iff its `stream` is a valid output of the encoding named by
`encoding_id` (which a consumer checks by decoding, not by
inspecting the payload).

### Recovering the original form

```text
input = <Encoding>::decode(FieldStream::from(payload.stream))?
```

The consumer must already know which `<Encoding>` corresponds
to `payload.encoding_id` — i.e. statically depend on the crate
that defines it. There is no runtime registry (see
[`encodings/README.md § What this registry intentionally does
NOT do`](./README.md)). A consumer that receives an unknown
`encoding_id` cannot decode it.

## Rust API contract

```rust
pub struct Payload {
    pub encoding_id: Fq,
    pub stream: Vec<Fq>,
}

impl Payload {
    /// Build a payload from an encoding's id and stream.
    pub fn new(encoding_id: Fq, stream: Vec<Fq>) -> Self;

    /// Convenience: build directly from a BytePayloadEncoding
    /// implementation and a byte input. Encodes, tags with the
    /// encoding's id.
    pub fn encode<E: BytePayloadEncoding>(input: &[u8])
        -> Result<Self, EncodingError>;

    /// Convenience: decode this payload's stream via the named
    /// encoding `E`. Errors if `E::id() != self.encoding_id`
    /// (wrong encoding) or if decode fails.
    pub fn decode<E: BytePayloadEncoding>(&self)
        -> Result<Vec<u8>, EncodingError>;
}
```

The `decode` helper's id check is the type-level expression of
the cross-encoding-confusion defense: you cannot decode a
`text-utf8-v1` payload by passing the `KvPairsV1` type, because
the ids won't match.

## Validity contracts

A conformant implementation MUST:

- **Treat `encoding_id` as public.** It is carried in the clear
  by envelopes and commitments; it is authenticated (via MAC /
  signal hash) but not encrypted.
- **Reject `Payload::decode::<E>()` when `E::id() !=
  payload.encoding_id`.** A payload may only be decoded under
  the encoding it was tagged with.
- **Bind `encoding_id` in every circuit that operates on a
  payload (Level A).** Via public input or signal hash. A
  circuit that omits the encoding id is unsound against
  cross-encoding confusion.
- **NOT weld structural-validity enforcement into base
  circuits (Level B is opt-in).**
- **Match the encoding-id derivation** pinned in
  [`encodings/README.md`](./README.md): path-based
  `bytes_to_field_be(Blake2b-256(spec_path))`.

## Worked Example

```text
encoding   = text-utf8-v1
spec_path  = "specs/encodings/text-utf8-v1.md"
encoding_id = bytes_to_field_be(Blake2b-256(spec_path))
            = 10251905648233427808659162032937842155138269080868533503078341140126603942221

input      = "hi"  (2 UTF-8 bytes)
stream     = text-utf8-v1::encode("hi")   // 9-element FieldStream

payload    = Payload {
    encoding_id: 10251905648233427808659162032937842155138269080868533503078341140126603942221,
    stream:      [<the 9 encoded fields>],
}

decode:
    payload.decode::<TextUtf8V1>()  ==  Ok(b"hi")     // id matches
    payload.decode::<KvPairsV1>()   ==  Err(WrongEncoding)  // hypothetical; id mismatch
```

The `encoding_id` decimal is pinned: any implementation that
derives a different id for `specs/encodings/text-utf8-v1.md` is
incompatible.

## References

- [`encodings/README.md`](./README.md) — the registry, the
  encoding-id construction, the byte/typed split, the
  versioning discipline.
- [`encodings/text-utf8-v1.md`](./text-utf8-v1.md) — the first
  concrete encoding; the reference for the worked example above.
- [`protocol-envelope.md`](../protocol-envelope.md) — carries
  `encoding_id` as public envelope metadata (retrofit pending).
- `protocol-commitment.md` — carries `encoding_id` as public
  commitment metadata (to be specified next).
- [`zk/circuit-envelope-open-at-0.md`](../zk/circuit-envelope-open-at-0.md)
  — binds `encoding_id` via the signal hash (Level A retrofit
  pending).
