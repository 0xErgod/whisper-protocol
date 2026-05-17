# Payload encoding registry

This directory holds the canonical specifications for the protocol's
**payload encodings** — the deterministic, fixed-arity mappings between
application-level inputs and the sequences of BN254 field elements the
protocol's downstream primitives (stream cipher, MAC, commitments,
signatures, ZK predicate circuits) actually consume.

## Why this exists

The asymmetric primitives in `crates/crypto` — Baby Jubjub curve,
keypairs, ECDH, Pedersen commitments, Schnorr signatures — all operate
on **a small fixed number of field elements**. Real protocol content
is variable-shape: a text message, a structured record, a JSON blob.
Something has to bridge the two, and that something is the encoding.

But an encoding is more than serialization. The protocol's whole
provability story rides on what a *circuit* can say about an encoded
payload: "this payload has length ≤ N," "the hash of this payload
equals X," "the payload's third field is a valid Sui address," etc.
Whether those statements are cheap to prove or prohibitively expensive
is a direct function of the encoding's shape. **An encoding is a
provability interface, not just a serialization format.**

That's the reason this is a registry at all — distinct encodings carry
distinct trade-offs about what's cheap to prove, and consumers pick the
right encoding for their proof story.

## The byte/typed split

Encodings divide into two categories with genuinely different shapes:

### Byte-input encodings (`BytePayloadEncoding`)

Input is a `&[u8]`. The encoding's job is to wrap that byte slice into
field elements, possibly with semantic preconditions (UTF-8 validity,
JSON-shape validity). Suited to:

- **Free-form text** (`text-utf8-v1`).
- **Externally-defined formats** — JSON, certificates, anything whose
  shape is fixed by a standard outside this protocol.
- **Append-only / streaming-shaped data** — log entries, event
  payloads.

The strength of byte-input encodings is that they're **uniform**: any
byte-input encoding can be wired into a generic "give me bytes, I'll
encode" path. The weakness is that the *circuit-side cost* of proving
things about the payload is determined by the byte representation,
which is often more expensive than necessary.

### Typed-input encodings (`TypedPayloadEncoding<Input = T>`) — future

Input is a typed Rust value. The encoding's job is to pack the
*structure* of that type into field elements with a layout it
declares. Suited to:

- **Structured records** — `(timestamp, sender, recipient, amount)`,
  payment-like tuples, transaction summaries.
- **Compound types with semantic fields** — a `MerkleProof`, a
  `(commitment, blinding)` pair, anything where the type system has
  meaningful structure to exploit.

The strength of typed encodings is **dramatically cheaper per-predicate
circuit cost** — a predicate that needs only one field of the type
reads exactly one field element, no byte-level parsing. The weakness
is that they're **not uniform** — every typed encoding has a different
`Input` type, so a uniform "decode any encoding" resolver can't exist
for typed encodings.

**Bytes-first is dumb translation: pack the opaque bits into fields,
let circuits parse them back if they want.** Typed-first is smart
translation: leverage type structure to compress field representation
and surface semantic queries cheaply, at the cost of per-encoding
type-specific code.

### What's shipped today

This v1 ships **byte-input encodings only**, via
[`BytePayloadEncoding`](../../crates/crypto/src/encoding/mod.rs). The
typed trait will land when the first real typed-input use case is
specified (likely the first envelope payload type, or a Sui-shaped
record). The taxonomy is documented now so future contributors know
the seam exists.

Both traits will share:
- The same `FieldStream` output type.
- The same id-derivation rule (path-based, see below).
- The same fixed-arity, deterministic, single-stream invariants.

They diverge only on `Input`. A consumer that handles "decode any
byte encoding" iterates registered `BytePayloadEncoding`s; a consumer
that handles `PaymentRecord` directly uses the specific
`TypedPayloadEncoding<PaymentRecord>`.

## Invariants every encoding (byte or typed) must satisfy

1. **Deterministic.** Same input always produces the same
   `FieldStream`. No randomness, no state. (Randomness for commitment
   blinding, IVs, etc. lives in the primitives that consume the
   encoding output, not in the encoding itself.)
2. **Fixed-arity.** Output `FieldStream` has the same `FIELD_COUNT`
   length every time. Variable-length inputs are handled by padding
   to a max; payloads larger than the max are rejected by `encode`.
3. **Single-stream.** Output is one `FieldStream`, not multiple
   parallel streams. (Encodings that need to separate header/body
   streams need a different trait, not yet shipped.)
4. **`decode ∘ encode = identity`** on accepted inputs.
   `decode(encode(input)?) == Ok(input)` for every `input` that
   `encode` does not reject.
5. **Two validity layers, explicitly distinguished.**
   - `validate_structural` is the cheap, in-circuit-shaped check:
     length, padding, chunk-fitness. Mirrors what a ZK circuit would
     prove.
   - `decode` performs the full check including semantic validity
     (e.g. UTF-8 validity for `text-utf8-v1`). MAY reject streams
     that `validate_structural` accepts.
6. **Compression is per-encoding and explicit, never implicit.** A
   typed encoding's spec doc MUST pin its exact field layout (which
   field element holds which member of the input type, in what byte
   order, etc.). The trait does not "figure out compression";
   encodings declare it.

## Identity: path-based encoding ids

Every encoding has an id derived from its canonical spec path:

```text
encoding_id = bytes_to_field_be(Blake2b-256(canonical_spec_path))
```

For `text-utf8-v1`, that's `Blake2b-256("specs/encodings/text-utf8-v1.md")`
reduced into the BN254 base field. The derivation function lives at
[`crypto::encoding::id::encoding_id`](../../crates/crypto/src/encoding/id.rs).

Properties of this choice:

- **Self-certifying.** Anyone with the spec path re-derives the id;
  no registry server needed.
- **Path-based, not content-based.** Editing the spec doc (fixing a
  typo, adding examples) does NOT change the id. The trade is that
  spec paths are load-bearing: a `git mv` of a spec doc silently
  mints a new encoding. The `-v<n>` discipline below makes this
  manageable.
- **Open.** No central writer. Third parties create encodings by
  adding `specs/encodings/<name>-v<n>.md` and a sibling
  implementation crate; ids don't collide with the protocol's by
  construction unless someone deliberately uses the same path.

## Versioning discipline

Every encoding's spec path **MUST** include a `-v<n>` suffix.

A **breaking change** to an encoding (different field layout,
different semantic preconditions, different size cap) mints a new
spec at `-v<n+1>` and a new implementation crate at
`crates/encodings/<name>-v<n+1>/`. The old spec and crate stay in
place so old payloads remain decodable.

A **non-breaking change** (editorial clarification, additional
test vector, expanded predicate table) edits the existing spec
in place. Since the id is path-based, the edit does not change
the id.

What counts as breaking is conservative:
- Changing `FIELD_COUNT` is breaking.
- Changing the byte→field layout is breaking.
- Tightening `encode`'s preconditions is breaking (some previously-
  encodable inputs are now rejected).
- Loosening `validate_structural` is breaking (streams that used
  to be invalid are now accepted).
- Loosening `decode`'s preconditions MAY be breaking depending on
  whether existing consumers rely on the stricter check.

If unsure, mint a new version. They're cheap.

## How to add a new encoding

1. **Write the spec.** `specs/encodings/<name>-v<n>.md`, following
   the shape of [`text-utf8-v1.md`](./text-utf8-v1.md). Pin
   `FIELD_COUNT`, the layout, the preconditions, the
   supported-predicates table.
2. **Implement the crate.** `crates/encodings/<name>-v<n>/`, implementing
   [`BytePayloadEncoding`](../../crates/crypto/src/encoding/mod.rs)
   (or `TypedPayloadEncoding` once that lands).
3. **Add fixture tests.** Round-trip vectors pinned in the spec.
   Edge cases: empty, max-length, structurally-invalid, semantically-
   invalid.
4. **Add the crate to the workspace.** Update
   [`Cargo.toml`](../../Cargo.toml) `[workspace] members`.
5. **(Optional) Expose via WASM.** Add `encode_<name>` /
   `decode_<name>` entries in `crypto-wasm` if the encoding crosses
   to JavaScript.
6. **(Optional) Add a visualization panel.** `apps/curve` is a
   convenient place to demo round-trips.

The pattern is identical for protocol-shipped and third-party
encodings — the protocol's encodings in `crates/encodings/` have no
special status beyond living in this repo.

## What this registry intentionally does NOT do

- **No runtime registration table.** There is no
  `register_encoding(id, impl)` call. If you want to decode an
  unknown id, you statically depend on the crate that defines it.
- **No automatic circuit generation.** The trait describes the
  *native-side* contract; circuits that prove statements over an
  encoded payload are separate code (will live in a future
  `crypto-circuits` crate). The spec doc names *what* can be cheaply
  proved; building the actual circuit is its own brick per predicate.
- **No on-chain registry.** Path-based ids are self-certifying
  off-chain. On-chain code that needs to know an id has it
  hardcoded.

These omissions are deliberate. Each could be added later as its own
sub-protocol; none should be premature for v1.

## Encodings shipped today

| Path | Crate | Purpose |
|---|---|---|
| [`text-utf8-v1.md`](./text-utf8-v1.md) | [`crates/encodings/text-utf8-v1`](../../crates/encodings/text-utf8-v1) | UTF-8 byte payloads, ≤ 248 bytes. The reference byte-input encoding. |

More will follow as protocol needs surface.
