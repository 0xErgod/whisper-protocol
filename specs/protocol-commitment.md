# Protocol Commitment (`protocol-commitment`)

This document specifies the protocol's **commitment** — a vector
Pedersen commitment to a [payload](./encodings/payload.md), with
the payload's encoding id cryptographically bound into the
commitment itself.

Cross-language compatibility contract between the Rust `protocol`
crate, the Move on-chain module, and the TypeScript SDK. Built on
[`babyjub-pedersen.md`](./babyjub-pedersen.md) and
[`encodings/payload.md`](./encodings/payload.md).

> **NOTE(name):** scheme tag `protocol-commitment` and crate name
> `protocol` are working names. No product name baked in.

**Any implementation that does not reproduce the exact point
coordinates in [§ Worked Example](#worked-example) is incompatible
with this scheme.**

## What this is

A binding, hiding commitment to a payload:

```text
commitment = {
    encoding_id : Fq,             // public; also bound inside `point`
    point       : EdwardsAffine,  // the Pedersen commitment
}
```

where `point` commits to the payload's stream **with the encoding
id prepended as the first committed element**:

```text
point = encoding_id · G_0
      + stream[0]    · G_1
      + stream[1]    · G_2
      + ...
      + stream[n-1]  · G_n
      + blinding     · H
```

This is the protocol's vector Pedersen commitment
([`babyjub-pedersen.md`](./babyjub-pedersen.md)) applied to the
augmented stream `[encoding_id, ...stream]`. The `encoding_id` is
NOT a side label — it occupies generator slot `G_0` and is bound
by the same binding property as every payload element.

## What this is FOR

Committing to a payload now, revealing (some of) it later, with a
proof that the revealed content matches. The canonical uses:

- **Commit-then-reveal flows.** Publish a commitment on chain;
  later prove "this commitment opens to a payload whose i-th
  element is X" via a ZK circuit, without revealing the rest.
- **Binding a payload to a transaction** without putting the
  payload on chain. The commitment is small (one curve point +
  one field id); the payload stays off-chain.
- **Linking commitments** via the homomorphic property (below)
  — proving two commitments are to related payloads without
  opening either.

## What this is NOT

- **Not encryption.** A commitment hides the payload from anyone
  without the opening (`stream` + `blinding`), but it is not a
  ciphertext — there is no key, and the committer cannot "send"
  the payload to a recipient via the commitment. For confidential
  *delivery*, use [`protocol-envelope.md`](./protocol-envelope.md).
- **Not a signature.** A commitment binds content, not identity.
  Anyone can produce a commitment to any payload.
- **Not length-hiding.** The number of committed elements is
  visible to anyone who knows the generator set. The encoding id
  (public) already implies the payload's shape, so length-hiding
  would be defeated by the id anyway. A future length-hiding
  variant would zero-pad to a fixed `MAX_LEN`.
- **Not the storage layout on Sui.** The Move-side `Commitment`
  struct's field layout is the on-chain spec's call; this spec
  pins the semantic contract and the binding construction.

## Why the encoding id is bound (Option 2), not attached

The encoding id COULD have been carried as unauthenticated
metadata next to the point — but a commitment whose entire job is
binding should not ship a relabel-able sticky note. Three
binding strategies were considered; this spec pins **committing
the id as the first element** (`G_0`'s coefficient):

- **Informative:** the id is bound by the commitment's binding
  property. You cannot open the commitment to a different
  encoding id without finding a non-trivial generator relation —
  the same hardness that protects every committed element.
- **Expressive:** the id is an ordinary committed element living
  in the same `G_0..G_n / H` generator family. Homomorphic adds,
  cross-commitment equality, range proofs over payload elements
  — all operate uniformly, with no bespoke tag-point machinery to
  special-case. (A separate tag generator `encoding_id · T` would
  bind the id but tax every future homomorphic relationship,
  which is why it was rejected.)
- **Enabling:** putting the id at position 0 makes "what kind of
  payload is this" the first thing every circuit sees. A circuit
  can branch on it, or prove set-membership over allowed
  encodings, cleanly — which an unbound label cannot support.

The cost is one generator slot (`G_0` is now the id, payload
elements shift to `G_1..G_n`) and a commitment value distinct
from the bare `babyjub-pedersen` commitment to the same stream.
That distinctness is correct: a commitment to a `text-utf8-v1`
payload `[a, b]` and a commitment to a `kv-pairs-v1` payload
`[a, b]` are different points, which is the cross-encoding
defense working as intended.

## Properties

Inherited from [`babyjub-pedersen.md`](./babyjub-pedersen.md),
with the augmented stream:

- **Binding** — the committer cannot open `point` to a different
  `(encoding_id, stream)` pair without a known generator relation.
  This now covers the encoding id, not just the stream.
- **Hiding** — for `blinding` sampled uniformly, `point` reveals
  nothing about the payload. (The `encoding_id` is separately
  public metadata, so it's not hidden — but it's bound.)
- **Element-wise additive homomorphism** —
  `commit(p_a, r_a).point + commit(p_b, r_b).point ==
  commit(p_a + p_b, r_a + r_b).point` where the augmented streams
  add element-wise. Two commitments under the **same encoding
  id** add to a commitment whose position-0 element is
  `2·encoding_id`; consumers relying on the homomorphism under a
  fixed encoding treat position 0 as structural and reconstruct
  it. Cross-encoding adds are well-defined but rarely meaningful.
- **Single-element addressability** — a circuit can prove "the
  i-th payload element is X" by isolating `stream[i] · G_{i+1}`
  (note the `+1` shift from the id occupying `G_0`).

## Construction

### Committing

```text
commit(payload: Payload, blinding: Fr) -> Commitment:
    augmented = [payload.encoding_id, ...payload.stream]
    point     = babyjub-pedersen.commit(augmented, blinding)
    return Commitment { encoding_id: payload.encoding_id, point }
```

### Verifying an opening

There is no separate `verify` function — same discipline as
`babyjub-pedersen`. A verifier recomputes:

```text
verify_opening(commitment, payload, blinding) -> bool:
    expected = commit(payload, blinding)
    return expected.point == commitment.point
        && expected.encoding_id == commitment.encoding_id
```

Both the point AND the encoding id must match. Since the id is
bound into the point, a matching point implies a matching id for
honestly-constructed commitments; the explicit id check is a
cheap defense against a malformed `Commitment` whose metadata id
disagrees with its committed id.

## Rust API contract

```rust
pub struct Commitment {
    pub encoding_id: Fq,
    pub point: EdwardsAffine,
}

/// Commit to a payload under a blinding scalar.
pub fn commit(payload: &Payload, blinding: Fr) -> Commitment;

/// Verify that `commitment` opens to `payload` under `blinding`.
pub fn verify_opening(
    commitment: &Commitment,
    payload: &Payload,
    blinding: Fr,
) -> bool;
```

`commit` is total — any payload, any blinding. `verify_opening`
returns `bool`, not `Result`, because there is exactly one
failure mode (mismatch) and no "broken input" distinction worth a
typed error at this layer.

## Caller responsibilities

- **Randomness for `blinding`.** This spec does not specify a
  source. A production caller MUST sample `blinding` from a CSPRNG
  and MUST NOT reuse it across commitments to different payloads
  (hiding-failure footgun, same as `babyjub-pedersen`).
- **Payload validity.** `commit` does not check that
  `payload.stream` is a well-formed output of the encoding named
  by `payload.encoding_id`. A malformed payload commits fine but
  won't decode. Validity is the encoding's concern, checked at
  decode time.

## On-chain mapping

The Move-side `Commitment` struct implements this spec. Its
layout is the Move package's call, subject to:

- **Field set MUST match:** `encoding_id` (a field element) and
  `point` (two affine coordinates). No extra fields whose
  validity isn't derivable from the spec.
- **The committed value MUST include the encoding id at position
  0.** A Move-side verifier reconstructing the commitment from a
  revealed payload MUST prepend the id before the stream, or the
  point won't match.
- **Field types round-trip** through the Rust↔Move serialization
  as 32-byte little-endian arrays (`Fq`/`Fr`) and coordinate
  pairs (`EdwardsAffine`), matching `babyjub-pedersen`'s wire
  conventions.

## Worked Example

Reuses the `text-utf8-v1` encoding id and a small fixture.
A conformant implementation reproduces every value below exactly.

### Inputs

```text
encoding_id = text-utf8-v1 id
            = 10251905648233427808659162032937842155138269080868533503078341140126603942221
stream      = [1, 2, 3, 4]
blinding    = 12345
augmented   = [encoding_id, 1, 2, 3, 4]
```

### Commitment point

```text
point = commit(augmented, blinding)    // via babyjub-pedersen
point.x = 8508428564166497174489599186311549407051130495712383842299767402731906828819
point.y = 3553708636932923270760553972757244610543695524520017929354621266609419728587
```

A deterministic function of the augmented stream `[encoding_id,
1, 2, 3, 4]` and the protocol's pinned Pedersen generators. The
fixture test `crates/protocol/tests/commitment_fixture.rs`
asserts these decimals; CI catches a drift the moment it lands.

### Negative cases the spec pins

- **Wrong blinding.** `verify_opening` with a different blinding
  returns `false`.
- **Wrong payload element.** Changing any `stream[i]` changes the
  point; `verify_opening` returns `false`.
- **Wrong encoding id.** A commitment to `[id_a, ...stream]` does
  NOT verify against a payload claiming `encoding_id = id_b` with
  the same stream — the augmented streams differ at position 0,
  so the points differ. This is the cross-encoding defense.

## References

- [`encodings/payload.md`](./encodings/payload.md) — the payload
  this commits to; pins the encoding-id construction and the
  public-metadata decision.
- [`babyjub-pedersen.md`](./babyjub-pedersen.md) — the underlying
  vector Pedersen commitment, generators, and homomorphic
  property.
- [`protocol-envelope.md`](./protocol-envelope.md) — the sibling
  composition for confidential delivery (vs. this one's
  commit-then-reveal).
- [`zk/circuit-pedersen-opens-to.md`](./zk/circuit-pedersen-opens-to.md)
  — the circuit proving a commitment opens to a claimed value
  (Level-A encoding-id binding retrofit pending; the stream
  layout shifts by one for the id at position 0).
