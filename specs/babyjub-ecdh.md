# Baby Jubjub ECDH Shared Point (`babyjub-ecdh-v1`)

This document pins the Baby Jubjub ECDH shared-point operation: given
the caller's secret key and a peer's public key, derive the curve point
both parties land on. It is the cross-language compatibility contract
between the Rust `crypto` crate, the WASM binding, and the TypeScript
SDK. Built on [`babyjub-curve.md`](./babyjub-curve.md) and
[`babyjub-keypair.md`](./babyjub-keypair.md).

> **NOTE(name):** scheme tag `babyjub-ecdh-v1` and crate name `crypto` are
> working names. The protocol's public name is undecided — no product name
> is baked in.

**Any implementation that does not reproduce the exact shared point in
[§ Worked Example](#worked-example) is incompatible with this scheme and
will not interoperate.**

## What this defines, and what it deliberately does NOT

This spec covers **only the shared point** — `sk_self · PK_peer`. It does
NOT cover:

- **The KDF** that turns the shared point into per-envelope key material.
  That belongs to the envelope-suite spec because its domain separation
  depends on the suite identifier, recipient index, and AAD format, none
  of which exist yet.
- **The transport** of the shared point or any derivative.
- **Authentication.** ECDH alone gives confidentiality against passive
  observers, not identity binding. A future Schnorr-signature spec
  provides that.

Keeping ECDH as just the curve operation leaves it composable: for
envelope encryption (via the future suite's KDF), for equality proofs,
for password-authenticated key exchange variants, for whatever the
protocol grows into. A KDF baked in here would tie ECDH to one
consumer.

## The operation

Given:

- `sk_self ∈ F_l` — the caller's secret scalar (from
  [`babyjub-keypair.md`](./babyjub-keypair.md))
- `PK_peer ∈ G` — the peer's public point, already on the curve and in
  the prime-order subgroup (the contract `PublicKey` carries)

The shared point is:

```text
K_shared = sk_self · PK_peer
```

Symmetry — the defining property:

```text
sk_A · PK_B = sk_A · (sk_B · Base8)
            = sk_B · (sk_A · Base8)
            = sk_B · PK_A
```

Both parties compute the same affine `K_shared`. The fixture below pins
that this holds at byte level, not only in principle.

## Validity contracts

A conformant implementation MUST:

- **Validate `PK_peer` before computing the shared point.** On-curve
  *and* in the prime-order subgroup. The Rust crate enforces this by
  requiring a `PublicKey`-typed argument, which can only be constructed
  via paths that validate (`keypair_from_seed` or
  `point_from_strings`). A direct `(x, y)` decoding bypass is not
  acceptable. The reason: a small-order peer key forces a low-order
  shared secret, leaking information about `sk_self` and trivially
  breaking confidentiality.

- **Treat `K_shared` as in the prime-order subgroup.** Scalar
  multiplication preserves subgroup membership, so this follows from
  validated inputs.

- **Not expose `sk_self` across language boundaries.** The TypeScript
  side derives `sk_self` from a 64-byte seed on every use, computes the
  shared point, and forgets the scalar. The WASM binding takes the seed
  as input — not `sk_self` itself — for exactly this reason.

## Worked Example

A conformant implementation reproduces every coordinate below exactly.

### Seeds

```text
Alice seed = 0x01 followed by 63 × 0x00   (64 bytes total)
Bob   seed = 0x02 followed by 63 × 0x00   (64 bytes total)
```

These derive (via [`babyjub-keypair.md`](./babyjub-keypair.md)) to:

```text
PK_Alice.x = 5973620972294513314673339121277153508734624544832413721485350068184114274974
PK_Alice.y = 17578450795250715997356049057547570616306557704415636814477109373899234445795

PK_Bob.x   = 10663274534402736726963618346545626675833419329443596343571402089744699622013
PK_Bob.y   = 17118641971790752267450378861266165944315881057953088539621212593641527445102
```

### Shared point

Both `sk_Alice · PK_Bob` and `sk_Bob · PK_Alice` equal:

```text
K_shared.x = 4441722070262887487676852990759346353102280890264110527729805261601919952792
K_shared.y = 18505774984025635106527431283405915983682689754171973024874112571296549171475
```

A conformant test asserts both computations land on these exact
decimals — the symmetry is a runtime invariant, not an inferred
property.

## References

- [`babyjub-curve.md`](./babyjub-curve.md) — the curve.
- [`babyjub-keypair.md`](./babyjub-keypair.md) — how `sk` and `PK` are
  derived from a seed.
