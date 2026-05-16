# Baby Jubjub Key Derivation Function (`babyjub-kdf`)

This document specifies the key derivation function used by the
protocol to turn an ECDH shared point into symmetric key material.
Cross-language compatibility contract between the Rust `crypto`
crate, the WASM binding, and the TypeScript SDK. Built on
[`babyjub-curve.md`](./babyjub-curve.md),
[`babyjub-ecdh.md`](./babyjub-ecdh.md),
[`poseidon-hash-fixed.md`](./poseidon-hash-fixed.md).

> **NOTE(name):** scheme tag `babyjub-kdf` and crate name `crypto`
> are working names. No product name baked in.

**Any implementation that does not reproduce the exact field-element
values in [§ Worked Example](#worked-example) is incompatible with
this scheme.**

## What this is

A function:

```text
derive(shared: G, context: Fq*) -> Fq
```

that takes a Baby Jubjub shared-secret curve point (the output of an
ECDH exchange) and a caller-supplied context — itself a stream of
field elements — and produces one field element suitable as a
symmetric key for downstream primitives (stream cipher, MAC,
key-confirmation, etc.).

```text
key = Poseidon-hash-fixed(kdf_domain, [shared.x, shared.y, ...context])
```

The construction is exactly one fixed-arity Poseidon call under a
dedicated KDF domain tag.

## What this is FOR

The canonical use is "I have a shared ECDH point with a peer and
want to derive symmetric keys for an envelope." The caller invokes
`derive` once per *role* that needs its own key, with a context
that distinguishes the roles:

```text
shared  = babyjub-ecdh(my_sk, peer_pk)
key_enc = babyjub-kdf(shared, [ENC_ROLE_TAG, envelope_id])
key_mac = babyjub-kdf(shared, [MAC_ROLE_TAG, envelope_id])
```

`key_enc` and `key_mac` are unrelated to anyone without the shared
point. The Poseidon hash's preimage and second-preimage resistance,
combined with the role-tag domain separation, ensure that learning
one key tells you nothing about the other.

## What this is NOT

- **A password KDF.** Argon2 / scrypt / bcrypt are for low-entropy
  inputs (passwords) and are deliberately slow to compute. This KDF
  assumes the input is already high-entropy: a curve point in the
  prime-order subgroup, indistinguishable from a uniformly-random
  subgroup element to anyone without one of the ECDH secrets.
- **An expander.** The output is always one field element. If a
  consumer needs multiple keys, it calls `derive` multiple times
  with different role tags. The composition is honest about the
  one-key-per-call shape.
- **A hash function.** It is one, internally — the contract is
  "produce key material," not "produce a cryptographic hash."
  Those contracts collapse for our use, but the name `derive`
  makes the intended use explicit.

## Context conventions

The `context` slice is **free-form** — the KDF itself does not
inspect it beyond passing it to Poseidon. Each consumer's spec
defines its context structure.

The standard pattern for envelope-style uses:

```text
context[0] = role_tag         # domain_tag("envelope-cipher-key"), etc.
context[1] = envelope_id      # or session id, or recipient index
context[2..] = additional binding fields as needed
```

The **role tag** distinguishes which downstream key is being derived
(encryption vs MAC vs key-confirmation). The role tag is itself
derived from a string via the same `bytes_to_field_be(Blake2b-256)`
construction every other domain tag in the protocol uses, so the
value is stable across implementations.

**Two role tags are pinned in this spec** for the canonical
envelope-cipher / envelope-MAC pair. Other roles will mint their
own tags in their consumer specs.

```text
ENC_ROLE_TAG = domain_tag("envelope-cipher-key")
             = 1509687719585944131241352475068886393759608140501623646780323187386706626075

MAC_ROLE_TAG = domain_tag("envelope-mac-key")
             = 5516219051016623209397290384142210256012461986142239137807233927652814454837
```

## Length cap

Imposed by `poseidon_hash_fixed`'s arity ceiling. The total
Poseidon arity is `1 + 2 + context.len()` (1 domain tag + 2 shared
coordinates + payload), which must be ≤ 12, so:

```text
MAX_CONTEXT_LEN = 9
```

A 9-element context is wide enough for every realistic protocol use
(role tag + a few binding fields). The cap is checked at runtime;
over-length context returns a typed error, never silently
truncates.

## Reductions

The output lives in `F_p`. Downstream consumers that need an `F_l`
scalar — for example, to use the key as a scalar multiplier — MUST
reduce explicitly via the protocol's standard `F_p → F_l` route:
serialize to little-endian bytes, re-parse into `F_l`. The bias
from this 254 → 251 bit reduction is `~2⁻²⁵¹` on uniform input, far
below cryptographic relevance.

The KDF itself produces an `F_p` element because that's what
Poseidon outputs into; making the reduction the consumer's
responsibility keeps the primitive's contract simple and lets
consumers that don't need the reduction skip it.

## Domain tag

```text
domain_string = "babyjub-kdf"
domain_tag    = 3272219569682266499062102338613573932030460640565260915701467620907397074782
```

## Worked Example

A conformant implementation reproduces every value below exactly.

### Shared point

Reuses Alice/Bob from [`babyjub-ecdh.md`](./babyjub-ecdh.md):

```text
Alice seed = 0x01 followed by 63 × 0x00
Bob   seed = 0x02 followed by 63 × 0x00
shared.x   = 4441722070262887487676852990759346353102280890264110527729805261601919952792
shared.y   = 18505774984025635106527431283405915983682689754171973024874112571296549171475
```

### Vector 1 — empty context

```text
context = []
key     = 17636122932579740171900542371485785762200772773883779227467254854068102551698
```

The "no binding" baseline. Useful as a default key when no
per-session context is available. Distinct from any non-empty
context.

### Vector 2 — cipher-key role, envelope id 42

```text
context = [ENC_ROLE_TAG, 42]
key     = 9799522521534548758133939899702695884003167902663631833387651174524282263857
```

The canonical "derive the encryption key for envelope 42"
invocation.

### Vector 3 — mac-key role, envelope id 42

```text
context = [MAC_ROLE_TAG, 42]
key     = 5302105009719633730025155498822445041452574923386899996802294480945238328306
```

Same envelope, different role. **MUST differ from Vector 2** — the
load-bearing role-separation property. A conformant implementation
that produces equal Vector-2 and Vector-3 keys has a domain-tag
construction error and is unsound.

### Vector 4 — cipher-key role, envelope id 43

```text
context = [ENC_ROLE_TAG, 43]
key     = 3185156709054186265396033369944106490450552430667171551230702264382884908002
```

Same role as Vector 2, different envelope id. **MUST differ from
Vector 2** — pins the per-envelope binding.

### Vector 5 — max-length context

```text
context = [1, 2, 3, 4, 5, 6, 7, 8, 9]
key     = 14698107046409286502950871063352220665802808368062148839547149322586317350782
```

A 9-element context, the maximum allowed. A 10-element context
returns a typed length error from `derive`; no silent truncation.

## Validity contracts

A conformant implementation MUST:

- **Reject `context` of length > 9** with a typed error from
  `derive`. No silent truncation.
- **Accept a curve point directly** (not as wire-decoded
  coordinates). The KDF is defined on the curve; validity of the
  point is the caller's job (it comes from `shared_secret` or
  `point_from_strings` — both already validate).
- **Treat the output as sensitive.** A KDF output is symmetric key
  material — anyone with it can encrypt or MAC, depending on how
  it's used. Production code SHOULD treat the value with the same
  hygiene the secret-key path uses.
- **Match every pinned vector byte-for-byte.**

## References

- [`babyjub-ecdh.md`](./babyjub-ecdh.md) — the shared-point input.
- [`poseidon-hash-fixed.md`](./poseidon-hash-fixed.md) — the
  underlying hash, including the arity-12 cap that determines
  `MAX_CONTEXT_LEN`.
- HKDF (RFC 5869) — the canonical Western-stack KDF; this scheme
  is the same idea (extract a uniformly-distributed key from a
  high-entropy input, then bind to a context for domain
  separation) over the protocol's circuit-friendly primitives.
