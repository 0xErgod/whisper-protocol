# Poseidon Hash — Fixed-Arity (`poseidon-hash-fixed-v1`)

This document specifies one of the two Poseidon hash families the
protocol uses to compress domain-tagged sequences of field elements
into a single field element. The other is
[`poseidon-hash-sponge-v1`](./poseidon-hash-sponge.md) — they are
**different hash functions** and produce different outputs on the same
input. Consumers pin which one they use in their own specs.

> **NOTE(name):** scheme tag `poseidon-hash-fixed-v1` is a working
> name. No product name baked in. A future tweak (different padding
> rule, different position for the domain tag) mints `-v2`.

**Any implementation that does not reproduce the exact field-element
values in [§ Worked Example](#worked-example) is incompatible with
this scheme.**

## What this is

A single Poseidon-`(1 + n)` permutation over the BN254 scalar field
with circomlib parameters. The caller-supplied domain tag occupies
position 0 of the Poseidon input; the `n` payload elements follow in
order.

```text
output = circomlib_Poseidon_(1+n) (domain_tag, inputs[0], inputs[1], ..., inputs[n-1])
```

## When to use this vs the sponge

Use fixed-arity when:

- The input length `n` is known at the consumer's spec time.
- `1 + n ≤ 12` (i.e. `n ≤ 11`). Beyond this, fixed-arity is
  unavailable — `light-poseidon` ships circomlib parameter tables for
  total Poseidon arity up to 12 (state width up to 13).

Use [`poseidon-hash-sponge-v1`](./poseidon-hash-sponge.md) when:

- The input length is variable (e.g. a MAC over a variable-length
  payload + AAD).
- The input length exceeds 11.

The two are **different hash functions**. A consumer that switches
from fixed to sponge (or vice versa) is making a breaking change to
every value it produces — re-spec, re-fixture, mint a new `-v<n>`.

## Domain tag

The domain tag is a single `Fq` element. By convention it is derived
from a UTF-8 string via:

```text
domain_tag = bytes_to_field_be(Blake2b-256(domain_string))
```

— the same construction other protocol specs use
([`babyjub-keypair.md`](./babyjub-keypair.md),
[`poseidon-commitment-format.md`](./poseidon-commitment-format.md)).
A consumer's spec MUST pin its specific `domain_string`. The hash
function itself takes the already-derived `Fq` element; it does not
hash strings.

## Parameter set

Circomlib's BN254 Poseidon parameters with α = 5 S-boxes, 8 full
rounds, and partial-round counts pinned per arity in
[`PARTIAL_ROUNDS`](https://github.com/Lightprotocol/light-poseidon/blob/main/src/parameters/bn254_x5.rs).
Each `(1 + n)` value picks the matching parameter set; **different `n`
produces a different concrete hash function** (different round
constants, different MDS matrix, different round count).

The library `light-poseidon` is used in the canonical Rust
implementation. A conformant implementation in another language MUST
use the same circomlib parameters; `poseidon-lite` is the JS
counterpart.

## Arity bounds

```text
ALLOWED:  1 ≤ 1 + n ≤ 12          ⇒  0 ≤ n ≤ 11
REJECT:   1 + n > 12              (use poseidon-hash-sponge-v1 instead)
```

The upper bound is determined by which circomlib parameter tables
`light-poseidon` ships. Tables for higher arities exist in circomlib's
own SageMath generator but are not part of this library; if a future
protocol need pushes past arity 12, either the parameter tables get
extended (a breaking change minting a new `-v<n>`) or the sponge
variant is used instead.

## Worked Example

A conformant implementation reproduces every value below exactly.
Domain string for the fixture is `"poseidon-hash-fixture-v1"`, the
same one [`poseidon-hash-sponge-v1`](./poseidon-hash-sponge.md) uses
— so the cross-construction differentiator (the two specs' outputs on
the same inputs must differ) is visible side by side.

### Domain tag

```text
domain_string = "poseidon-hash-fixture-v1"
domain_tag    = 3979466444311687069470688388412388132284863585885029621423754853532995657454
```

### Vector 1 — empty inputs

```text
inputs = []
output = 20041987324127481975055040243862195468401413291871545710243215988343495957297
```

This is `Poseidon-1(domain_tag)` — the domain-tag-only hash; a
per-domain constant. Even with no payload, the output is non-trivial
and distinct from the domain tag itself.

### Vector 2 — `[1, 2, 3]`

```text
inputs = [1, 2, 3]
output = 12187659365913684405060258586364191053768216120494362944135933139066214817674
```

Total arity 4 → circomlib Poseidon-4.

### Vector 3 — `[42; 8]` (eight copies of 42)

```text
inputs = [42, 42, 42, 42, 42, 42, 42, 42]
output = 2868523744403348874235778030142570132454685527577859032935933827672336794306
```

Total arity 9 → circomlib Poseidon-9.

### Vector 4 — `[0, 1, …, 19]` is OUT OF RANGE

```text
inputs = [0, 1, 2, ..., 19]   (20 elements)
output = ArityOutOfRange { total_arity: 21 }
```

A conformant implementation MUST reject this input with an error
indicating the arity-out-of-range condition. The sponge variant
accepts the same input and produces a defined output; see
[`poseidon-hash-sponge-v1.md § Worked Example`](./poseidon-hash-sponge.md#worked-example).

## Validity contracts

A conformant implementation MUST:

- **Reject inputs that violate the arity bound.** No silent
  truncation; the caller has to know the limit.
- **Match the cross-construction differentiator.** On every input
  where both fixed and sponge produce a defined output, the two
  values MUST differ. The fixture's Vector 1, 2, and 3 each pin one
  side; the matching sponge spec pins the other; they are different.

## References

- [`poseidon-hash-sponge-v1.md`](./poseidon-hash-sponge.md) — the
  variable-length sibling, used when the input length is unknown or
  exceeds 11.
- [`poseidon-commitment-format.md`](./poseidon-commitment-format.md) —
  the original protocol use of Poseidon, with the same circomlib
  parameters and the same `bytes_to_field_be(Blake2b256(domain))`
  domain-tag construction.
- [`light-poseidon`](https://github.com/Lightprotocol/light-poseidon)
  — the canonical Rust implementation.
- [`poseidon-lite`](https://www.npmjs.com/package/poseidon-lite) —
  the canonical TS implementation; same parameter set.
