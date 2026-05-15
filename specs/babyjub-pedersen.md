# Baby Jubjub Pedersen Commitments (`babyjub-pedersen-v1`)

This document specifies the single-value Pedersen commitment scheme used
by the protocol. It is the cross-language compatibility contract between
the Rust `crypto` crate, the WASM binding, and the TypeScript SDK. Built
on [`babyjub-curve.md`](./babyjub-curve.md).

> **NOTE(name):** scheme tag `babyjub-pedersen-v1` and crate name `crypto`
> are working names. No product name is baked in.

**Any implementation that does not reproduce the exact point coordinates
in [§ Worked Example](#worked-example) is incompatible with this scheme
and will not interoperate.**

## What this defines

A commitment to a single field element `value ∈ F_l`, blinded by a
caller-supplied scalar `blinding ∈ F_l`:

```text
C = value · G + blinding · H
```

where:

- `G` is `Base8`, the protocol's standard generator (see
  [`babyjub-curve.md`](./babyjub-curve.md)).
- `H` is a second prime-order-subgroup point pinned in this spec. Its
  discrete log with respect to `G` is unknown by construction — without
  that property, a malicious committer could equivocate (open the same
  `C` to two different values).

The commitment is:

- **Binding**: the committer cannot open `C` to a value other than the
  one they committed to without solving `log_G(H)`, which is
  computationally infeasible for an honestly-derived `H`.
- **Hiding**: for `blinding` sampled uniformly at random from `F_l`,
  `C` reveals nothing about `value`.
- **Additively homomorphic**:
  `commit(a, r_a) + commit(b, r_b) == commit(a+b, r_a+r_b)`. A property
  the protocol's commitment layer can rely on for operations like
  summing committed values without opening them.

## What this does NOT define

- **Multi-message vector Pedersen** (`C = Σ value_i · G_i + blinding · H`).
  Straightforward extension; not implemented because no consumer needs it
  yet. A future addendum would pin additional generators `G_1, G_2, ...`
  via the same nothing-up-my-sleeve derivation.
- **Pedersen as a hash function** (commit-to-bit-vector without
  blinding). Different primitive; `circomlib` has one.
- **Verification function.** Verification is `commit(value, blinding) == C`
  — re-run the commitment and compare. No separate `verify` exists by
  design; adding one would obscure the relationship.
- **Zero-knowledge proofs of opening.** Future bricks.

## Caller responsibilities

- **Randomness for `blinding`**: this spec does not specify a source.
  Consistent with the rest of the protocol's primitives, randomness is
  outsourced. A production caller MUST sample `blinding` from a
  cryptographically secure source; a deterministic test or fixture MAY
  use a fixed value. Reusing `blinding` across commitments to different
  values is a hiding-failure footgun — implementations SHOULD document
  this hazard at the caller's surface.
- **Value range**: `value` is any element of `F_l`. The protocol's
  application layer is responsible for any narrower constraint (e.g.
  "the value is a 32-bit unsigned integer") and for proving membership
  in that range, which is its own future ZK-proof brick.

## The second generator `H`

### Derivation (procedure)

`H` is derived from a fixed UTF-8 domain string by try-and-increment
hash-to-curve, with cofactor clearing:

```text
DOMAIN     = "babyjub-pedersen-h-v1"
seed       = Blake2b-256(DOMAIN)
for counter in 0, 1, 2, ...:
    bytes  = seed || counter_as_big_endian_4_bytes
    digest = Blake2b-256(bytes)
    y      = bytes_to_field_be(digest) mod p     // candidate y-coordinate
    want_odd_x = digest[0] >> 7                  // top bit picks the x sign
    if x² := (1 - y²) / (a - d·y²) has a square root in F_p:
        x = chosen_sqrt
        if (x is odd) != want_odd_x: x = -x      // disambiguate the two roots
        if (x, y) is on the curve:
            P = (x, y)
            H = 8 · P                            // cofactor-clear into the subgroup
            if H is not identity and l · H == identity:
                return H
```

Notes on the construction:

- **Curve equation**: twisted Edwards `a·x² + y² = 1 + d·x²·y²` with
  the ERC-2494 parameters pinned in `babyjub-curve.md`.
- **Why try-and-increment**: not every `y` in `F_p` is the `y`-coordinate
  of an on-curve point. Roughly half are; incrementing a counter until
  one is found is standard. Distribution of `H` over the subgroup
  remains uniform in practice.
- **Disambiguating roots**: `(x, y)` and `(-x, y)` are both on the
  curve. The top bit of the digest picks which one, so the procedure
  is fully deterministic — every implementation, in every language,
  ends up on the same `H`.
- **Cofactor clear**: any on-curve point times the cofactor `h = 8`
  lands in the prime-order subgroup. The final `l · H == identity`
  check is defence-in-depth — mathematically redundant after
  cofactor-clearing, but pins the invariant so a future subgroup-order
  bug fails loudly.

### Derivation (result)

`H` for `babyjub-pedersen-v1` is the affine point:

```text
H.x = 841592716755229802932648006577806087532565884664794707633999447952449024030
H.y = 21165608275098473985804540174915770236470038226241417420449949757110115410790
```

A conformant implementation MUST reproduce these coordinates *or*
re-derive them via the procedure above. Hardcoding the result is the
norm in production paths; the spec contract is that re-deriving
produces the same point.

## Worked Example

Conformant implementations reproduce every coordinate below exactly.

### Vector 1 — `value = 1, blinding = 2`

```text
C.x = 19911656000857052962597456184037789990217243984679140824149869840037557852443
C.y = 34605269953567020705948092501852398380697724299788400696888085852242656086
```

### Vector 2 — `value = 1, blinding = 3`

Same value, different blinding — yields a different commitment. Demonstrates
the hiding contribution of the blinding term.

```text
C.x = 9723198969615360247427292934898140973342948570751173978342403991207916323546
C.y = 19044047517359543872210876966731992607318248008643325810704580417544715049471
```

### Vector 3 — `value = 42, blinding = 2`

```text
C.x = 1804774864997895270957637913205168337534034589478355406223869248964063078669
C.y = 17220584685130698597038207882485107316548594410613344843261730748713825165424
```

### Vector 4 — `value = 43, blinding = 5`

```text
C.x = 9316700122791050606807820069898233419825981554378647093992330639267548556400
C.y = 8709108737583240974862181978592935408278162780419237157205423253882576286426
```

### Vector 5 — `value = 85, blinding = 7` (= Vector 3 + Vector 4)

`85 = 42 + 43` and `7 = 2 + 5`, so the additive-homomorphism property
predicts `Vector 5 == Vector 3 + Vector 4` in the group. A conformant
implementation MUST produce both the explicit `commit(85, 7)` below and
the same point as the group sum of `Vector 3 + Vector 4`.

```text
C.x = 6870881176262591255209957784559476352128178258958653506281010548778139552124
C.y = 21358251945557300339181094850512781582761528410355366539487020884672487905717
```

## Validity contracts

A conformant implementation MUST:

- **Produce commitments in the prime-order subgroup.** Follows
  mathematically from `G` and `H` both being subgroup generators, but a
  decoder accepting an external commitment value (a stored on-chain
  point, a JS-side input) MUST validate via `point_from_strings` (which
  enforces on-curve + prime-subgroup) before any downstream use.

- **Reject `H == G`**, `H == identity`, and `log_G(H)` known to the
  caller. These are derivation-correctness requirements; if any holds,
  binding or hiding is lost.

- **Treat the blinding scalar as sensitive.** The blinding is the
  hiding contribution. If it leaks, the commitment becomes a
  deterministic hash of `value`, which is trivially brute-forceable for
  small value spaces.

## References

- [`babyjub-curve.md`](./babyjub-curve.md) — the curve `H` lives on.
- [`babyjub-keypair.md`](./babyjub-keypair.md) — same scalar field
  conventions, same "caller supplies randomness" pattern.
- Pedersen, T. P. (1991). *Non-interactive and information-theoretic
  secure verifiable secret sharing*. CRYPTO '91. The original
  construction.
