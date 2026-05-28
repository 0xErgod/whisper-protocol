# Poseidon Hash — Sponge (`poseidon-hash-sponge-v1`)

This document specifies the variable-length sibling of
[`poseidon-hash-fixed-v1`](./poseidon-hash-fixed.md). The two are
**different hash functions** and produce different outputs on the
same input. Consumers pin which one they use in their own specs.

> **NOTE(name):** scheme tag `poseidon-hash-sponge-v1` is a working
> name. A change to the padding rule, rate, capacity, or
> domain-tag-absorption position mints `-v2`.

**Any implementation that does not reproduce the exact field-element
values in [§ Worked Example](#worked-example) is incompatible with
this scheme.**

## What this is

A duplex sponge over circomlib's Poseidon-3 (state size `t=3`, rate
`r=2`, capacity `c=1`) parameters. The caller-supplied domain tag is
the first element absorbed; the payload elements follow in order; a
length-extension-safety padding marker (a single `1` followed by zero
padding to a rate boundary) terminates the tape. The output is the
first state element after the final permutation.

## When to use this vs the fixed-arity hash

Use sponge when:

- The input length is variable (not known at the consumer's spec
  time).
- The input length exceeds the fixed-arity ceiling (more than 11
  elements after the domain tag).

Use [`poseidon-hash-fixed-v1`](./poseidon-hash-fixed.md) when:

- The input length is known at spec time and `≤ 11`. Fixed-arity is
  cheaper (one permutation) and is the simpler primitive.

The two are **different hash functions**. A consumer that switches
between them is making a breaking change.

## Construction

### Sponge parameters

```text
t = 3                           # state size
r = 2                           # rate (number of elements absorbed per permutation)
c = 1                           # capacity (security parameter)
permutation = Poseidon-3        # circomlib parameters for width 3:
                                #   α = 5, 8 full rounds, 57 partial rounds
```

State width 3 with rate 2 / capacity 1 is the standard duplex sponge
for BN254 Poseidon. The capacity-1 element provides 128-bit security
against generic attacks, which matches the protocol's overall
security target.

### Algorithm

Given a domain tag `d ∈ Fq` and a payload `inputs[0], ..., inputs[n-1]
∈ Fq`:

```text
# 1. Build the absorption tape: domain tag, then payload, then
#    length-extension-safe padding.
tape = [d] ++ inputs ++ [1]                    # the "1" is the pad marker
while len(tape) % r != 0:
    tape ++= [0]                               # zero-pad to a rate boundary

# 2. Initialise the state.
state = [0, 0, 0]                              # all zeros, width t=3

# 3. Absorb the tape, one rate-sized chunk at a time.
for i in 0, 2, 4, ..., len(tape) - 2:
    state[0] += tape[i]
    state[1] += tape[i + 1]
    state = Poseidon-3-permutation(state)      # full permutation, capacity untouched

# 4. Squeeze the first state element.
return state[0]
```

The `Poseidon-3-permutation` is exactly the same round structure
circomlib's `Poseidon` with width 3 (= arity 2 + 1) performs: 8 full
rounds, then 57 partial rounds, then 8 more full rounds, each round
applying `(add round constants) → (S-box: x → x⁵) → (MDS matrix
multiply)`. Round constants and MDS matrix come from circomlib's
published `bn254_x5` parameter tables for state width 3.

### Why pad-1-then-zero

Without the trailing `1` marker, two distinct input streams would
produce the same absorption tape:

```text
inputs = [a]       → tape = [d, a, 0]     # zero-padded to a rate boundary
inputs = [a, 0]    → tape = [d, a, 0]     # same tape!
```

Both would absorb identically and produce the same output — a
length-extension collision. Appending a `1` before the zero-padding
makes the tape unambiguously decode back to a unique input length:

```text
inputs = [a]       → tape = [d, a, 1, 0]
inputs = [a, 0]    → tape = [d, a, 0, 1]   # different tape, different output
```

This is the standard SAFE-ish padding rule for ZK-friendly sponges.

### Why absorb the domain tag first

Placing the domain tag at position 0 of the tape ensures it is part
of the *first* permutation, mixed with the initial payload elements.
Distinct domains diverge as early as possible, with no permutation
applied to the state before the tag enters.

## Edge cases

- **Empty input (`n = 0`)**: tape is `[d, 1]`. Length is 2, exactly
  the rate, so no zero-padding is needed. One permutation, then
  squeeze. The output is a well-defined per-domain constant.

- **Single-element input**: `[d, a, 1, 0]` (length 4, two
  permutations). Distinct from the empty input (different padding,
  different state after absorption).

- **Long input (> 11 elements)**: handled identically; the sponge
  has no upper bound. This is the regime where fixed-arity is
  unavailable.

## Worked Example

A conformant implementation reproduces every value below exactly.
Domain string for the fixture is `"poseidon-hash-fixture-v1"`, the
same one [`poseidon-hash-fixed-v1`](./poseidon-hash-fixed.md) uses —
so the cross-construction differentiator is visible side by side.

### Domain tag

```text
domain_string = "poseidon-hash-fixture-v1"
domain_tag    = 3979466444311687069470688388412388132284863585885029621423754853532995657454
```

### Vector 1 — empty inputs

```text
inputs = []
output = 10642285785463773045920661422493220139048932562145189104824959581581429359133
```

Compare with `poseidon-hash-fixed-v1` Vector 1:
`2004198…495957297`. **Different. The two hashes are distinct
functions.**

### Vector 2 — `[1, 2, 3]`

```text
inputs = [1, 2, 3]
output = 3142103391069538918340996461610585237878047473358483513672836623723625048541
```

Compare with `poseidon-hash-fixed-v1` Vector 2: `1218765…214817674`.
Different.

### Vector 3 — `[42; 8]` (eight copies of 42)

```text
inputs = [42, 42, 42, 42, 42, 42, 42, 42]
output = 5990019678255268617078544532103655242415209041127922847673813392906627566777
```

Compare with `poseidon-hash-fixed-v1` Vector 3: `2868523…336794306`.
Different.

### Vector 4 — `[0, 1, …, 19]` (20 elements)

```text
inputs = [0, 1, 2, ..., 19]
output = 9741254265752179457738278212425315146396646303497642974741669492324356027870
```

The fixed-arity sibling rejects this input (arity 21 > 12 limit).
The sponge accepts and produces a defined output. This vector
demonstrates the sponge's regime — variable-length inputs past the
fixed-arity ceiling.

## Validity contracts

A conformant implementation MUST:

- **Accept inputs of any length.** No upper bound; lower bound is 0
  (empty inputs are well-defined).
- **Reject NO input on length grounds.** All length errors a
  consumer encounters come from the consumer's own preconditions
  (e.g. encoding limits), not from this primitive.
- **Use the pad-1-then-zero rule exactly.** Other padding rules
  (no marker, marker at end of zero pad, different marker value) are
  not interoperable; they produce a different hash function.
- **Match the cross-construction differentiator.** On every input
  where both fixed and sponge produce a defined output, the two
  values MUST differ.

## References

- [`poseidon-hash-fixed-v1.md`](./poseidon-hash-fixed.md) — the
  fixed-arity sibling.
- [`protocol-commitment.md`](./protocol-commitment.md) —
  same circomlib parameters and domain-tag construction.
- Hadeshash / Grain v1 — the SageMath script generating
  circomlib's parameters.
