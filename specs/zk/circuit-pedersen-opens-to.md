# Circuit: `pedersen_opens_to`

This document specifies the protocol's first ZK circuit:
**proving that a Pedersen commitment opens to a stream whose
first element equals a publicly-known value.** Cross-language
compatibility contract between the Rust `circuits` and `prover`
crates and any future verifier (Move-side, JS-side, off-chain).
Built on [`zk/stack.md`](./stack.md) and
[`babyjub-pedersen.md`](../babyjub-pedersen.md).

> **NOTE(name):** circuit tag `pedersen-opens-to`, crate name
> `circuits`, and the `prover` crate name are working names. No
> product name baked in.

**Any prover implementation that does not produce proofs
verifiable against the exact public-input layout in
[§ Verifier interface](#verifier-interface) is incompatible
with this circuit's verifier and will be rejected on-chain.**

## What this circuit proves

The prover demonstrates knowledge of a stream
`[x_0, x_1, ..., x_{N-1}]` and a blinding `r` such that:

```text
commitment        = Σ_i x_i · G_i + r · H            (vector Pedersen)
x_0               = claimed_first_value
```

The verifier learns:

- **Nothing about `x_1..x_{N-1}` or `r`.** The blinding hides
  them via Pedersen's hiding property.
- **That the commitment opens to *some* stream**, and that
  whatever that stream is, the first element equals the public
  value the prover claimed.

The verifier does NOT learn anything about which prover holds
the secret stream — Groth16 proofs are not bound to a prover
identity. Compositions that bind to a prover (signature
verification, key-derivation proofs) live in other circuits.

## Why this is the first circuit

Smallest non-trivial protocol claim that meaningfully exercises
the gadget substrate:

- **Pedersen gadget is the heaviest** in the substrate. If
  trusted setup, prove, and verify work for this circuit, every
  lighter circuit will work without re-validating the prover
  plumbing.
- **No signature math.** Just Pedersen + two equality
  constraints. Keeps the prover layer's bugs visible.
- **Public-input count is 3** of Sui's 8-element cap. Room to
  evolve without compressing via signal-hash.
- **Real protocol shape.** "Commit to a stream, later reveal
  one element" is a building block any envelope-style flow
  ends up using.

## Stream length: `N = 9`

Pinned at the value `text-utf8-v1` produces. Future variants
(e.g. `pedersen-opens-to-n-32` for a longer encoding) live in
their own circuit modules with their own `(PK, VK)` keypair.
Each `N` is its own circuit; arkworks does not let `N` be a
runtime parameter.

## Verifier interface

The verifier MUST consume exactly **3 public inputs**, in this
order:

| Position | Name                  | Type | Meaning                                           |
|----------|-----------------------|------|---------------------------------------------------|
| 0        | `commitment_x`        | `Fq` | x-coordinate of the Pedersen commitment           |
| 1        | `commitment_y`        | `Fq` | y-coordinate of the Pedersen commitment           |
| 2        | `claimed_first_value` | `Fq` | the value the prover claims `stream[0]` equals    |

`Fq` here is BN254's base field — the same prime field
`crypto::babyjub::Fq` aliases and the same field every native
protocol value lives in.

A conformant verifier accepts iff:

```text
Groth16::verify(VK, [commitment_x, commitment_y, claimed_first_value], proof) == true
```

The order matters; passing the inputs in any other order
unsatisfies the verification equation.

## Proving interface

The prover constructs the circuit instance with:

```text
PedersenOpensTo::new(
    commitment           : EdwardsAffine,     // public
    claimed_first_value  : Fq,                // public
    stream               : [Fq; 9],           // witness
    blinding             : Fr,                // witness (Baby Jubjub scalar field)
)
```

and calls `prover::prove(circuit, &pk, &mut rng)`. The proof
artifact is opaque bytes; serialize via
`prover::serialize_proof` for transport / on-chain submission.

## Constraint shape

The numbers below come from
`cargo run -p circuits --example pedersen_opens_to_stats --release`
and are stable across `ark-r1cs-std 0.5.x` patch releases.

| Metric                  | Value  |
|-------------------------|--------|
| `num_constraints`       | 18,703 |
| `num_instance_variables`| 4      |
| `num_witness_variables` | 17,314 |

`num_instance_variables = 4` is the 3 public inputs plus
arkworks' always-1 constant slot at index 0. The verifier's
public-input vector is length 3 (the always-1 slot is internal
plumbing).

If these numbers shift, the gadget substrate changed
substantively — re-run the stats example, update this section,
and consider whether a downstream consumer's setup cost
estimates need revisiting.

## Worked Example

A conformant implementation MUST reproduce every field-element
value below exactly.

### Inputs

```text
stream    = [10, 20, 30, 40, 50, 60, 70, 80, 90]
blinding  = 12345
claimed_first_value = 10
```

### Native commitment

Computed by `crypto::babyjub::commit(&stream, blinding)`:

```text
commitment.x = 5897619111316274370769790191687306012343305332773391509514783004726110239420
commitment.y = 10670721326457331835290598050860396503551558481410756683820575574209654653921
```

These coordinates depend only on the native Pedersen scheme
(`specs/babyjub-pedersen.md`'s pinned `G_i` and `H` generators).
A drift in those generators changes this fixture; a drift in
the circuit's gadget composition does NOT — the gadget mirrors
the native primitive exactly.

### Public-input vector for the verifier

```text
public_inputs = [
    5897619111316274370769790191687306012343305332773391509514783004726110239420,
    10670721326457331835290598050860396503551558481410756683820575574209654653921,
    10,
]
```

In this exact order. The integration test
`crates/prover/tests/pedersen_opens_to.rs` runs the full
setup → prove → verify cycle against this fixture; CI catches a
drift the moment it lands.

## Why proof bytes are NOT pinned in the worked example

A natural question reading the specs above: "where are the proof
bytes?" — every other primitive spec in this protocol pins the
exact output, byte-for-byte.

Groth16 proofs are NOT deterministic in any version-stable way:

- **Setup randomness.** The trusted setup consumes random `tau`,
  `alpha`, `beta` values to produce `(PK, VK)`. Different setup
  runs produce different keys — even with the same RNG seed
  across arkworks versions, internal `RngCore` consumption order
  can shift in a patch release.
- **Prove randomness.** Groth16 proving also consumes randomness
  (for the zero-knowledge property). Same RNG seed under
  arkworks 0.5.0 and 0.5.1 is not guaranteed to produce the same
  proof bytes.
- **Proof bytes are non-malleable but not unique.** A given
  `(PK, public_inputs, witness)` admits many valid proofs.
  Pinning one would falsely suggest others are wrong.

What IS stable and pinned above:

- The **public-input values** (deterministic from protocol
  inputs).
- The **native commitment** (deterministic from `stream` +
  `blinding` + the protocol's pinned Pedersen generators).
- The **constraint shape** (structural, not value-dependent).
- The **circuit's satisfaction relation** — checked by the
  unit test `honest_witness_satisfies`.

What's verified by the integration test, end-to-end:

- A setup → prove → verify cycle on the honest witness produces
  acceptance.
- A proof generated under one `(PK)` rejects under a different
  `(VK)`.
- Changing the public inputs after the fact unsatisfies the
  verification equation.
- Byte-blob serialization round-trips preserve all artifacts.

## Setup artifacts

A conformant deployment ships:

- **`PK` (proving key).** ~17,000-witness, ~18,700-constraint
  Groth16 key. Generated by `prover::setup(PedersenOpensTo::
  empty(), &mut rng)`. Persisted to disk on first boot by the
  prover server; not source-controlled. Size: roughly 8–12 MB
  in arkworks' compressed canonical encoding.
- **`VK` (verifying key).** Small (~hundreds of bytes).
  Generated alongside `PK` from the same setup run. Deployed to
  the on-chain verifier (Sui Move's `groth16_verify_proof`) as
  a byte blob. The Move-side code consumes
  `prover::serialize_vk(&vk)`'s output directly.

**Production trusted setup is a future spec.** The development
path uses `ark_std::test_rng()` (deterministic, reproducible);
production needs a Powers-of-Tau-style ceremony so the random
`tau` is provably unrecoverable. That ceremony's protocol is
not in this document.

## Validity contracts

A conformant prover implementation MUST:

- **Allocate the public inputs in the order pinned in
  § Verifier interface.** Any other order produces a proof
  that does not verify under the standard public-input vector.
- **Allocate `stream` as exactly `N = 9` field elements** as
  witnesses. Different `N` is a different circuit.
- **Use the same Pedersen generators** as
  `specs/babyjub-pedersen.md` pins. The gadget composes
  `gadgets::babyjub::pedersen::commit_var`, which embeds those
  generators as circuit constants — no caller flexibility,
  intentionally.

A conformant verifier implementation MUST:

- **Reject proofs whose serialized form does not decode** under
  `Proof::<Bn254>::deserialize_compressed`.
- **Reject proofs whose public-input count is not exactly 3.**
- **Use the same `VK`** the prover used in setup. A mismatched
  VK rejects every proof; the test
  `pedersen_opens_to_proof_rejects_wrong_vk` confirms this.

## References

- [`zk/stack.md`](./stack.md) — the proving stack this circuit
  targets (Groth16 / BN254 / arkworks 0.5 / circomlib Poseidon).
- [`babyjub-pedersen.md`](../babyjub-pedersen.md) — the
  commitment scheme the circuit binds against; pins the
  generators `G_i` and `H`.
- `crates/circuits/src/pedersen_opens_to.rs` — the
  `ConstraintSynthesizer` impl.
- `crates/prover/tests/pedersen_opens_to.rs` — the end-to-end
  integration test that exercises the fixture above.
- `crates/circuits/examples/pedersen_opens_to_stats.rs` — the
  one-shot probe that reproduces the constraint-shape numbers
  and the worked-example fixture quoted above.
- Sui's [`groth16` Move module](https://docs.sui.io/references/framework/sui-framework/groth16) —
  the on-chain verifier this circuit's `VK` is deployed to.
