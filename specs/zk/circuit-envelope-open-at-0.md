# Circuit: `envelope_open_at_0`

This document specifies the protocol's second ZK circuit:
**proving that the prover is the legitimate recipient of an
envelope, and revealing one specific element of the recovered
plaintext** (the first element, at position 0) without
revealing the rest, the recipient's secret key, or any other
private state.

Cross-language compatibility contract between the Rust
`circuits` and `prover` crates, the `prover-server` HTTP
transport, the `prover-wasm` browser transport, and any future
verifier (Move-side, JS-side, off-chain). Built on
[`zk/stack.md`](./stack.md),
[`protocol-envelope.md`](../protocol-envelope.md), and the
underlying primitive specs `babyjub-{ecdh,kdf,cipher,mac}.md`.

> **NOTE(name):** circuit tag `envelope-open-at-0` is a working
> name. No product name baked in.

**Any prover implementation that does not produce proofs
verifiable against the exact public-input layout in
[§ Verifier interface](#verifier-interface) is incompatible
with this circuit's verifier and will be rejected on-chain.**

## What this circuit proves

The prover demonstrates knowledge of a recipient secret key
`sk_b` such that, for a specific envelope, the encrypt-then-MAC
opening procedure succeeds AND the resulting plaintext's
**first element** equals a publicly-known value.

```text
shared        = sk_b · sender_pk
key_enc       = kdf(shared, [ENC_ROLE_TAG, envelope_id])
key_mac       = kdf(shared, [MAC_ROLE_TAG, envelope_id])
mac(key_mac, [encoding_id, ...ciphertext])  =  mac_tag   (verifier check)
plaintext     = cipher.decrypt(key_enc, ciphertext)
plaintext[0]  =  claimed_value                (revealed claim)
```

The verifier learns:

- **The prover holds the secret key behind the envelope's
  `recipient_pk`.** (The MAC verification gates everything; it
  only passes under the shared point that `sk_b · sender_pk`
  produces.)
- **The plaintext's first element equals `claimed_value`.**
- **Nothing about the rest of the plaintext** or about `sk_b`.

## Why this is the second circuit

After `pedersen_opens_to` shook out the prover plumbing, this
is the first circuit that exercises the *envelope* — the
protocol's headline data structure — and the first that
composes ECDH, KDF, cipher, and MAC gadgets together. It's the
substrate's integration test.

It also unlocks a real protocol pattern: **selective
disclosure of envelope content**. The recipient can prove "the
envelope I received under id X contains value Y at position 0"
to a third party (the chain, a verifier service) without
revealing the rest of the envelope's payload.

## Public inputs (2 of 8)

```text
| Position | Name         | Type | Meaning                                   |
|----------|--------------|------|-------------------------------------------|
| 0        | signal       | Fq   | Poseidon-sponge hash of envelope fields   |
| 1        | claimed_value| Fq   | the value the prover claims equals        |
|          |              |      | plaintext[0]                              |
```

Six slots of headroom for future variants.

## Signal hash: the compression pattern

The naive layout would have every envelope field as its own
public input — `sender_pk.x`, `sender_pk.y`, `recipient_pk.x`,
`recipient_pk.y`, `envelope_id`, `encoding_id`, `mac_tag`, plus
`N` ciphertext elements. For `N=9` that's 16 fields, well over
Sui's 8-input cap.

The protocol's solution is the **signal-hash compression
pattern** pinned in [`zk/stack.md`](./stack.md): collapse the
bulk-public fields into one Poseidon-sponge hash, expose that
hash as a single public input. The verifier (Move-side, etc.)
reconstructs `signal` from the authoritative on-chain envelope
and passes it alongside the proof.

### Signal construction

```text
signal_domain = bytes_to_field_be(Blake2b-256("envelope-open-signal"))

signal = poseidon_hash_sponge(
    signal_domain,
    [
        sender_pk.x,
        sender_pk.y,
        recipient_pk.x,
        recipient_pk.y,
        envelope_id,
        encoding_id,
        mac_tag,
        ciphertext[0],
        ciphertext[1],
        ...
        ciphertext[N-1],
    ],
)
```

The signal binds **everything an outside observer would need
to recompute** about the envelope. The circuit reconstructs
`signal` from its witness envelope fields and enforces
equality against the public signal input — so a prover who
lies about any field (e.g. claims a different ciphertext than
what the chain stores) produces a proof whose internal signal
doesn't match the public one, and the proof fails.

### Why the signal does NOT include `claimed_value` or `position`

`claimed_value` is its own public input — the verifier wants
to see it directly, not derive it from the signal.

`position` is compile-time-fixed at 0 in this circuit variant.
A future `envelope_open_at_3` variant would have a different
circuit, a different VK, the same signal layout (because the
signal is about the *envelope*, not the *claim shape*).

## Stream length: `N = 9`

Pinned at the value `text-utf8-v1` produces. Different `N` is a
different circuit with its own `(PK, VK)`. Future variants:

- `envelope_open_at_0_n_32` — for a 32-element encoding.
- `envelope_open_at_3` — same N, different position.

Each one is independent; no runtime parameterization.

## Verifier interface

The verifier MUST consume exactly **2 public inputs**, in this
order:

```text
[signal, claimed_value]
```

A conformant verifier accepts iff:

```text
Groth16::verify(VK, [signal, claimed_value], proof) == true
```

### Move-side reconstruction

A Sui Move verifier reads the authoritative on-chain
`Envelope` object, computes `signal` natively (using the same
Poseidon sponge construction), and passes
`[signal, claimed_value]` to `groth16_verify_proof`. The
prover cannot lie about envelope fields because the chain
holds the authoritative copy; the prover cannot lie about
`claimed_value` because the verifier sees it directly.

## Proving interface

The prover constructs the circuit instance with:

```text
EnvelopeOpenAt0::new(
    // public
    signal              : Fq,
    claimed_value       : Fq,
    // witness
    recipient_sk        : Fr,
    sender_pk           : EdwardsAffine,
    recipient_pk        : EdwardsAffine,
    envelope_id         : Fq,
    encoding_id         : Fq,
    ciphertext          : [Fq; 9],
    mac_tag             : Fq,
)
```

The witness includes the recipient's secret key AND the full
envelope state (because the signal-hash binding requires
reproducing every envelope field inside the circuit). The
caller is responsible for computing `signal` from the same
envelope fields (a helper in the circuit crate provides this).

## Witnesses

The intermediate values the circuit allocates internally
(shared point, derived keys, decrypted plaintext) are not
caller-supplied; the circuit derives them from the primary
witnesses above. Specifically:

```text
shared       = recipient_sk · sender_pk          (via scalar_mul_var)
key_enc      = kdf_derive_var(shared, [ENC_ROLE_TAG, envelope_id])
key_mac      = kdf_derive_var(shared, [MAC_ROLE_TAG, envelope_id])
computed_mac = mac_var(key_mac, ciphertext)
plaintext    = decrypt_var(key_enc, ciphertext)
```

## Constraints

The circuit enforces:

```text
1. shared = scalar_mul_var(recipient_sk, sender_pk)
   (one curve scalar-mul, ~5k constraints)

2. recipient_pk = scalar_mul_var(recipient_sk, generator)
   — pins that the witness recipient_sk actually corresponds
   to the recipient_pk that hashes into the signal. Without
   this, a malicious prover could supply any (sk, sender_pk)
   pair whose product yields a valid ECDH shared with
   *some* envelope's MAC key.

3. enforce_equal(mac_var(key_mac, ciphertext), mac_tag)
   — the MAC check, gating decryption.

4. enforce_equal(decrypt_var(key_enc, ciphertext)[0], claimed_value)
   — the revealed-value constraint.

5. enforce_equal(
       poseidon_hash_sponge_var(
           signal_domain,
           [sender_pk.x, sender_pk.y, recipient_pk.x, recipient_pk.y,
            envelope_id, encoding_id, mac_tag, ciphertext...]
       ),
       signal,
   )
   — the signal-hash binding to public input #0.
```

Constraint 2 is load-bearing — without it, the recipient_pk
field of the witness is never tied to recipient_sk, and a
prover could craft a proof for any (sender_pk, recipient_pk,
sk) triple where sk · sender_pk happens to be a valid ECDH
shared point. Constraint 2 forces the circuit's witness
recipient_pk to be the one derivable from witness
recipient_sk, and the signal hash binds witness recipient_pk
to the public envelope.

## Constraint shape

Numbers come from
`cargo run -p circuits --example envelope_open_at_0_stats --release`
(planned, parallel to the `pedersen_opens_to_stats` example).

| Metric                  | Value  |
|-------------------------|--------|
| `num_constraints`       | 11,617 |
| `num_instance_variables`| 3 (2 public inputs + arkworks' always-1 slot) |
| `num_witness_variables` | 11,625 |

These numbers are stable across `ark-r1cs-std 0.5.x` patch
releases. If they shift, the gadget substrate changed
substantively — re-run the stats example, update this section.

## Worked Example

Reuses the canonical Alice/Bob/envelope-42 fixture from
[`protocol-envelope.md § Worked Example`](../protocol-envelope.md).
A conformant implementation reproduces every value below
exactly.

### Inputs

```text
Alice seed   = 0x01 followed by 63 × 0x00
Bob seed     = 0x02 followed by 63 × 0x00
envelope_id  = 42
plaintext    = [1, 2, 3, 4, 5, 6, 7, 8, 9]   (9 elements for N=9)
position     = 0                              (fixed by this circuit variant)
claimed_value = 1                             (the prover claims plaintext[0] = 1)
```

The native envelope (`protocol::envelope::seal(...)`) produces:

```text
sender_pk    = Alice's public key (see babyjub-keypair.md)
recipient_pk = Bob's public key   (see babyjub-keypair.md)
envelope_id  = 42
ciphertext   = [
    ciphertext[0],
    ...
    ciphertext[8],
]
mac_tag      = mac.mac(key_mac, ciphertext)
```

(The exact ciphertext and mac_tag for the 9-element plaintext
are pinned in this circuit's integration fixture — they're a
function of `babyjub-cipher.md`'s and `babyjub-mac.md`'s
Vector 4 chained through the envelope construction.)

### Signal

```text
signal = poseidon_hash_sponge(
    domain_tag("envelope-open-signal"),
    [sender_pk.x, sender_pk.y, recipient_pk.x, recipient_pk.y,
     42, encoding_id, mac_tag, ct[0], ct[1], ..., ct[8]],
)
```

The exact decimal is pinned in the circuit's integration
fixture (`crates/prover/tests/envelope_open_at_0.rs` once that
lands).

### Public-input vector

```text
public_inputs = [signal, 1]
```

### Negative cases the spec pins

- **Tampered ciphertext (signal mismatch).** A prover who
  changes one ciphertext element in the witness produces a
  different in-circuit signal than the verifier's public
  signal. Constraint 5 unsatisfies; proof rejects.
- **Tampered MAC tag (signal mismatch + MAC check).** Same
  story — the signal includes `mac_tag`, so any tampering
  there fails Constraint 5. Even if the prover doctored the
  public signal to match, the MAC verify (Constraint 3) would
  fail because the tampered mac_tag wouldn't validate against
  the real `key_mac`.
- **Wrong `claimed_value`.** A prover whose actual
  `plaintext[0]` doesn't equal `claimed_value` unsatisfies
  Constraint 4.
- **Wrong `recipient_sk`.** Without the recipient's secret
  key, the prover can't produce a `shared` that yields a
  matching `key_mac`; the MAC verify fails (Constraint 3).

## Why proof bytes are NOT pinned

Same reasoning as
[`circuit-pedersen-opens-to.md`](./circuit-pedersen-opens-to.md):
Groth16 proofs depend on setup randomness, prove randomness,
and arkworks patch-version internals. What's pinned is the
deterministic substrate (public-input values, native
envelope fields, signal hash, satisfaction relation).

## Setup artifacts

A conformant deployment ships, per `(N, position)` variant:

- **`PK`** for `envelope_open_at_0` (this variant, N=9, pos=0).
- **`VK`** for the same variant. Deployed to the on-chain
  Move verifier alongside the on-chain envelope-decoding
  glue that reconstructs the signal.

Production trusted setup is a future spec.

## Validity contracts

A conformant prover implementation MUST:

- **Allocate public inputs in the order pinned in
  § Verifier interface**: `[signal, claimed_value]`.
- **Use the exact signal-hash domain tag**:
  `domain_tag("envelope-open-signal")`.
- **Use the exact role tags** from
  [`babyjub-kdf.md`](../babyjub-kdf.md):
  `envelope-cipher-key` and `envelope-mac-key`.
- **Pin position at 0** for this variant. A different
  position is a different circuit.

A conformant verifier implementation MUST:

- **Reject proofs whose public-input count is not exactly 2.**
- **Compute `signal` from the same envelope fields the
  circuit hashes**, in the same order: sender_pk, recipient_pk,
  envelope_id, encoding_id, mac_tag, ciphertext. Drift in field
  order or inclusion is a soundness break.

## References

- [`protocol-envelope.md`](../protocol-envelope.md) — the
  envelope this circuit operates on.
- [`zk/stack.md`](./stack.md) — proving stack pins, public-
  input cap discipline, signal-hash compression pattern.
- [`zk/circuit-pedersen-opens-to.md`](./circuit-pedersen-opens-to.md) —
  the first circuit; same brick discipline, same docstring
  conventions.
- [`babyjub-ecdh.md`](../babyjub-ecdh.md),
  [`babyjub-kdf.md`](../babyjub-kdf.md),
  [`babyjub-cipher.md`](../babyjub-cipher.md),
  [`babyjub-mac.md`](../babyjub-mac.md) — primitive specs the
  envelope construction chains through.
- `crates/circuits/src/envelope_open_at_0.rs` — the
  `ConstraintSynthesizer` impl.
- `crates/prover/tests/envelope_open_at_0.rs` — the end-to-end
  integration test against the fixture above (planned).
