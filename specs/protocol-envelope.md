# Protocol Envelope (`protocol-envelope`)

This document specifies the protocol's **envelope** — the
composition of ECDH, KDF, stream cipher, and MAC into a single
authenticated unit suitable for on-chain transport. The envelope
is the protocol's headline data structure: when one party sends
another a private message routed via Sui, an envelope is what
lands on chain.

Cross-language compatibility contract between:

- The Rust `protocol` crate (this protocol's seal/open
  implementation).
- The Move on-chain module (the future Sui-side `Envelope`
  struct and its verifier glue).
- The TypeScript SDK (dApp-side seal/open via the WASM
  binding).

Built on [`babyjub-keypair.md`](./babyjub-keypair.md),
[`babyjub-ecdh.md`](./babyjub-ecdh.md),
[`babyjub-kdf.md`](./babyjub-kdf.md),
[`babyjub-cipher.md`](./babyjub-cipher.md), and
[`babyjub-mac.md`](./babyjub-mac.md).

> **NOTE(name):** scheme tag `protocol-envelope` and crate name
> `protocol` are working names. No product name is baked in.

**Any implementation that does not reproduce the exact
field-element values in [§ Worked Example](#worked-example) is
incompatible with this scheme and will not interoperate.**

## What this is

A typed bundle of fields, with a pinned construction rule, that
collectively constitute an authenticated message from a
known-identity sender to a known-identity recipient under a
per-envelope key.

```text
envelope = {
    sender_pk         : EdwardsAffine,   // public, on-curve, prime-subgroup
    recipient_pk      : EdwardsAffine,   // public, on-curve, prime-subgroup
    envelope_id       : Fq,              // per-envelope binding scalar
    ciphertext        : Vec<Fq>,         // length-preserving cipher output
    mac_tag           : Fq,              // one-field-element integrity tag
}
```

Plaintext, blinding scalars, and the sender's secret key are
**never** part of the envelope. Decryption requires the
recipient's secret key (or, equivalently, the sender's secret
key — ECDH is symmetric — but the protocol's roles distinguish
sender from recipient at the application layer).

## What this is FOR

The canonical use is **"send a private message from wallet A to
wallet B, routed via Sui."** Wallet A produces an `Envelope` and
publishes it on chain (as a Sui object or as event-payload
bytes). Wallet B reads the envelope, runs `open`, and recovers
the plaintext.

The on-chain side does not need the plaintext to verify routing,
authenticity, or — when the protocol's ZK layer lands —
properties of the plaintext. The protocol's
[§ Validity contracts](#validity-contracts) pin what the chain
can check natively, and what requires a circuit.

## What this is NOT

- **Not a forward-secrecy protocol.** Compromise of either
  party's long-term secret key compromises every envelope
  between them. A future "ratcheting envelope" variant would
  rotate per-envelope keypairs; that's a different scheme and
  would mint its own spec.
- **Not a group envelope.** The construction is two-party
  (sender, recipient). A group envelope variant (1-to-N, with
  per-recipient key wraps) is a separate scheme; see
  [`protocol-invariants.md § 5. Multi-recipient envelopes`](./protocol-invariants.md)
  for the placeholder.
- **Not anonymity-preserving for the sender.** `sender_pk` is
  in the clear. The protocol's threat model assumes the sender
  is willing to be publicly identified. Sender-anonymity is a
  composition with a ring signature or set-membership proof,
  not an envelope-level concern.
- **Not the storage layout on Sui.** The Move-side `Envelope`
  struct is a downstream consumer of this spec; its field
  ordering and BCS encoding are pinned in
  [§ On-chain mapping](#on-chain-mapping), but Move-specific
  packing (e.g. `vector<u8>` vs. `vector<Fq>`) is the
  on-chain spec's call.

## Construction

### Sealing (sender side)

Given sender's keypair `(sk_a, pk_a)`, recipient's public key
`pk_b`, an envelope id `envelope_id ∈ Fq`, and a plaintext
stream `plaintext: Vec<Fq>`:

```text
1. shared       = babyjub-ecdh(sk_a, pk_b)
2. key_enc      = babyjub-kdf(shared, [ENC_ROLE_TAG, envelope_id])
3. key_mac      = babyjub-kdf(shared, [MAC_ROLE_TAG, envelope_id])
4. ciphertext   = babyjub-cipher.encrypt(key_enc, plaintext)
5. mac_tag      = babyjub-mac.mac(key_mac, ciphertext)
6. envelope     = { sender_pk: pk_a, recipient_pk: pk_b, envelope_id,
                    ciphertext, mac_tag }
```

The role tags are pinned in
[`babyjub-kdf.md`](./babyjub-kdf.md):

```text
ENC_ROLE_TAG = domain_tag("envelope-cipher-key")
             = 1509687719585944131241352475068886393759608140501623646780323187386706626075

MAC_ROLE_TAG = domain_tag("envelope-mac-key")
             = 5516219051016623209397290384142210256012461986142239137807233927652814454837
```

### Opening (recipient side)

Given recipient's keypair `(sk_b, pk_b)` and an envelope
`{sender_pk, recipient_pk, envelope_id, ciphertext, mac_tag}`:

```text
1. Verify recipient_pk == pk_b. If not, reject (envelope is
   for a different recipient).
2. shared       = babyjub-ecdh(sk_b, sender_pk)
3. key_mac      = babyjub-kdf(shared, [MAC_ROLE_TAG, envelope_id])
4. Verify babyjub-mac.verify(key_mac, ciphertext, mac_tag). If
   not, reject (envelope is corrupt or forged).
5. key_enc      = babyjub-kdf(shared, [ENC_ROLE_TAG, envelope_id])
6. plaintext    = babyjub-cipher.decrypt(key_enc, ciphertext)
```

**The MAC check happens BEFORE decryption.** This is the
encrypt-then-MAC discipline:
[`babyjub-mac.md`](./babyjub-mac.md) pins it; the envelope
inherits it. A recipient that decrypts before checking the MAC
has voluntarily exposed itself to chosen-ciphertext attacks.

### Composition order: encrypt-then-MAC

The order matters and is non-negotiable:

- **Cipher key and MAC key MUST be domain-separated via
  distinct role tags** in the KDF context. Same shared point,
  different roles, different keys. The spec pins
  `envelope-cipher-key` and `envelope-mac-key`; a third role
  (e.g. for a key-confirmation hash) would mint its own tag.
- **`envelope_id` MUST be unique per (sender, recipient) pair.**
  Reusing an id with the same shared point yields the same
  cipher key, which leaks plaintext-difference information.
  Recommended id sources: a Sui object id (already globally
  unique), a monotonic counter persisted by the sender, or
  fresh randomness from the sender's RNG.
- **The MAC covers the ciphertext, NOT the plaintext.** Pairing
  the MAC over the *ciphertext* (not the *plaintext*) is what
  makes encrypt-then-MAC sound; reversing it (MAC-then-encrypt)
  has known foot-guns and is forbidden.

## Properties

- **Confidentiality** — without `shared`, the ciphertext reveals
  nothing about the plaintext (the cipher's hiding property,
  inherited from `babyjub-cipher.md`).
- **Integrity** — the MAC binds the ciphertext under a key only
  the sender and recipient can derive. Tampering changes the
  tag; the recipient rejects (inherited from `babyjub-mac.md`).
- **Per-envelope keying** — distinct `envelope_id`s yield
  distinct cipher and MAC keys, even under the same
  `(sender_pk, recipient_pk)` pair. Compromise of one
  envelope's keys does not compromise another's (inherited
  from `babyjub-kdf.md`).
- **Replay resistance per-envelope-id** — a published envelope
  tagged with `id = X` cannot be re-submitted as `id = X+1`
  without re-signing under the new key (which the attacker
  doesn't hold). The chain MAY additionally enforce
  monotonicity at the consumer layer; the envelope itself does
  not encode an ordering.

## What this construction does NOT defend against

- **Sender-impersonation via stolen `sk`.** If an attacker
  obtains `sk_a`, they can produce envelopes that any recipient
  accepts as "from A." There is no per-envelope sender proof
  beyond what ECDH+KDF implicitly provides (which is "this
  envelope was sealed by someone who held `sk_a` or `sk_b`,"
  i.e. either party, not specifically `sk_a`). A
  sender-binding variant adds a Schnorr signature over the
  envelope; that's a separate scheme.
- **Side-channel leakage of `envelope_id`.** The id is public
  by construction. If the application binds sensitive data
  into the id (e.g. a counter that reveals account activity),
  that's an application-layer leak, not an envelope-layer one.
- **Quantum adversaries.** Baby Jubjub is not
  post-quantum-secure. A protocol-version migration to a PQC
  suite is in scope for
  [`protocol-invariants.md § Cipher suite versioning`](./protocol-invariants.md).

## On-chain mapping

The Move-side `Envelope` struct on Sui implements this spec.
Its concrete field layout is the Move package's call, but the
following constraints hold:

- **Field set MUST match the spec.** No fewer fields, no
  extra fields whose validity isn't derivable from the spec's
  inputs.
- **Field ordering MUST be pinned in the Move package's spec
  doc** (when it lands). The BCS-encoded byte layout is a
  consumer of that ordering; downstream verifiers (off-chain,
  in-circuit) read the same bytes.
- **Field types MUST round-trip through the Rust↔Move
  serialization layer without precision loss.** `Fq` and `Fr`
  values cross as 32-byte little-endian arrays (matching
  arkworks' canonical encoding). `EdwardsAffine` crosses as
  a pair of 32-byte little-endian arrays for the affine
  coordinates.

The Move spec is a downstream doc; this spec does not pre-empt
its decisions about packing or representation. What this spec
DOES pre-empt: the **semantic contract** (what fields exist,
what they mean, what the construction rule is) must match
byte-for-byte across implementations.

## Rust API contract

The Rust `protocol` crate exposes the envelope as a thin
data-transfer object:

```rust
pub struct Envelope {
    pub sender_pk:    EdwardsAffine,
    pub recipient_pk: EdwardsAffine,
    pub envelope_id:  Fq,
    pub ciphertext:   Vec<Fq>,
    pub mac_tag:      Fq,
}

pub fn seal(
    sender_sk:    &SecretKey,
    sender_pk:    &PublicKey,
    recipient_pk: &PublicKey,
    envelope_id:  Fq,
    plaintext:    &[Fq],
) -> Envelope;

pub fn open(
    recipient_sk: &SecretKey,
    recipient_pk: &PublicKey,
    envelope:     &Envelope,
) -> Result<Vec<Fq>, OpenError>;
```

`OpenError` distinguishes:

- `WrongRecipient` — the envelope's `recipient_pk` does not
  match `pk_b`.
- `MacFailure` — the MAC tag does not verify; envelope is
  corrupt or forged.

Decryption never produces "garbage plaintext" on the public
API; an envelope either opens to its actual plaintext or
errors. (The underlying `babyjub-cipher::decrypt` is total —
wrong key produces wrong output — but `open` is gated by the
MAC check, so the only way to get a value out is to pass the
MAC.)

## Validity contracts

A conformant implementation MUST:

- **Reject envelopes whose `sender_pk` or `recipient_pk` is
  not on the Baby Jubjub curve and in the prime-order
  subgroup.** This is the wire decoder's job
  (`crypto::babyjub::point_from_strings` already validates);
  the envelope MUST be parsed through that decoder before any
  cryptographic operation runs.
- **Reject envelopes where the MAC fails** before attempting
  decryption.
- **Use the exact role tags pinned in
  [`babyjub-kdf.md`](./babyjub-kdf.md)**:
  `domain_tag("envelope-cipher-key")` and
  `domain_tag("envelope-mac-key")`. No other role tag is
  permitted for envelope construction; mixing role tags
  with other consumers would break domain separation.
- **Treat `envelope_id` as a non-private value.** The id is
  part of the public envelope; do not derive it from secret
  material.
- **Match every pinned vector byte-for-byte.**

## Worked Example

Reuses the Alice/Bob fixture from the underlying primitive
specs. A conformant implementation reproduces every value below
exactly.

### Inputs

```text
Alice seed   = 0x01 followed by 63 × 0x00
Bob seed     = 0x02 followed by 63 × 0x00
envelope_id  = 42
plaintext    = [1, 2, 3, 4]
```

Derived (already pinned in
[`babyjub-keypair.md`](./babyjub-keypair.md) and
[`babyjub-ecdh.md`](./babyjub-ecdh.md) and
[`babyjub-kdf.md`](./babyjub-kdf.md)):

```text
shared.x     = 4441722070262887487676852990759346353102280890264110527729805261601919952792
shared.y     = 18505774984025635106527431283405915983682689754171973024874112571296549171475

key_enc      = babyjub-kdf(shared, [ENC_ROLE_TAG, 42])
             = 9799522521534548758133939899702695884003167902663631833387651174524282263857
key_mac      = babyjub-kdf(shared, [MAC_ROLE_TAG, 42])
             = 5302105009719633730025155498822445041452574923386899996802294480945238328306
```

### Envelope fields

`sender_pk` and `recipient_pk` are the Alice/Bob public keys
derived from their seeds (see
[`babyjub-keypair.md`](./babyjub-keypair.md)).

`ciphertext` matches
[`babyjub-cipher.md`](./babyjub-cipher.md) Vector 3 exactly —
the cipher-role-key encryption of `[1, 2, 3, 4]` for envelope
id 42:

```text
ciphertext = [
  10787321779190226554676337514347691875659477298610453494316095697639731105525,
  11005131623232030623906867189653141067415173065234117331769608574160093139922,
  11791314040563090199526129580738560103220176213914809365331933459954108858858,
  7865039964291077852173468667319105421171640084683400461629880408575490986497,
]
```

`mac_tag` matches [`babyjub-mac.md`](./babyjub-mac.md) Vector 5
exactly — the mac-role-key tag over the canonical ciphertext
above:

```text
mac_tag = 16162720997808794646235033165738484245710842752524771795771394985271256269398
```

### Round trip

Bob runs `open(sk_b, &pk_b, &envelope)`:

1. Recipient check: `envelope.recipient_pk == pk_b`. ✓
2. `shared = ecdh(sk_b, sender_pk)` → same `(shared.x,
   shared.y)` above.
3. `key_mac = kdf(shared, [MAC_ROLE_TAG, 42])` → matches the
   pinned `key_mac` above.
4. `mac.verify(key_mac, ciphertext, mac_tag)` → `true`. ✓
5. `key_enc = kdf(shared, [ENC_ROLE_TAG, 42])` → matches the
   pinned `key_enc` above.
6. `plaintext = cipher.decrypt(key_enc, ciphertext)` →
   `[1, 2, 3, 4]`. ✓

The recovered plaintext equals the original by the cipher's
round-trip contract (`babyjub-cipher.md § Vector 3`).

### Negative cases the spec pins

- **Tampered ciphertext.** Flipping any single field of
  `ciphertext` produces a different MAC tag; the recipient
  rejects with `MacFailure`. No partial-plaintext leak.
- **Wrong recipient.** Substituting Eve's `pk_e` for
  `recipient_pk` in the envelope and passing it to Bob's
  `open`: Bob rejects with `WrongRecipient` before any
  cryptographic operation runs. (The envelope is still valid
  for the actual recipient if they happen to encounter it; the
  field is a routing hint, not a soundness gate.)
- **Wrong envelope_id.** Substituting `id = 43` for `id = 42`
  yields different `key_mac` and `key_enc`; the MAC verify
  fails, `open` returns `MacFailure`.

## References

- [`protocol-invariants.md`](./protocol-invariants.md) —
  protocol-level invariants this envelope must satisfy. In
  particular, "plaintext never touches the chain" is the
  load-bearing one.
- [`babyjub-keypair.md`](./babyjub-keypair.md) — sender/recipient
  keypair derivation.
- [`babyjub-ecdh.md`](./babyjub-ecdh.md) — shared-point
  derivation.
- [`babyjub-kdf.md`](./babyjub-kdf.md) — role-tag-keyed key
  derivation. Pins the canonical
  `envelope-cipher-key` and `envelope-mac-key` tags this
  envelope uses.
- [`babyjub-cipher.md`](./babyjub-cipher.md) — stream cipher.
- [`babyjub-mac.md`](./babyjub-mac.md) — keyed sponge MAC.
- [`zk/stack.md`](./zk/stack.md) — the proving stack circuits
  built on top of envelopes target.
- Sui's [`groth16`](https://docs.sui.io/references/framework/sui-framework/groth16)
  Move module — the on-chain verifier circuits proving
  envelope-level claims will target.
