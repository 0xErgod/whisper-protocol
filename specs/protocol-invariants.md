# Whisper Protocol Invariants

> **Status.** This document defines the properties that should remain true as
> Whisper evolves. It is not a point-in-time implementation description. It is
> a guardrail document for protocol design, contract upgrades, SDK changes, and
> future extensions such as group envelopes, commitments, and proofs.

## Purpose

Whisper will likely evolve across:

- multiple envelope formats
- multiple encryption suites
- multiple key derivation paths
- application-specific schemas
- future commitment and proof layers

That evolution is expected.

What should not drift are the protocol's core guarantees and interpretation
rules. This document names those invariants so that future changes can be
checked against them explicitly.

## Terminology

- **Wallet identity**: the Sui account address that acts as the public identity
  of the user.
- **Encryption identity**: the encryption key material bound to or derived from
  the wallet identity.
- **Envelope**: an on-chain object representing encrypted delivery metadata and
  ciphertext.
- **Suite**: the concrete cryptographic mechanism used for encryption and
  decryption, including KEM/key agreement, KDF, and AEAD choices.
- **Schema**: the application-level meaning of the decrypted plaintext.
- **Context**: application routing or namespacing metadata used before and after
  decryption.

## Invariants

### 1. Plaintext never touches the chain

The chain may store:

- recipient routing metadata
- sender identity
- ciphertext
- suite identifiers
- schema/context metadata
- timestamps, versions, and audit fields
- commitments and proofs

The chain must not store recoverable plaintext as part of normal encrypted
 transport.

Implication:

- encryption must happen client-side before submission
- decryption must happen client-side after retrieval

### 2. Wallet identity remains the root public identity

Whisper may evolve its derivation methods, signing flows, and suite support, but
 the public identity anchor remains the user's Sui wallet address.

Implication:

- no Whisper-specific account namespace should replace wallet identity at the
  base layer
- future features may add indirection or privacy layers, but those should build
  on top of the wallet-bound model rather than replace it silently

### 3. Encryption identity must remain bound to wallet control

An encryption key used by Whisper must be either:

- derived from wallet-controlled secret material, or
- explicitly registered by a wallet-authorized action

Implication:

- the security boundary of Whisper should not be weaker than wallet ownership
- clients must not accept arbitrary off-chain keys as authoritative for a wallet
  unless the wallet has explicitly authorized them

### 4. Historical envelopes must remain readable under supported legacy rules

Protocol upgrades must not make historical envelopes uninterpretable.

A current client may reject unknown future versions, but it should continue to
 decode old supported versions.

Implication:

- read compatibility and write compatibility are separate concerns
- envelope decoding must be versioned at the data level, not only at the
  package/deployment level
- a deployment-wide `protocol_version()` check is not sufficient on its own

### 5. Envelope interpretation must not depend on mutable current registry state

A historical envelope must remain unambiguous even after the recipient rotates
 keys or changes suites.

Implication:

- envelopes must carry enough metadata to identify how they were encrypted
- if registry semantics evolve, the envelope should include a stable key
  reference or equivalent historical anchor
- "current key" lookups are valid for sending new messages, not for
  interpreting old ones

### 6. Every envelope must be self-describing enough to choose the correct decoder

An envelope must provide enough information to answer:

- which envelope format version applies
- which encryption suite applies
- which schema applies
- which key version or key reference applies

Implication:

- decoders should dispatch by explicit metadata
- decrypters should dispatch by explicit suite identifier
- future additions should prefer additive metadata over implicit conventions

### 7. Suite agility must not weaken safety

Whisper should be able to support more than one encryption suite over time.

That does not mean "accept anything". Unknown or unsupported suites must fail
 closed.

Implication:

- the SDK must not silently decrypt or encrypt using fallback assumptions
- adding a new suite must be explicit in both registration and envelope
  handling
- suite identifiers are protocol inputs, not UI labels

### 8. Key rotation must be monotonic and auditable

Key rotation should move forward in a way that is publicly observable and
 unambiguous.

Implication:

- key versions must increase monotonically
- new sends should target the current registered version
- stale sends should be rejectable
- historical envelopes remain tied to the version they targeted

### 9. Confidentiality is required; anonymity is optional

The base Whisper layer guarantees confidentiality of payload contents for
 authorized recipients.

It does not guarantee:

- sender anonymity
- recipient anonymity
- hidden communication graphs
- traffic analysis resistance

Implication:

- future privacy-enhancing layers may be added, but base-layer messaging should
  not be described as providing stronger privacy than it actually does

### 10. On-chain observability of delivery must remain possible

One of Whisper's core properties is that the existence of an envelope is
 publicly observable on-chain even if its contents are not.

Implication:

- future optimizations should not remove the ability to observe that an envelope
  existed, who it was routed to, and which application namespace it belongs to,
  unless a separate higher-privacy mode is introduced intentionally

### 11. Schema and context remain application-level, not cryptographic truth

`schema` and `context` help applications route and decode messages. They are not
 sufficient proof that a decrypted payload is truthful, useful, or well-formed
 in the application sense.

Implication:

- applications must treat schema/context as typed metadata, not semantic proof
- stronger guarantees belong in commitments, signatures, or proofs layered above
  the envelope

### 12. Commitments must be stable under encryption randomness

If Whisper adds commitments, the commitment must bind to the underlying secret
 and relevant domain-separation metadata, not to the ciphertext alone.

Implication:

- the same plaintext may yield different ciphertexts under randomized
  encryption, so ciphertext is not a stable identifier for the secret
- commitments must be derived from stable bytes representing the committed value

### 13. Proof systems must be optional layers, not hidden base-layer dependencies

Whisper's encrypted transport must remain useful even without zero-knowledge
 proofs.

Implication:

- pairwise encrypted delivery should not depend on proving systems
- commitments and proofs should compose cleanly on top
- proof-specific cryptographic choices should not be allowed to degrade the base
  transport unless there is a clear, intentional tradeoff

### 14. Cryptographic domain separation must remain explicit

Different uses of signatures, KDF inputs, commitments, and proofs must stay
 separated by stable domain tags or equivalent mechanism.

Implication:

- canonical message derivation must remain byte-stable and namespaced
- commitment hashing must include domain/context separation
- proof inputs should be typed and namespaced

### 15. Unknown future versions must fail closed, not misdecode

If a client encounters an envelope version or suite it does not understand, it
 must refuse to interpret it as an older format.

Implication:

- "best effort" fallback decoding is dangerous
- decoder and suite registries should be exact-match dispatch systems

### 16. The protocol should prefer additive evolution over semantic mutation

When possible, new capabilities should be introduced by:

- new envelope format versions
- new suite identifiers
- new schema names
- new optional fields

rather than by silently changing the meaning of existing fields.

Implication:

- old semantics should remain stable once shipped
- existing identifiers should not drift in meaning over time

## Upgrade Checklist

Any proposed protocol change should be checked against this list:

1. Can historical envelopes still be decoded?
2. Does a reader need mutable current registry state to interpret old messages?
3. Is the suite/version selection explicit and fail-closed?
4. Does the change preserve plaintext-off-chain behavior?
5. Does the change preserve wallet-bound authority for encryption identity?
6. Does the change keep key rotation monotonic and auditable?
7. If commitments or proofs are involved, are domain separation and stable byte
   encoding explicit?
8. Does the change accidentally claim anonymity when it only preserves
   confidentiality?

## Near-Term Consequences for the Current Codebase

The current repo should move toward:

- versioned envelope decoders in the SDK
- suite dispatch in the SDK rather than one hardcoded transport path
- explicit separation between read compatibility and write compatibility
- stable historical references for key material if/when registry semantics grow
- keeping the base envelope layer independent from future proof machinery

## Summary

Whisper should evolve aggressively in features but conservatively in meaning.

The constants of the system are:

- plaintext stays off-chain
- wallet control remains the root authority
- envelopes remain historically interpretable
- unknown versions fail closed
- cryptographic choices are explicit, versioned, and domain-separated
- commitments and proofs remain layers on top of transport, not hidden
  replacements for it
