# Issue: Make Protocol Versioning Backward-Compatible for Old Envelopes

## Summary

The current protocol/version check is deployment-wide: the SDK reads the on-chain `protocol_version()` and assumes that value is the only valid format for the package.

That is safe for write-compatibility, but it is not sufficient for long-term read-compatibility. Once the protocol evolves, clients still need to:

- read old envelopes
- decrypt old envelopes
- understand old event payloads
- avoid depending on mutable current registry state to interpret historical messages

We should define a versioning model that lets a newer client keep reading historical data while still rejecting writes it does not understand.

## Problem

Today, protocol compatibility is effectively checked at the package level rather than at the envelope/event level.

That creates a few risks:

- a future protocol bump can cause a newer deployment to reject or mishandle old data
- old envelopes may become ambiguous if registry entries mutate across key rotations or scheme changes
- adding new encryption schemes is harder because the rules are not fully self-described per message
- clients may be forced into "all-or-nothing" compatibility instead of "read old, write new"

## Goal

Support the following behavior:

- a current client can read and decrypt historical envelopes from older protocol versions
- a client can determine how to decode an envelope from the envelope/event payload itself
- write-compatibility remains strict
- introducing a new encryption scheme or envelope layout does not break historical reads

## Non-Goals

- preserving binary compatibility for every helper API forever
- supporting arbitrary unknown future protocol versions without explicit decoder support
- keeping mutable registry state as the source of truth for historical decryption

## Main Design Constraint

Old envelopes must remain interpretable without consulting the recipient's current registry entry.

If a user rotates from scheme A to scheme B, previously posted envelopes must still say enough to be decoded and decrypted correctly.

## Options

### Option 1: Global protocol version gate, version-specific deployments

Keep the current model:

- `protocol_version()` is the main compatibility switch
- each deployment/package only serves one wire format
- clients upgrade in lockstep with deployments

Pros:

- simplest implementation
- easiest to reason about operationally
- strong safety for writes

Cons:

- poor historical compatibility story
- old envelopes are hard to read after upgrades unless clients keep explicit legacy branches outside the main model
- encourages package-level coupling instead of data-level self-description

Assessment:

This is acceptable for a POC, but not a good long-term model.

### Option 2: Version each envelope/event payload explicitly

Add a durable format/version field to the envelope and event payloads, for example:

- `format_version`
- `encryption_scheme`
- `schema`
- `key_version`

SDK behavior:

- choose a decoder by `format_version`
- choose a decrypter by `encryption_scheme`
- keep old decoders around indefinitely

Pros:

- best read-compatibility story
- natural fit for adding new envelope layouts or encryption suites
- lets the SDK support multiple historical formats in one binary

Cons:

- more code in the SDK
- requires discipline around decoder maintenance
- event and object formats must stay self-describing

Assessment:

This is the strongest general-purpose approach and likely the best default.

### Option 3: Immutable key-registration objects instead of mutable registry-only state

Keep the live registry for discovery, but make each key registration an immutable object with:

- public key
- encryption scheme
- key version
- timestamp

Each envelope would reference one of:

- the immutable key object id, or
- the exact public key bytes used

Pros:

- historical messages no longer depend on "current registry state"
- key rotations and scheme changes are safer
- improves auditability

Cons:

- more on-chain state
- more complexity in contract design
- envelopes may become slightly larger if they embed more metadata

Assessment:

Strong complement to Option 2. Particularly useful if key semantics may evolve across versions.

### Option 4: Treat `protocol_version()` as write-compat only

Keep `protocol_version()` for deployment capability checks, but stop using it as a universal startup gate for all reads.

Model:

- `protocol_version()` answers "what can this deployment write?"
- envelope metadata answers "how should this message be read?"
- SDK has separate paths for:
  - `assertCanWrite(version)`
  - `decodeEnvelope(version, payload)`

Pros:

- preserves a useful deployment guardrail
- avoids blocking historical reads unnecessarily
- works well with Option 2

Cons:

- adds conceptual complexity
- needs a clearer distinction between read compatibility and write compatibility in the SDK API

Assessment:

Recommended in combination with Option 2.

### Option 5: Legacy compatibility via explicit migration/indexing layer

Instead of making the on-chain envelope fully self-describing, rely on:

- historical events
- indexer state
- migration tooling

Pros:

- smaller on-chain object changes
- can sometimes avoid immediate protocol changes

Cons:

- weaker trust model
- historical reads depend on off-chain reconstruction
- more operational complexity
- worse portability for SDK consumers

Assessment:

Useful only as a temporary bridge, not as the primary design.

## Recommendation

Recommended direction:

1. Use per-envelope/per-event versioned decoding.
2. Keep `protocol_version()` as a deployment/write capability marker.
3. Ensure envelopes carry enough metadata to choose the correct decoder and decrypter.
4. Stop relying on mutable current registry state to interpret historical envelopes.
5. Consider immutable key-registration objects or stable key references if scheme/key semantics may evolve.

## Concrete Next Steps

### Minimal next step

Add versioned read/write scaffolding in the SDK:

- split read compatibility from write compatibility
- introduce decoder dispatch by envelope format version
- introduce suite dispatch by `encryption_scheme`

### Stronger next step

Update the contract so each envelope carries:

- `format_version`
- `encryption_scheme`
- possibly a stable key reference

### Follow-up

Define SDK interfaces along these lines:

```ts
type EnvelopeDecoder = {
  version: number;
  decode(fields: unknown): DecodedEnvelope;
};

type SuiteHandler = {
  id: string;
  encrypt(input: EncryptInput): EncryptedPayload;
  decrypt(input: DecryptInput): Uint8Array | null;
};
```

## Open Questions

- Is backward compatibility needed only for reading old envelopes, or also for posting new messages to older deployments?
- Should envelope compatibility be guaranteed forever, or only for a bounded set of historical versions?
- Do we want immutable key-registration objects now, or only once multiple encryption schemes are introduced?
- Is object size/gas overhead acceptable for storing additional self-describing metadata per envelope?
