# Secret Sharing PoC Build Spec

> **Status — as-built, with drift notes.** This document was the original
> build plan and parts of it predate the implementation. The Move event
> shapes, function signatures, and the `KeyRegistry` shared object below
> have been updated to match the code in
> [contracts/sources/secret_sharing.move](../contracts/sources/secret_sharing.move).
> The "Ed25519 demo seeds in `.env`" assumption is the as-built path; the
> production-shaped successor is in
> [wallet-signature-derived-keys.md](./wallet-signature-derived-keys.md).
> The product name has been rebranded to **Whisper Protocol** — the
> on-chain Move module is still `secret_sharing` for backward
> compatibility (see README naming note).

## Goal

Build a local proof of concept for wallet-derived private secret sharing on Sui.

The PoC demonstrates three characters, Alice, Bob, and Charlie, publishing encryption keys and sending encrypted structured secrets to each other through public on-chain envelopes.

The web app shows a global feed. Everyone can see that messages exist, but only the intended recipient can decrypt and read each private message.

## Demo Concept

The app behaves like a global chat/intel board.

```text
Alice -> Bob: encrypted secret
Bob -> Charlie: encrypted secret
Charlie -> Alice: encrypted secret
Alice -> everyone: public note
```

When viewing as Alice:

```text
Alice can read:
  - messages sent to Alice
  - messages Alice sent
  - public notes

Alice cannot read:
  - Bob -> Charlie private messages
```

Changing perspective to Bob or Charlie updates which encrypted feed items are readable.

## PoC Assumptions

This PoC optimizes for protocol exploration, not production wallet security.

As-built assumptions:

- Local Ed25519 private keys for Alice, Bob, and Charlie are loaded from
  `.env` and used directly by the client.
- All demo accounts use Ed25519.
- X25519 encryption keys are derived deterministically from the Ed25519
  seed via SHA-512 + Curve25519 clamping (mirrors
  `ed25519-dalek::SigningKey::to_curve25519_secret`).
- The app runs against a local Sui network at `127.0.0.1:9000`.
- Indexing is direct event polling from the web client (no separate
  indexer service was built).
- Recipients are stored explicitly on the envelope object (no hint /
  trial-decrypt layer).
- Ciphertexts are small enough to store directly on-chain (4 KiB cap
  enforced by `MAX_CIPHERTEXT_BYTES`).

The "client has the Ed25519 seed" assumption is the demo-mode shortcut.
The production-shaped successor lives in
[wallet-signature-derived-keys.md](./wallet-signature-derived-keys.md):
the encryption keypair is derived from a wallet-produced signature over
a domain-separated canonical message, so the dapp never sees private key
material. The on-chain shapes in this document are unchanged by that
move.

Out of scope:

- Wallet plugin integration (covered as a future phase in
  [wallet-bound-private-messaging.md](./wallet-bound-private-messaging.md)).
- Production key custody.
- Metadata hiding.
- ZK proofs (see
  [provable-shared-secrets-extensions.md](./provable-shared-secrets-extensions.md)).
- Walrus storage.
- Group / multi-recipient envelopes.
- Forward secrecy (no ratchet layer).

## Required Parts

```text
contracts/
  Move package for key registration and encrypted envelopes.

web/
  Local demo UI for Alice, Bob, and Charlie.

crypto/
  TypeScript helpers for Ed25519-to-X25519 conversion, encryption, and decryption.

indexing/
  Lightweight event reader or client-side cache for key registrations and envelopes.

local-sui/
  Scripts or commands for running local Sui, publishing contracts, and funding demo accounts.
```

The exact folder names can follow the existing repo structure once implementation starts.

## Local Sui Setup

Use the installed Sui toolkit to run a local network.

The local workflow should support:

```text
1. Start local Sui network.
2. Create or load Alice, Bob, and Charlie accounts.
3. Fund all three accounts.
4. Publish the Move package.
5. Store the package ID in web app config.
6. Run the web app against the local fullnode RPC.
```

The web app should target the local RPC endpoint by default.

Example config shape:

```ts
export const localConfig = {
  rpcUrl: "http://127.0.0.1:9000",
  packageId: "0x...",
  moduleName: "secret_sharing",
};
```

## Move Contract

The Move package should be intentionally simple.

Responsibilities:

- Emit key registration events.
- Store encrypted envelope objects.
- Emit envelope posted events.
- Optionally support public feed notes.

The contract does not decrypt, verify ciphertext, or validate plaintext.

### Shared `KeyRegistry` Object

The contract creates a single shared `KeyRegistry` object at publish time.
Every `register_encryption_key` and `post_envelope` call takes it as input,
so all clients agree on a single source of truth for current keys and
versions.

```move
public struct KeyRegistry has key {
    id: UID,
    entries: Table<address, KeyEntry>,
}

public struct KeyEntry has store {
    encryption_scheme: vector<u8>,
    encryption_pubkey: vector<u8>,
    key_version: u64,
    rotated_at_ms: u64,
}
```

Re-registering an account overwrites the entry **and** increments
`key_version`. Old envelopes encrypted to a previous version remain on
chain but become undecryptable by clients that no longer hold the matching
private key (deletion is recipient-only via `delete_envelope`).

### Key Registration Event

```move
public struct EncryptionKeyRegistered has copy, drop {
    account: address,
    encryption_scheme: vector<u8>,
    encryption_pubkey: vector<u8>,
    key_version: u64,
    rotated_at_ms: u64,
}
```

For the demo PoC:

```text
encryption_scheme = "x25519-from-ed25519"
key_version       = 1 on first registration, +1 each subsequent call
```

The wallet-signature successor (see
[wallet-signature-derived-keys.md](./wallet-signature-derived-keys.md))
keeps the same event shape; only the `encryption_scheme` string changes
(`"x25519-derived-from-wallet-sig-v1"` is reserved for the future path).

### Encrypted Envelope Object

```move
public struct EncryptedEnvelope has key, store {
    id: UID,
    sender: address,
    recipient: address,
    context: vector<u8>,
    schema: vector<u8>,
    key_version: u64,
    eph_pubkey: vector<u8>,
    nonce: vector<u8>,
    ciphertext: vector<u8>,
    created_at_ms: u64,
}
```

The PoC ships single-recipient direct ECIES (no `wrapped_key` field).
Multi-recipient envelopes via wrapped message keys remain a follow-up
(see Follow-Up Work). The `context: vector<u8>` field is an opaque
indexer tag the contract neither inspects nor validates.

The envelope object is `transfer::public_transfer`'d to the recipient,
making the recipient the on-chain owner. Recipient privacy via hidden
recipients + trial decryption is **not** implemented in the PoC.

### Envelope Event

```move
public struct EnvelopePosted has copy, drop {
    envelope_id: ID,
    sender: address,
    recipient: address,
    context: vector<u8>,
    schema: vector<u8>,
    key_version: u64,
    created_at_ms: u64,
}
```

### Public Note Object

Used for the global feed broadcast primitive. Not part of the encrypted
transport core.

```move
public struct PublicNote has key, store {
    id: UID,
    sender: address,
    context: vector<u8>,
    text: vector<u8>,
    created_at_ms: u64,
}
```

### Contract Functions

```move
entry fun register_encryption_key(
    registry: &mut KeyRegistry,
    encryption_scheme: vector<u8>,
    encryption_pubkey: vector<u8>,
    clock: &Clock,
    ctx: &mut TxContext,
)
```

Inserts on first call, overwrites and bumps `key_version` on subsequent
calls. The `account` is `tx_context::sender(ctx)` — there is no separate
"player" or `game_id` argument.

```move
entry fun post_envelope(
    registry: &KeyRegistry,
    recipient: address,
    context: vector<u8>,
    schema: vector<u8>,
    key_version: u64,
    eph_pubkey: vector<u8>,
    nonce: vector<u8>,
    ciphertext: vector<u8>,
    clock: &Clock,
    ctx: &mut TxContext,
)
```

The contract reads the recipient's current `KeyEntry` from the registry
and aborts with `E_STALE_KEY_VERSION` (abort code `3`) if the declared
`key_version` does not match. This means a sender racing a rotation gets
told to retry rather than silently posting an envelope encrypted to a
key the recipient no longer holds. **This invariant is load-bearing —
preserve it in any future revision.**

```move
entry fun delete_envelope(envelope: EncryptedEnvelope)
```

Owner-only via Sui object ownership. The recipient can clean up
envelopes encrypted to a key version they have rotated past.

```move
entry fun post_public_note(
    context: vector<u8>,
    text: vector<u8>,
    clock: &Clock,
    ctx: &mut TxContext,
)
```

### Public Accessors

`current_key`, `key_version_of`, `encryption_pubkey_of`, and
`encryption_scheme_of` let downstream Move modules read registry state
inside a PTB without going through events.

### Error Codes

```text
E_EMPTY_FIELD              = 0
E_TOO_LARGE                = 1
E_RECIPIENT_NOT_REGISTERED = 2
E_STALE_KEY_VERSION        = 3
```

## Crypto Module

The TypeScript crypto module should provide a narrow API.

```ts
type CharacterKeyMaterial = {
  name: "Alice" | "Bob" | "Charlie";
  address: string;
  ed25519PrivateKey: Uint8Array;
  ed25519PublicKey: Uint8Array;
  x25519PrivateKey: Uint8Array;
  x25519PublicKey: Uint8Array;
};
```

Required functions:

```ts
deriveX25519FromEd25519(ed25519PrivateKey: Uint8Array): {
  privateKey: Uint8Array;
  publicKey: Uint8Array;
}
```

```ts
encryptSecret(input: {
  plaintext: Uint8Array;
  senderPrivateKey: Uint8Array;
  recipientPublicKey: Uint8Array;
  aad: Uint8Array;
}): {
  ephPubkey: Uint8Array;
  wrappedKey: Uint8Array;
  nonce: Uint8Array;
  ciphertext: Uint8Array;
}
```

```ts
decryptSecret(input: {
  ephPubkey: Uint8Array;
  wrappedKey: Uint8Array;
  nonce: Uint8Array;
  ciphertext: Uint8Array;
  recipientPrivateKey: Uint8Array;
  aad: Uint8Array;
}): Uint8Array | null
```

For the first implementation, direct ECIES-style encryption is acceptable:

```text
shared = X25519(recipient_x25519_private, sender_ephemeral_public)
key = HKDF(shared, aad)
plaintext = AEAD_Decrypt(key, nonce, ciphertext, aad)
```

If wrapping a random message key adds too much complexity initially, encrypt the payload directly with the derived AEAD key. Add wrapped message keys later for multi-recipient messages.

## Plaintext Message Format

Use typed JSON or BCS. JSON is acceptable for the first UI demo.

Example secret:

```json
{
  "kind": "asset_location_v1",
  "assetId": "fortress-001",
  "message": "Fortress is hidden near the north ridge",
  "x": 42,
  "y": 9,
  "createdAtMs": 1710000000000
}
```

The decrypted UI should show the structured fields, not just raw text.

## Indexing Strategy

For the PoC, use one of two strategies.

### Option A: Client-Side Event Fetching

The web app queries Sui events directly:

```text
EncryptionKeyRegistered
EnvelopePosted
```

Then it fetches envelope objects by ID.

This keeps the PoC small.

### Option B: Local Indexer Service

A small Node process watches the local fullnode and maintains:

```ts
type KeyRegistry = Map<string, RegisteredEncryptionKey>;
type Feed = FeedItem[];
```

The web app calls the local indexer over HTTP.

This is closer to a production shape, but adds another moving part.

Recommendation: start with client-side event fetching. Add a local indexer only if direct event querying becomes awkward.

## Web App

The web app should be a single local demo UI.

### Required Views

```text
Top bar:
  - current perspective selector: Alice | Bob | Charlie
  - local network/package status

Registration panel:
  - show whether each character published their encryption key
  - button: Register key for selected character

Composer:
  - sender defaults to current perspective
  - recipient selector: Alice | Bob | Charlie
  - schema selector: asset_location_v1 | note_v1
  - structured fields for asset location
  - button: Send encrypted secret
  - button: Send public note

Global feed:
  - all envelope/public-note events in chronological order
  - readable messages rendered normally
  - unreadable messages rendered as encrypted/locked
  - metadata shown: sender, recipient, schema, key_version, timestamp
```

### Feed Behavior

Each feed item has one of three states:

```text
public:
  Everyone can read it.

decryptable:
  Current perspective can decrypt it.

locked:
  Current perspective cannot decrypt it.
```

Example display as Alice:

```text
[Public] Bob: Rally at dusk.
[Private to Alice] Charlie: Asset fortress-001 at (42, 9).
[Locked] Alice cannot decrypt Bob -> Charlie asset_location_v1.
```

Changing perspective should not mutate chain state. It should only change which local key is used to attempt decryption.

## Demo Characters

The PoC should provide three deterministic local characters:

```text
Alice
Bob
Charlie
```

Each needs:

- Sui address.
- Ed25519 private key.
- Ed25519 public key.
- Derived X25519 private key.
- Derived X25519 public key.
- Local Sui signer for PTBs.

The keys may be generated by a setup script and stored in local development config.

Do not commit real keys.

## Happy Path Demo Script

The intended demo flow:

```text
1. Start local Sui.
2. Publish Move package.
3. Open web app.
4. Select Alice.
5. Register Alice's encryption key.
6. Select Bob.
7. Register Bob's encryption key.
8. Select Charlie.
9. Register Charlie's encryption key.
10. Alice sends encrypted asset location to Bob.
11. Bob sends encrypted asset location to Charlie.
12. Charlie sends encrypted asset location to Alice.
13. Bob sends a public note.
14. Switch perspective between Alice, Bob, and Charlie.
15. Observe that each character can only read their own private messages plus public notes.
```

## PTB Usage

The first implementation can use one transaction per action.

Useful PTBs:

```text
register key
post encrypted envelope
post public note
```

Later, combine actions:

```text
register key + send first secret
update game state + post secret
send secret + post public decoy note
```

## Validation Rules

Client-side validation:

- Sender must have local Ed25519 key material.
- Recipient must have a registered encryption public key.
- Sender should not encrypt to missing or stale key registrations.
- Decryption must validate associated data.
- Decrypted payload must match expected schema.

Move-side validation:

- Use `tx_context::sender(ctx)` as the sender.
- Emit timestamps from `Clock`.
- Enforce maximum vector sizes for ciphertext and text.
- Optionally reject empty fields.

## Success Criteria

The PoC is successful when:

- Alice, Bob, and Charlie can each register an encryption key.
- The web app can discover published keys.
- Any character can send an encrypted secret to any registered character.
- The global feed shows all messages.
- Current perspective can decrypt only messages intended for them or sent by them.
- Other private messages remain unreadable in the UI.
- The whole demo runs against local Sui.

## Follow-Up Work

After the basic PoC:

- Support multi-recipient envelopes.
- Hide recipient hints and use trial decryption.
- Replace JSON plaintext with BCS.
- Add key revocation events.
- Add local indexer service.
- Store large ciphertexts in Walrus.
- Move encryption/decryption into a wallet plugin or companion extension.
- Add commitments and ZK proofs as a separate claims layer.

