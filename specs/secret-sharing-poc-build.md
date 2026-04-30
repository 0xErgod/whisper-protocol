# Secret Sharing PoC Build Spec

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

Assumptions:

- We can access local Ed25519 private keys for Alice, Bob, and Charlie.
- All demo accounts use Ed25519.
- X25519 encryption keys are derived from Ed25519 key material.
- The app runs against a local Sui network.
- The indexer can be simple in-memory client state or a small local service.
- Recipient hints are public for the first PoC.
- Ciphertexts are small enough to store directly on-chain.

Out of scope:

- Wallet plugin integration.
- Production key custody.
- Metadata hiding.
- ZK proofs.
- Walrus storage.
- Group key management.

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

### Key Registration Event

```move
public struct EncryptionKeyRegistered has copy, drop {
    game_id: ID,
    player: address,
    signing_scheme: vector<u8>,
    signing_pubkey: vector<u8>,
    encryption_scheme: vector<u8>,
    encryption_pubkey: vector<u8>,
    key_version: u64,
    created_at_ms: u64,
}
```

For the PoC:

```text
signing_scheme = "ed25519"
encryption_scheme = "x25519-from-ed25519"
key_version = 1
```

### Encrypted Envelope Object

```move
public struct EncryptedEnvelope has key, store {
    id: UID,
    game_id: ID,
    sender: address,
    recipient_hint: address,
    schema: vector<u8>,
    key_version_hint: u64,
    eph_pubkey: vector<u8>,
    wrapped_key: vector<u8>,
    nonce: vector<u8>,
    ciphertext: vector<u8>,
    created_at_ms: u64,
}
```

For the first PoC, use a single recipient per envelope.

Multi-recipient sharing can come after the basic demo works.

### Envelope Event

```move
public struct EnvelopePosted has copy, drop {
    envelope_id: ID,
    game_id: ID,
    sender: address,
    recipient_hint: address,
    schema: vector<u8>,
    key_version_hint: u64,
    created_at_ms: u64,
}
```

### Public Note Object

Optional, but useful for the global feed.

```move
public struct PublicNote has key, store {
    id: UID,
    game_id: ID,
    sender: address,
    text: vector<u8>,
    created_at_ms: u64,
}
```

### Contract Functions

Minimum functions:

```move
public entry fun register_encryption_key(
    game_id: ID,
    signing_scheme: vector<u8>,
    signing_pubkey: vector<u8>,
    encryption_scheme: vector<u8>,
    encryption_pubkey: vector<u8>,
    key_version: u64,
    clock: &Clock,
    ctx: &mut TxContext,
)
```

```move
public entry fun post_envelope(
    game_id: ID,
    recipient_hint: address,
    schema: vector<u8>,
    key_version_hint: u64,
    eph_pubkey: vector<u8>,
    wrapped_key: vector<u8>,
    nonce: vector<u8>,
    ciphertext: vector<u8>,
    clock: &Clock,
    ctx: &mut TxContext,
)
```

```move
public entry fun post_public_note(
    game_id: ID,
    text: vector<u8>,
    clock: &Clock,
    ctx: &mut TxContext,
)
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
  - metadata shown: sender, recipient hint, schema, timestamp
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

