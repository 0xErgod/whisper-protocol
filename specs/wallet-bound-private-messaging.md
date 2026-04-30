# Wallet-Bound Private Messaging Protocol

## Status

Draft specification for a proof of concept.

## Goal

Enable two or more Sui wallets to exchange private structured data over public Sui infrastructure without relying on centralized key servers or backend custody.

The main use case is private game intel, such as sharing asset locations between selected players or tribe members.

## Core Idea

The Sui wallet remains the public identity, transaction signer, and source key material for the proof of concept.

For the PoC, assume the client can access the user's Ed25519 private key. The client deterministically converts the Ed25519 key material into X25519 key material for encryption and decryption.

```text
Sui wallet key:
  - signs transactions
  - signs key registration transactions
  - proves ownership of a Sui address
  - derives the X25519 encryption keypair for the PoC

Encryption key:
  - X25519 keypair derived from Ed25519 key material
  - encrypts/decrypts private messages
  - not independently generated in the initial PoC
```

This removes the need for wallet plugins during the PoC.

Long term, this derivation/decryption should move into wallets, wallet plugins, or a local privacy module so the game client does not access private key material.

## System Components

### Move Module

The on-chain Move module emits public encryption key registration events and stores encrypted message envelopes.

It does not decrypt messages and does not validate message plaintext.

Responsibilities:

- Register derived encryption public keys for wallet addresses.
- Store encrypted envelopes.
- Optionally gate posting by game, tribe, or membership rules.
- Emit events for indexing.
- Support key versioning.

### Sui Wallet

The user's Sui wallet signs transactions.

Responsibilities:

- Provide access to Ed25519 private key material in the PoC environment.
- Sign PTBs that register encryption keys and post encrypted envelopes.

### PoC Client Crypto Module

The PoC client crypto module derives encryption keys and performs encryption/decryption.

Responsibilities:

- Convert the local Ed25519 private key into an X25519 private key.
- Convert the local Ed25519 public key into an X25519 public key.
- Publish the associated X25519 public key through the Move module.
- Encrypt payloads for one or more recipients.
- Decrypt envelopes intended for the local wallet.

### Game Client

The game client coordinates UX and PTB construction.

Responsibilities:

- Connect to the user's Sui wallet.
- Derive the local encryption keypair.
- Publish key registration events and envelopes on-chain.
- Fetch encrypted envelopes from Sui or an indexer.
- Decrypt candidate envelopes locally.

For the PoC, the game client may handle private key material. This is an explicit simplification and not the target production trust boundary.

### Indexer

An indexer watches key registration events and envelope events.

Responsibilities:

- Map Sui wallet addresses to latest encryption public keys.
- Map Sui wallet addresses to key versions.
- Surface envelopes by recipient hint, sender, game, tribe, or schema.
- Help clients avoid scanning the full chain.

The indexer is not trusted for confidentiality. Clients must verify key registrations and decrypt locally.

## Trust Model

Trusted:

- The user's wallet implementation.
- The user's local device.
- The PoC client crypto implementation.
- Standard cryptographic assumptions for X25519, HKDF, and AEAD.

Not trusted:

- Public Sui observers.
- Indexers.
- Other players.
- Any centralized key server.

No third-party service is required to derive, store, release, or recover encryption keys.

For the PoC, the game client is trusted with wallet private key access.

## Cryptographic Primitives

Recommended primitives:

```text
Signing key type: Ed25519
Encryption key derivation: Ed25519-to-X25519 conversion
Key agreement: X25519
Key derivation: HKDF-SHA256
Authenticated encryption: XChaCha20-Poly1305 or AES-256-GCM
Hashing: Blake2b-256 or SHA-256
Serialization: BCS for structured plaintexts
```

Every encrypted payload must use authenticated encryption with associated data.

## Identity Binding

Each player publishes the X25519 encryption public key associated with their Ed25519 wallet key.

The key registration is submitted by the wallet address itself, so the transaction signer authenticates the binding.

Registration payload:

```text
SUI_PRIVATE_MESSAGING_KEY_REGISTRATION_V1
game_id: <game object id or package id>
address: <sui address>
signing_scheme: Ed25519
signing_pubkey: <ed25519 pubkey bytes>
encryption_scheme: X25519
encryption_pubkey: <x25519 pubkey bytes>
key_version: <u64>
created_at_ms: <u64>
```

The Move module emits an event containing this data.

Anyone can verify that:

```text
1. The transaction sender is the claimed player address.
2. The Ed25519 public key corresponds to the claimed Sui address.
3. The X25519 public key is the deterministic conversion of the Ed25519 public key.
```

The indexer stores the latest key registration per `(game_id, player)`.

## On-Chain Data Model

### Encryption Key Binding

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

The latest key version should be used for new messages.

### Encrypted Envelope

```move
public struct EncryptedEnvelope has key, store {
    id: UID,
    game_id: ID,
    sender: address,
    recipient_hint: option::Option<address>,
    schema: vector<u8>,
    key_version_hint: u64,
    eph_pubkey: vector<u8>,
    wrapped_keys: vector<vector<u8>>,
    nonce: vector<u8>,
    ciphertext: vector<u8>,
    created_at_ms: u64,
}
```

`wrapped_keys` may contain one wrapped message key or many wrapped message keys.

If recipient privacy matters, recipient addresses should not be stored directly in the envelope.

For the initial PoC, `recipient_hint` should be included to simplify indexing and UI recovery.

The module should emit an event when an envelope is posted:

```move
public struct EnvelopePosted has copy, drop {
    envelope_id: ID,
    game_id: ID,
    sender: address,
    recipient_hint: option::Option<address>,
    schema: vector<u8>,
    key_version_hint: u64,
    created_at_ms: u64,
}
```

## Message Encryption

Use hybrid encryption.

For each message:

1. Generate a random message key `K_msg`.
2. Serialize the plaintext with BCS.
3. Encrypt the plaintext once with `K_msg`.
4. Wrap `K_msg` separately for each recipient using X25519.
5. Store one ciphertext and multiple wrapped keys.

```text
K_msg = random(32)
payload_ct = AEAD_Encrypt(K_msg, payload_nonce, bcs_plaintext, aad)
```

For each recipient, the sender fetches the recipient's registered X25519 public key from the indexer or chain.

Then:

```text
sender_eph_sk, sender_eph_pk = X25519.generate()
shared_i = X25519(sender_eph_sk, recipient_encryption_pubkey_i)
wrap_key_i = HKDF(shared_i, salt, info)
wrapped_key_i = AEAD_Encrypt(wrap_key_i, wrap_nonce_i, K_msg, aad)
```

The envelope stores:

```text
sender_eph_pk
wrapped_key_1
wrapped_key_2
...
payload_nonce
payload_ct
```

## Associated Data

Associated data binds ciphertexts to their context.

Recommended associated data:

```text
protocol = "sui-private-msg-v1"
game_id
sender
recipient_hint
schema
key_version_hint
envelope_context
```

This prevents ciphertexts from being replayed across games, schemas, or protocol versions.

## Plaintext Schemas

Plaintexts should be typed and versioned.

Example asset-location payload:

```text
AssetLocationV1 {
  asset_id: ID,
  world_id: ID,
  owner: address,
  x: u64,
  y: u64,
  epoch: u64,
  timestamp_ms: u64,
  nonce: vector<u8>,
}
```

The receiver should reject stale timestamps, old epochs, duplicate nonces, or unexpected owners.

## Sending Flow

Player E shares an asset location with Player A.

```text
1. Game/indexer fetches A's latest registered X25519 public key.
2. E's client encrypts AssetLocationV1 for A.
3. E's client builds an EncryptedEnvelope payload.
4. Game builds a PTB that calls the Move module to store the envelope.
5. E's Sui wallet signs and executes the PTB.
```

For multiple recipients, the same payload ciphertext is reused and only `wrapped_keys` grows.

## Receiving Flow

Player A reads private intel.

```text
1. Game fetches candidate envelopes from Sui or an indexer using A's recipient hint.
2. A's client converts A's Ed25519 private key to X25519 private key.
3. A's client attempts to unwrap one message key.
4. If successful, it decrypts the payload and returns plaintext.
5. Game validates schema, timestamp, epoch, nonce, and sender expectations.
```

If recipient addresses are hidden, A may need to trial-decrypt multiple wrapped keys.

## Pull Request Flow

Player A requests a location from Player E.

```text
1. A encrypts an AssetLocationRequestV1 to E.
2. A posts the request envelope on-chain.
3. E's client decrypts the request.
4. E decides whether to respond.
5. E posts an encrypted AssetLocationV1 response to A.
```

The response should include the request envelope ID or request nonce inside the encrypted plaintext.

## Push Sharing Flow

Player E pre-shares with a selected set of allies.

```text
1. E selects recipients A, B, C.
2. E encrypts one AssetLocationV1 payload.
3. E wraps the message key to A, B, and C.
4. E posts one envelope on-chain.
5. A, B, and C can decrypt; others cannot.
```

This avoids persistent tribe-wide shared keys.

## Key Rotation

A player may rotate their encryption key only by changing the source Ed25519 wallet key or by moving to a future dedicated encryption key design.

```text
1. Player uses a new Ed25519 wallet key or future dedicated encryption key.
2. Client derives or obtains the new X25519 public key.
3. Client publishes a new key registration with key_version + 1.
4. New messages use the latest key version.
```

Old messages require old keys unless they are re-encrypted.

The PoC should support a revocation event, but key rotation is limited when encryption keys are deterministically derived from wallet keys.

## Privacy Properties

Provides:

- Payload confidentiality.
- Sender-authenticated delivery through the Sui transaction signer.
- Recipient-only decryption.
- No third-party key custody.
- Selective multi-recipient sharing.

Does not automatically provide:

- Metadata privacy.
- Forward secrecy for old messages if local encryption keys are compromised.
- Protection against recipients leaking plaintext.
- Protection against malicious wallets or compromised devices.
- Isolation between transaction signing keys and encryption keys.

Metadata visible on-chain may include:

- Sender address.
- Posting time.
- Message size.
- Game or tribe object.
- Envelope frequency.

Recipient addresses can be hidden by omitting explicit recipient lists and using trial decryption.

## Registration Discovery Flow

Before sending a message, the sender needs the recipient's encryption public key.

```text
1. Sender asks indexer for latest key registration for recipient.
2. If found, sender verifies the registration data.
3. If not found, sender cannot encrypt to recipient yet.
4. Recipient must broadcast a registration transaction.
5. Indexer observes EncryptionKeyRegistered.
6. Sender retries encryption.
```

The client should expose a simple readiness check:

```text
can_receive_private_messages(address) -> bool
```

If false, the player must run registration.

## Proofs and Claims Layer

This protocol can be extended with commitments and zero-knowledge proofs.

Examples:

- Commit to an asset location without revealing it.
- Prove knowledge of a committed location.
- Prove a location is inside a region.
- Prove receipt of a valid encrypted report.

The messaging layer remains independent:

```text
encrypted envelopes = private transport
commitments/ZK proofs = public claims about private data
Move contracts = storage, routing, verification
```

## PoC Plan

### Phase 1: Ed25519-Derived Local PoC

Build a local client module that can access Ed25519 private key material and derive X25519 key material.

```ts
deriveEncryptionKeypair(ed25519SecretKey)
registerEncryptionKey(gameId)
encryptForRecipients({ recipients, plaintext, aad })
decryptEnvelope({ envelope, aad })
```

Use Move events and an indexer for public key discovery.

### Phase 2: Local Privacy Companion

Move key access and decryption into a browser extension or local module.

Example API:

```ts
window.suiPrivacy.getPublicKey({ gameId })
window.suiPrivacy.encrypt({ recipients, plaintext, aad })
window.suiPrivacy.decrypt({ envelope, aad })
```

### Phase 3: Wallet Standard Custom Feature

Expose the privacy API as a wallet-standard-compatible custom feature where possible.

Example feature names:

```text
sui-private:registerEncryptionKey
sui-private:getEncryptionPublicKey
sui-private:encrypt
sui-private:decrypt
sui-private:rotateEncryptionKey
```

### Phase 4: Native Wallet Integration

Move the privacy module into a full Sui wallet or partner wallet.

The end-state user experience should be:

```text
connect wallet
enable private game messaging
sign one key binding
send and receive private intel
```

## Open Questions

- Which Sui wallets can support custom wallet-standard features today?
- Should encrypted envelopes be owned objects, shared objects, or events plus off-chain indexing?
- Should recipient addresses be omitted after the first PoC?
- Should key registration be an owned object, event-only, or both?
- Should large ciphertexts be stored directly on Sui or in Walrus with only references on-chain?
- Which Ed25519-to-X25519 conversion library should be standardized for the TypeScript PoC?
