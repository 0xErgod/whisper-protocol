# Provable Shared Secrets Extensions

## Goal

Extend the private secret sharing protocol with ways to make public, verifiable claims about secrets without immediately revealing the secrets.

This spec is intentionally separate from the initial secret-sharing PoC. The base PoC moves encrypted secrets between players. This extension layer lets those secrets become game-relevant commitments, claims, receipts, and later zero-knowledge predicates.

## Assumptions

Secrets may have arbitrary form, but are usually regular human-readable text rather than binary data.

Examples:

```text
asset_location:fortress-001:x=42:y=9
raid_plan:north-gate:at-dusk
alliance_oath:alice:bob:epoch=7
scout_report:region-12:enemy_seen=true
```

The protocol should not assume that all secrets are numeric, fixed-size, BCS-encoded, or machine-structured.

For commitments and later proofs, text secrets should be converted to a stable byte representation before hashing or proving.

## Core Idea

Private messages move secrets.

Commitments make hidden secrets publicly anchored.

Proofs make claims about hidden secrets publicly checkable.

```text
encrypted envelope:
  "I privately sent this secret to Bob."

commitment:
  "I publicly locked in this secret."

opening:
  "Here is the secret; verify it matches the commitment."

proof:
  "I know a secret with property X, without revealing it."
```

## Layering

The extension stack should be layered like this:

```text
Layer 1: Secret sharing
  Pairwise encryption and on-chain envelopes.

Layer 2: Commitments
  Hash commitments to text secrets encoded as stable bytes.

Layer 3: Openings
  Revealing secrets and salts when gameplay requires it.

Layer 4: Receipts
  Public evidence that a secret was shared or received.

Layer 5: ZK predicates
  Later proofs about secret properties without revealing the secret.
```

The initial implementation should stop at commitments, openings, and simple receipts.

## Text Encoding

Because secrets are usually regular text, the first requirement is stable encoding.

Recommended text envelope:

```text
SUI_SECRET_V1
game_id=<id>
schema=<schema>
author=<address>
created_at_ms=<u64>
body=<text body>
```

Rules:

- Use UTF-8 bytes.
- Normalize line endings to `\n`.
- Preserve user text by default.
- Include a schema string.
- Include game ID and author address.
- Include a timestamp or logical epoch.
- If binary data is ever needed, encode it as hex or base64 instead of mixing raw bytes into the text body.

Example encoded secret:

```text
SUI_SECRET_V1
game_id=0x123
schema=asset_location_v1
author=0xabc
created_at_ms=1710000000000
body=Fortress is hidden near the north ridge at x=42, y=9.
```

The resulting UTF-8 byte string is what gets encrypted, committed, opened, and eventually proven over.

## Commitments

A commitment anchors a secret publicly without revealing it.

Use a salted hash:

```text
commitment = H(domain || encoded_secret || salt)
```

Recommended:

```text
domain = "sui-secret-commitment-v1"
salt = 32 random bytes
hash = Blake2b-256 or SHA-256
```

The salt is required because many text secrets are guessable.

Without a salt, observers could brute-force likely secrets such as:

```text
x=42;y=9
attack=north
vote=yes
```

## Commitment Object

The Move module can store commitment objects or emit commitment events.

```move
public struct SecretCommitment has key, store {
    id: UID,
    game_id: ID,
    author: address,
    schema: vector<u8>,
    commitment: vector<u8>,
    hash_scheme: vector<u8>,
    created_at_ms: u64,
    opened: bool,
}
```

For event indexing:

```move
public struct SecretCommitted has copy, drop {
    commitment_id: ID,
    game_id: ID,
    author: address,
    schema: vector<u8>,
    commitment: vector<u8>,
    hash_scheme: vector<u8>,
    created_at_ms: u64,
}
```

## Opening A Commitment

Opening reveals:

```text
encoded_secret
salt
```

Anyone verifies:

```text
H(domain || encoded_secret || salt) == commitment
```

Move can verify the hash on-chain if the hash function is available and the secret is small enough.

Alternatively, the app can verify openings client-side while Move records the reveal.

Opening event:

```move
public struct SecretOpened has copy, drop {
    commitment_id: ID,
    opener: address,
    secret: vector<u8>,
    salt: vector<u8>,
    opened_at_ms: u64,
}
```

For the PoC, client-side verification is acceptable. For game-enforced reveals, Move should verify before marking `opened = true`.

## Sharing Commitment Openings Privately

A strong pattern is:

```text
1. Alice commits to a secret on-chain.
2. Alice privately shares encoded_secret + salt with Bob.
3. Bob can verify locally that the secret opens Alice's commitment.
4. Bob can later reveal or prove knowledge of the opening.
```

This turns private sharing into transferable knowledge.

Example:

```text
Alice posts commitment to fortress location.
Alice privately shares the opening with Bob.
Bob now knows the committed location.
The public still does not.
```

This supports gameplay like:

- Trusted ally disclosure.
- Betrayal by revealing an opening.
- Proof that a scout learned real information.
- Delayed public reveal after a raid.

## Receipts

A receipt proves that a secret was shared, without necessarily revealing the secret.

The simplest receipt is a public hash of the encrypted envelope contents:

```text
receipt = H(domain || envelope_id || sender || recipient || ciphertext_hash)
```

This proves that an encrypted exchange occurred, but not what was inside.

For a stronger receipt, the decrypted plaintext can contain:

```text
receipt_nonce
commitment_id
encoded_secret_hash
```

The recipient can later reveal only the receipt fields, not the full secret.

Receipt event:

```move
public struct SecretReceiptClaimed has copy, drop {
    envelope_id: ID,
    claimant: address,
    sender: address,
    schema: vector<u8>,
    receipt_hash: vector<u8>,
    claimed_at_ms: u64,
}
```

This is not a ZK proof. It is just a public marker that a participant claims to have received something matching a known envelope or commitment.

## Claims About Text Secrets

Many useful claims over text secrets are text predicates.

Examples:

```text
secret starts with "asset_location:"
secret contains "region=12"
secret contains "tribe=red"
secret has schema "scout_report_v1"
secret body length <= 256
secret hash opens commitment C
```

Text predicates are possible in ZK later, but they are more expensive than numeric predicates.

For near-term design, normal prose is fine. If a secret may later need machine-checked claims, prefer text that also carries explicit fields:

```text
schema=asset_location_v1
body=asset_id=fortress-001;x=42;y=9;region=12
```

This gives future circuits or client-side verifiers clear fields to parse.

## Optional Structured Text Format

For secrets that may later need precise claims, use structured text rather than unconstrained prose.

Recommended optional body format:

```text
key=value;key=value;key=value
```

Rules:

- Keys are lowercase text identifiers: `[a-z_][a-z0-9_]*`.
- Values are regular text without unescaped `;`.
- Escape `;`, `=`, and `\` if needed.
- Keep body size bounded.

Example:

```text
asset_id=fortress-001;x=42;y=9;region=north_ridge
```

This is still human-readable but much easier to parse later.

This format is optional. Ordinary text secrets remain valid.

## Future ZK Direction

Later, the system can add zero-knowledge proofs over committed text secrets.

Useful predicates:

```text
I know encoded_secret and salt such that H(secret || salt) = commitment.

The secret has schema asset_location_v1.

The secret contains x and y coordinates within region R.

The secret was shared in an envelope addressed to me.

The secret timestamp is within the current epoch.
```

For arbitrary text, circuits must either:

- Verify bytes directly.
- Parse bounded key-value strings.
- Hash the full secret and prove only relations to extracted fields.

The third option is usually best:

```text
private inputs:
  encoded_secret
  salt
  parsed fields

public inputs:
  commitment
  claimed region

proof checks:
  hash(encoded_secret || salt) == commitment
  parsed fields are correctly extracted from encoded_secret
  region predicate holds
```

## Practical PoC Extension Plan

### Phase 1: Commitments

Add client support for:

```ts
encodeTextSecret(secret): Uint8Array
createCommitment(encodedSecret): { commitment, salt }
verifyOpening(encodedSecret, salt, commitment): boolean
```

Add Move support for:

```text
commit_secret
open_secret
SecretCommitted event
SecretOpened event
```

### Phase 2: Private Opening Sharing

Allow encrypted messages to contain:

```json
{
  "kind": "commitment_opening_v1",
  "commitmentId": "0x...",
  "encodedSecret": "...",
  "salt": "..."
}
```

The recipient UI verifies the opening locally and displays:

```text
Verified opening for commitment 0x...
```

### Phase 3: Receipts

Allow recipients to post receipt claims:

```text
I received a secret related to commitment C from Alice.
```

This remains non-ZK and does not reveal the secret.

### Phase 4: ZK Claims

Add circuits only after the commitment/opening UX is working.

Start with:

```text
prove knowledge of opening for commitment C
```

Then add:

```text
prove asset location is inside region R
```

## Example Game Flow

```text
1. Alice creates a text asset-location secret.
2. Alice encodes it to stable UTF-8 bytes.
3. Alice creates commitment C = H(secret || salt).
4. Alice posts C on-chain.
5. Alice privately sends secret + salt to Bob.
6. Bob decrypts the message.
7. Bob verifies that secret + salt opens C.
8. Bob now knows Alice's committed secret.
9. Later, Bob may reveal the opening or claim receipt.
10. Future ZK extension lets Bob prove knowledge without revealing.
```

## Security Notes

- Always salt commitments.
- Bound secret length.
- Encode text to stable UTF-8 bytes before hashing.
- Bind commitments to game ID, schema, author, and timestamp.
- Do not rely on unsalted hashes for human-readable secrets.
- Treat receipt claims as claims, not cryptographic proofs of plaintext knowledge.
- Keep ZK predicates narrow and schema-specific.

## Success Criteria

This extension is useful when:

- A player can commit to a text secret.
- Another player can receive the opening privately.
- The receiver can verify the opening locally.
- The opening can later be revealed publicly.
- The feed can distinguish plain encrypted secrets from commitment openings.
- No ZK machinery is required for the first extension.
