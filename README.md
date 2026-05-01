# Whisper Protocol PoC

Proof of concept for Whisper — Sui-based private messaging where the
ciphertext, sender, recipient, schema, and key version are public on chain
but the plaintext is only legible to the addressed recipient.

> **Naming note.** The on-chain Move module is still `secret_sharing` and
> the HKDF info string is still `sui-secret-sharing-poc-v1`. These are
> wire-level identifiers — changing them requires a republish and key
> rotation. The "Whisper" rename is a display-layer change only, so the
> running localnet keeps working.

The current implementation focuses on the protocol core:

- Ed25519 demo keys loaded from `.env`.
- X25519 encryption keys derived from Ed25519 key material.
- Local encrypt/decrypt CLI for Alice, Bob, and Charlie.
- Move contract with a shared `KeyRegistry` (with monotonic key versions)
  and `EncryptedEnvelope` transport bound to the recipient's current key.

## Setup

Start a local Sui node:

```powershell
sui start --force-regenesis --with-faucet --fullnode-rpc-port 9000
```

If this runs in a separate terminal, leave it open while working against localnet.

Generate local demo keys:

```powershell
cargo run -q -- generate-env
```

Copy the output into `.env`, then add:

```text
SUI_RPC_URL=http://127.0.0.1:9000
SUI_PACKAGE_ID=<published package id>
SUI_REGISTRY_ID=<published KeyRegistry object id>
```

Do not use real funded keys.

Import the `.env` demo keys into the local Sui keystore and fund them:

```powershell
.\scripts\import-env-keys.ps1
.\scripts\fund-demo-keys.ps1
```

Publish the Move package:

```powershell
sui client publish contracts --gas-budget 200000000 --json
```

From the publish output's `objectChanges` array:

- copy the `packageId` of the `published` entry into `.env` as `SUI_PACKAGE_ID`;
- copy the `objectId` of the `created` entry whose `objectType` ends in
  `::secret_sharing::KeyRegistry` into `.env` as `SUI_REGISTRY_ID`.

The `KeyRegistry` is a shared object created at publish time by the module's
`init` function. All on-chain commands take it as an input.

## Local Protocol Commands

Print a character's derived public keys:

```powershell
cargo run -q -- keys alice
```

Encrypt a text secret from Alice to Bob:

```powershell
cargo run -q -- encrypt alice bob --text "fortress at x=42 y=9"
```

Decrypt an envelope as Bob:

```powershell
$envelope = cargo run -q -- encrypt alice bob --text "fortress at x=42 y=9"
cargo run -q -- decrypt bob --envelope $envelope
```

Trying to decrypt the same envelope as Charlie should fail.

## On-Chain Protocol Commands

Register each character's derived encryption public key into the shared
`KeyRegistry`:

```powershell
cargo run -q -- register-key alice
cargo run -q -- register-key bob
cargo run -q -- register-key charlie
```

Re-running `register-key` for a character rotates their key and bumps
`key_version` (1, 2, 3, ...). Old envelopes encrypted to a previous version
remain decryptable only with the prior key material.

Send an encrypted secret on-chain. The CLI reads the recipient's current
`key_version` from the registry, encrypts to it, and posts the envelope:

```powershell
cargo run -q -- send-secret alice bob --text "fortress at x=42 y=9"
```

Posting fails on-chain (`E_STALE_KEY_VERSION`, abort code 3) if the declared
`key_version` doesn't match the recipient's current registry entry — so a
sender racing a rotation will be told to retry.

Read owned encrypted envelopes as a character:

```powershell
cargo run -q -- inbox bob
cargo run -q -- inbox charlie
```

Bob can decrypt envelopes sent to Bob; Charlie sees only envelopes he owns.
Any envelope encrypted with a key the recipient no longer holds shows as
`<locked>`. Recipients can clean those up with the contract's
`delete_envelope` entry function.

## Move Contract

The Move package lives in `contracts/`.

Core types:

- `KeyRegistry` — shared object, created at publish; holds a
  `Table<address, KeyEntry>` of every account's current encryption key.
- `KeyEntry` — `encryption_scheme`, `encryption_pubkey`, monotonic
  `key_version`, `rotated_at_ms`.
- `EncryptedEnvelope` — owned object, transferred to the recipient address.
  Carries opaque `ciphertext` plus `eph_pubkey`, `nonce`, `key_version`, and
  an optional opaque `context: vector<u8>` indexer tag.
- `PublicNote` — separate broadcast primitive; not part of the encrypted
  transport core.

Entry functions:

- `register_encryption_key(&mut KeyRegistry, scheme, pubkey, &Clock)` —
  insert on first call, overwrite + bump `key_version` on subsequent calls.
- `post_envelope(&KeyRegistry, recipient, context, schema, key_version,
  eph_pubkey, nonce, ciphertext, &Clock)` — asserts the declared
  `key_version` equals the recipient's current registry entry, then transfers
  an `EncryptedEnvelope` to the recipient.
- `delete_envelope(EncryptedEnvelope)` — owner-only via Sui object
  ownership.
- `post_public_note(context, text, &Clock)`.

Public accessors `current_key`, `key_version_of`, `encryption_pubkey_of`,
`encryption_scheme_of` let downstream modules read registry state inside a
PTB.

The contract stores ciphertext and emits events; it never inspects plaintext
or the `context` tag. Membership/scoping/gating live (or will live) in
optional modules layered on top of this core.

## Verification

Rust protocol CLI:

```powershell
cargo check
```

Move package:

```powershell
sui move build --path contracts
```

The `contracts/Move.toml` localnet environment must match the active local chain identifier. If localnet is regenerated, refresh it with:

```powershell
sui client chain-identifier
```

Then update the `[environments] localnet = "..."` value in `contracts/Move.toml`.
