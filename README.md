# Signal Privacy PoC

Proof of concept for Sui-based private secret sharing.

The current implementation focuses on the protocol core:

- Ed25519 demo keys loaded from `.env`.
- X25519 encryption keys derived from Ed25519 key material.
- Local encrypt/decrypt CLI for Alice, Bob, and Charlie.
- Move contract scaffold for key registration and encrypted envelope posting.

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
```

Do not use real funded keys.

Import the `.env` demo keys into the local Sui keystore and fund them:

```powershell
.\scripts\import-env-keys.ps1
.\scripts\fund-demo-keys.ps1
```

Publish the Move package:

```powershell
sui client publish contracts --gas-budget 100000000 --json
```

Copy the published `packageId` into `.env` as `SUI_PACKAGE_ID`.

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

Register each character's derived encryption public key:

```powershell
cargo run -q -- register-key alice
cargo run -q -- register-key bob
cargo run -q -- register-key charlie
```

Send an encrypted secret on-chain:

```powershell
cargo run -q -- send-secret alice bob --text "fortress at x=42 y=9"
```

Read owned encrypted envelopes as a character:

```powershell
cargo run -q -- inbox bob
cargo run -q -- inbox charlie
```

The intended behavior is that Bob can decrypt envelopes sent to Bob, while Charlie sees only envelopes owned by Charlie. Any envelope encrypted with the wrong key shows as `<locked>`.

## Move Contract

The Move package lives in `contracts/`.

It currently defines:

- `register_encryption_key`
- `post_envelope`
- `post_public_note`
- `EncryptionKeyRegistered`
- `EnvelopePosted`
- `EncryptedEnvelope`
- `PublicNote`

The contract is intentionally dumb transport. It stores ciphertext and emits events; it does not decrypt or validate plaintext.

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
