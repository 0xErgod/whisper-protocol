# Whisper Protocol

Sui-based private messaging where the ciphertext, sender, recipient, schema, and key version are public on chain but the plaintext is only legible to the addressed recipient.

This monorepo houses the Move package, the TypeScript SDK, the wallet-derivation helper, and a demo dApp.

## Layout

```
contracts/                              # Move package — published to localnet/testnet/mainnet
crates/secret-sharing-cli/              # Rust CLI for scripted demos (internal, not published)
packages/
  sdk/                                  # @whisper-protocol/sdk — encrypt, decrypt, build txs
  wallet-derived-keys/                  # @whisper-protocol/wallet-derived-keys — wallet-signature key derivation
web/                                    # demo dApp consuming the SDK + @mysten/dapp-kit
networks.json                           # canonical deployment IDs per network (auto-updated by CI)
specs/                                  # protocol design docs
```

The SDK and the contract version independently. The contract exposes `protocol_version()` and the SDK ships a matching `SDK_PROTOCOL_VERSION` constant; bumping either side requires a coordinated release.

## Quickstart (local)

```powershell
# Start a local Sui node
sui start --force-regenesis --with-faucet --fullnode-rpc-port 9000

# Generate demo keys (creates .env)
cargo run -q -- generate-env

# Import + fund the demo addresses
.\scripts\import-env-keys.ps1
.\scripts\fund-demo-keys.ps1

# Build everything
pnpm install
pnpm build

# Publish the contract (overwrite any stale Published.toml first)
sui client publish contracts --gas-budget 200000000 --json
# Copy packageId + KeyRegistry objectId into web env or networks.json

# Run the dApp
pnpm dev:web
```

## How it works

1. **Connect a Sui wallet.** No demo seed phrase needed — the dApp uses [`@mysten/dapp-kit`](https://www.npmjs.com/package/@mysten/dapp-kit).
2. **Sign a canonical message once per device.** The wallet's signature over a fixed, domain-separated message is run through HKDF-SHA256 to produce an X25519 encryption keypair. The signature itself never leaves the browser. See [specs/wallet-signature-derived-keys.md](specs/wallet-signature-derived-keys.md).
3. **Register your encryption public key on the shared `KeyRegistry`.** Other senders look you up here to encrypt to your current `key_version`.
4. **Send / receive envelopes.** Senders read your key from the registry, encrypt with X25519 + ChaCha20-Poly1305, and post the envelope on chain via `post_envelope`. The contract asserts the declared `key_version` matches your current registration; senders racing a rotation get told to retry.

## Threat model

Whisper provides:

- Payload confidentiality against public chain observers, indexers, and other users.
- Sender-authenticated delivery via Sui transaction signing.
- Recipient-only decryption.

Whisper does **not** provide:

- Forward secrecy. A wallet compromise reveals every encryption key derivable under any version → every past message is decryptable.
- Recipient anonymity. Recipient address is public on the envelope.
- Deniability. The keypair is wallet-attributable.
- Metadata privacy. Sender, recipient, schema, key version, sizes, and timestamps are all public.

See [specs/](specs/) for full design notes and trade-offs.

## CI/CD

- **`ci.yml`** — typecheck + build on every push and PR (TypeScript packages, Rust CLI, Move package).
- **`publish-sdk.yml`** — on tag `sdk-v*` or `wallet-derived-v*`, publish to npm with provenance.
- **`deploy-contract.yml`** — manually triggered (`workflow_dispatch`); publishes the Move package to testnet (or mainnet with explicit confirmation), captures the new IDs, opens a PR updating `networks.json`.

## Specs

- [secret-sharing-poc-build.md](specs/secret-sharing-poc-build.md) — as-built Move contract and demo flow.
- [wallet-bound-private-messaging.md](specs/wallet-bound-private-messaging.md) — broader protocol design with future multi-recipient envelopes.
- [wallet-signature-derived-keys.md](specs/wallet-signature-derived-keys.md) — the wallet-signature derivation scheme used by `@whisper-protocol/wallet-derived-keys`.
- [provable-shared-secrets-extensions.md](specs/provable-shared-secrets-extensions.md) — forward-looking commitments / openings / ZK roadmap.

## License

MIT.
