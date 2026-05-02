# Whisper Protocol

Sui-based private messaging where the ciphertext, sender, recipient, schema, and key version are public on chain but the plaintext is only legible to the addressed recipient.

This monorepo houses the Move package, the TypeScript SDK, the wallet-derivation helper, and a demo dApp.

## Try it

Live demo on Sui **testnet**: **<https://0xergod.github.io/whisper-protocol/>** *(canonical deployment from this repo's `main`)*

You will need a Sui wallet (Slush, Suiet, etc.) set to **Testnet**. The demo derives an X25519 encryption keypair from one personal-message signature, registers your public key on chain, and lets you send encrypted secrets to any other registered address. Nothing leaves your browser unencrypted; the chain only ever sees ciphertext.

> **Trust the URL above.** Anyone can fork this repo and publish a copy to their own `*.github.io` subdomain. Only the URL above is built from `main` of `0xErgod/whisper-protocol` via the `deploy-web` workflow.

## npm packages

- [`@whisper-protocol/sdk`](https://www.npmjs.com/package/@whisper-protocol/sdk) — encrypt, decrypt, build txs
- [`@whisper-protocol/wallet-derived-keys`](https://www.npmjs.com/package/@whisper-protocol/wallet-derived-keys) — derive an X25519 encryption keypair from a Sui wallet signature

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
- **`release.yml`** — runs `semantic-release` on every push to `main`. Each package decides independently whether to cut a release based on the **scope** of the commits since its last tag.
- **`deploy-web.yml`** — on every push to `main`, builds the demo dApp and deploys it to GitHub Pages at <https://0xergod.github.io/whisper-protocol/>.
- **`deploy-contract.yml`** — manually triggered (`workflow_dispatch`); publishes the Move package to testnet (or mainnet with explicit confirmation), captures the new IDs, opens a PR updating `networks.json`.

## Releasing

The two npm packages release independently and automatically. There is no manual `npm version` / `git tag` / `git push --tags` step. **The version number, changelog, npm publish, GitHub release, and changelog commit are all driven by the conventional-commit history.**

To trigger a release, write commits with the right scope and merge them to `main`:

| Commit                                  | Effect                                          |
| --------------------------------------- | ----------------------------------------------- |
| `feat(sdk): add new helper`             | `@whisper-protocol/sdk` minor release           |
| `fix(sdk): correct decoding bug`        | `@whisper-protocol/sdk` patch release           |
| `feat(sdk)!: rename WhisperClient API`  | `@whisper-protocol/sdk` **major** release       |
| `feat(wallet-derived-keys): …`          | `@whisper-protocol/wallet-derived-keys` release |
| `feat: top-level repo change`           | no release (unscoped)                           |
| `feat(web): dApp UI tweak`              | no release (web is not published)               |
| `chore: …` / `ci: …` / `test: …`        | no release                                      |

When the workflow finds commits that warrant a release for a given package, it:

1. Computes the next version from the commit history (semver).
2. Updates `packages/<pkg>/package.json` and writes / appends `packages/<pkg>/CHANGELOG.md`.
3. Publishes to npm with provenance (`--provenance` via OIDC, no manual signing).
4. Creates a GitHub release at the tag `sdk-vX.Y.Z` (or `wallet-derived-vX.Y.Z`) with the changelog body and the npm tarball attached.
5. Pushes a `chore(<pkg>): release X.Y.Z [skip ci]` commit back to `main` so the version bump persists. The `[skip ci]` keeps the next CI run from running again.

**Trade-off you accepted by choosing semantic-release**: there is no review gate on the release itself. A `feat(sdk):` commit merged to `main` will publish to npm within ~3 minutes. The protection is at *merge time* — protect `main` so all PRs require green CI before merging, and treat scoped commits as deliberate release intents. To stage a release without publishing, push to a `next` / `alpha` / `beta` branch — semantic-release ships those as pre-releases (`0.2.0-beta.1`).

### Authentication (OIDC trusted publishing)

The release workflow uses npm's [trusted publishing](https://docs.npmjs.com/trusted-publishers/) flow — no long-lived `NPM_TOKEN` secret. GitHub Actions issues a short-lived OIDC JWT proving `(0xErgod/whisper-protocol, release.yml)`, npm validates it against a per-package trusted-publisher record, and exchanges it for a credential that lasts a few minutes. Provenance signing happens from the same id-token, so every npm release is automatically Sigstore-signed and shows a green badge on npmjs.com.

What this setup requires:

- **`id-token: write`** permission on the workflow job (already set in `release.yml`).
- **A trusted-publisher record on each package** (`@whisper-protocol/sdk` and `@whisper-protocol/wallet-derived-keys`) at npmjs.com → package settings → "Publishing access" → add GitHub Actions trusted publisher with:
  - Organization: `0xErgod`
  - Repository: `whisper-protocol`
  - Workflow filename: `release.yml`
  - Environment name: *(leave blank)*

If you ever rename `release.yml` or move the release logic into a reusable workflow, update the npm-side records first or the next publish will 401. For an extra protection layer, add a GitHub `production` environment with required reviewers and pin it on both the workflow job (`environment: production`) and the trusted-publisher record — every release then requires manual approval before npm accepts it.

## Specs

- [secret-sharing-poc-build.md](specs/secret-sharing-poc-build.md) — as-built Move contract and demo flow.
- [wallet-bound-private-messaging.md](specs/wallet-bound-private-messaging.md) — broader protocol design with future multi-recipient envelopes.
- [wallet-signature-derived-keys.md](specs/wallet-signature-derived-keys.md) — the wallet-signature derivation scheme used by `@whisper-protocol/wallet-derived-keys`.
- [provable-shared-secrets-extensions.md](specs/provable-shared-secrets-extensions.md) — forward-looking commitments / openings / ZK roadmap.

## License

MIT.
