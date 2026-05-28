# Whisper Protocol

Sui-based private messaging built on a ZK-friendly cryptographic stack:
BabyJubjub + Poseidon for envelopes and commitments, Groth16-on-BN254
for on-chain proofs. The chain stores the ciphertext, sender, recipient,
and encoding id publicly, but only the addressed recipient can read the
plaintext — and a commitment's opening can be *proven* on chain without
ever revealing it.

This monorepo houses the Move package, the Rust cryptography + circuit +
prover crates, the WASM bindings the SDK consumes, the TypeScript SDK,
and a set of demo apps.

## Why this stack

Every primitive lives in BN254's field world so that **decrypting an
envelope or opening a commitment inside a Groth16 circuit is tractable**:

- **BabyJubjub** — a twisted Edwards curve whose base field is BN254's
  scalar field. ECDH, key derivation, and signatures are native field
  arithmetic in a BN254 circuit (~thousands of constraints, not millions).
- **Poseidon** (circomlib parameters) — the hash for the KDF, the stream
  cipher, the MAC, and the commitment, at ~250 constraints per call.
- **Vector Pedersen commitments** over BabyJubjub, with the payload's
  encoding id bound at generator slot `G_0`.
- **Groth16 on BN254** — the proving system, because Sui ships a native
  on-chain verifier for it.

The cryptography is implemented once in Rust (`crates/crypto`), compiled
to WASM for the browser/SDK (`crates/crypto-wasm`), and mirrored as
circuit gadgets (`crates/gadgets`, `crates/circuits`). Cross-language
fixtures pin TS↔Rust↔circuit agreement byte-for-byte.

## Layout

```
contracts/                  # Move package (whisper_protocol): registry, envelopes, commitments, proofs
crates/
  crypto/                   # native BabyJubjub + Poseidon + Pedersen primitives
  crypto-wasm/              # wasm-bindgen bindings the SDK consumes
  encodings/                # payload encodings (text-utf8-v1, …)
  gadgets/                  # circuit gadgets mirroring the native primitives
  circuits/                 # Groth16 circuits (pedersen_opens_to, envelope_open_at_0)
  prover/                   # trusted setup, prove, verify
  prover-server/            # Axum HTTP server wrapping the prover
  prover-wasm/              # (deferred) in-browser proving
  protocol/                 # envelope + commitment composition over the primitives
packages/
  sdk/                      # @whisper-protocol/sdk — wire codecs, PTB builders, proof client
apps/
  protocol/                 # the demo dApp
  curve/                    # BabyJubjub curve visualization
  zk/                       # circuit prove/verify playground
networks.json               # canonical deployment IDs per network
specs/                      # protocol design docs (pinned constructions + worked-example fixtures)
```

## How it works

1. **Derive a BabyJubjub keypair.** The wallet signs one fixed canonical
   message; the signature seeds `keypair_from_seed`. The signature never
   leaves the browser. Cached in IndexedDB so you sign once per device.
2. **Register your BJJ public key** on the shared `KeyRegistry`. Senders
   look you up to encrypt to your current `key_version`.
3. **Send / receive envelopes.** A sender seals a payload with BabyJubjub
   ECDH → Poseidon KDF → Poseidon stream cipher → Poseidon MAC (the
   encoding id is folded into the MAC, so it's public but authenticated),
   and posts it via `post_envelope`. The recipient reconstructs the shared
   point and opens it locally.
4. **Commit + open.** Post a vector Pedersen commitment to a payload via
   `commit_secret`; later either fully reveal it (`open_secret`) or
   **prove a partial opening** (`open_with_proof`) — a Groth16 proof that
   you know an opening whose `stream[0]` equals a claimed value, verified
   on chain by Sui's native Groth16 verifier, without revealing the rest.

## Dev environment

The shared dev devnet is `http://sui-devnet:9000`. It is the default
target of the demo dApp and the SDK.

```powershell
# Build the WASM bindings + SDK + apps
pnpm install
pnpm build

# Publish the Move package to the dev devnet (runs the VK drift guard,
# writes the package + registry ids into networks.json, regenerates
# the SDK's networks.ts). Requires a funded address on the devnet.
./scripts/deploy-devnet.ps1

# Run the demo dApp (defaults to the devnet via networks.json)
pnpm dev:protocol
```

To exercise the on-chain proof flow, also run the prover-server:

```powershell
# First boot runs Groth16 trusted setup (deterministic seed) and writes keys/
cargo run --release --bin prover-server
```

Tests:

```powershell
sui move test --path contracts     # Move
cargo test --workspace             # Rust (crypto, circuits, prover, …)
pnpm test                          # TypeScript (SDK)
```

## Threat model

Whisper provides:

- Payload confidentiality against public chain observers, indexers, and
  other users.
- Sender-authenticated delivery via Sui transaction signing.
- Recipient-only decryption.
- Provable partial openings: a third party can be convinced a committer
  knows an opening to a claimed value, without seeing the opening.

Whisper does **not** provide:

- Forward secrecy. A wallet compromise reveals every derivable key.
- Recipient anonymity. The recipient address is public on the envelope.
- Metadata privacy. Sender, recipient, encoding id, sizes, and timestamps
  are public.

See [specs/](specs/) for the pinned constructions, worked-example
fixtures, and the ZK proving-stack rationale ([specs/zk/stack.md](specs/zk/stack.md)).

## CI/CD

- **`ci.yml`** — typecheck + build (TypeScript, Rust, Move) on every push
  and PR. Builds the WASM bindings before the TS jobs so the workspace
  `link:` to `crates/crypto-wasm/pkg` resolves.
- **`release.yml`** — runs `semantic-release` for `@whisper-protocol/sdk`
  on every push to `main`, gated by conventional-commit scope.
- **`deploy-protocol-demo.yml`** — builds + deploys the demo dApp to
  GitHub Pages on every push to `main`.
- **`deploy-contract.yml`** — manual (`workflow_dispatch`); publishes the
  Move package to a hosted network and opens a PR updating `networks.json`.

## Releasing

`@whisper-protocol/sdk` releases automatically via `semantic-release`,
driven by conventional-commit scope:

| Commit                                 | Effect                              |
| -------------------------------------- | ----------------------------------- |
| `feat(sdk): add new helper`            | minor release                       |
| `fix(sdk): correct a bug`              | patch release                       |
| `feat(sdk)!: rename an API`            | **major** release                   |
| `feat(protocol): dApp tweak`           | no release (the dApp isn't published)|
| `chore: …` / `ci: …` / `test: …`       | no release                          |

Publishing uses npm's OIDC trusted-publishing flow (no `NPM_TOKEN`); the
GitHub Actions id-token is exchanged at npm for a short-lived credential,
and provenance is signed from the same token. Renaming `release.yml`
requires updating the npm-side trusted-publisher record first.

## License

MIT.
