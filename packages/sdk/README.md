# @whisper-protocol/sdk

[![npm version](https://img.shields.io/npm/v/@whisper-protocol/sdk.svg)](https://www.npmjs.com/package/@whisper-protocol/sdk)
[![provenance](https://img.shields.io/badge/npm-provenance-brightgreen)](https://docs.npmjs.com/generating-provenance-statements)

Client SDK for the **Whisper Protocol** — Sui-based private messaging on a
ZK-friendly cryptographic stack (BabyJubjub + Poseidon for envelopes and
commitments, Groth16-on-BN254 for on-chain proofs).

The SDK is a thin JavaScript layer over [`crypto-wasm`](https://github.com/0xErgod/whisper-protocol/tree/main/crates/crypto-wasm)
(the WASM build of the protocol's Rust cryptography): wire codecs, PTB
builders, registry queries, BJJ key derivation, and a proof client. It
holds **no secrets** — every operation takes the caller's seed/keys as
explicit input.

## Install

```bash
pnpm add @whisper-protocol/sdk
```

Peer-required: a `SuiClient` from `@mysten/sui` and a way to sign
transactions (a wallet adapter, dapp-kit, or a raw `Keypair`).

> The SDK depends on the `crypto-wasm` package (a `--target bundler`
> wasm-pack build). Bundlers need `vite-plugin-wasm` (or equivalent);
> see the demo dApp's `vite.config.ts` for the setup.

## Quick start

```ts
import { SuiClient } from "@mysten/sui/client";
import {
  WhisperClient,
  deriveFromSignature,
  cryptoWasm,
} from "@whisper-protocol/sdk";
import { DEVNET } from "@whisper-protocol/sdk/networks";

const suiClient = new SuiClient({ url: DEVNET.rpcUrl });
const whisper = new WhisperClient({
  suiClient,
  packageId: DEVNET.packageId!,
  registryId: DEVNET.registryId!,
});

// 1. Derive a BabyJubjub keypair from a wallet signature over the
//    canonical message. The signature bytes are the seed.
const keys = deriveFromSignature(walletSignatureBytes, { address: myAddress });

// 2. Register your BJJ public key on chain.
const regTx = whisper.buildRegisterKeyTx({ pubkeyX: keys.pubkeyX, pubkeyY: keys.pubkeyY });
await wallet.signAndExecuteTransaction({ transaction: regTx });

// 3. Seal + post an envelope to a registered recipient.
const stream = cryptoWasm.text_utf8_v1_encode(new TextEncoder().encode("hello"));
const { tx } = await whisper.prepareSend({
  senderAddress: myAddress,
  senderSeed: keys.seed,
  senderPubkeyX: keys.pubkeyX,
  senderPubkeyY: keys.pubkeyY,
  recipientAddress: bobAddress,
  envelopeId: freshEnvelopeId(),       // unique per (sender, recipient)
  payload: { encodingId: cryptoWasm.text_utf8_v1_id(), stream },
});
await wallet.signAndExecuteTransaction({ transaction: tx });

// 4. Recipient side: fetch an envelope and decrypt it.
const onChain = await whisper.fetchEnvelope(envelopeObjectId);
const payload = whisper.decryptEnvelope({
  envelope: onChain!,
  recipientSeed: keys.seed,
  recipientPubkeyX: keys.pubkeyX,
  recipientPubkeyY: keys.pubkeyY,
});
const text = new TextDecoder().decode(cryptoWasm.text_utf8_v1_decode(payload.stream));
```

## Commitments

```ts
import { commit, verifyOpening, buildCommitTx, buildOpenTx } from "@whisper-protocol/sdk";

// Vector Pedersen commitment (encoding id bound at G_0).
const { commitmentX, commitmentY, opening } = commit({
  encodingId: cryptoWasm.text_utf8_v1_id(),
  stream: cryptoWasm.text_utf8_v1_encode(new TextEncoder().encode("secret")),
  blinding: freshBlinding(),
});
// `opening` (stream + blinding) is what you keep to open later.
await wallet.signAndExecuteTransaction({
  transaction: buildCommitTx({ packageId, encodingId, commitmentX, commitmentY }),
});
```

## On-chain proof of partial opening

```ts
import { proveCommitmentOpening, buildOpenWithProofTx } from "@whisper-protocol/sdk";

// Generate a Groth16 proof (via the prover-server) that you know an
// opening whose stream[0] equals the claimed value — without revealing
// the rest. Then post it for on-chain verification.
const proofBytes = await proveCommitmentOpening({
  commitmentX, commitmentY, opening,
  claimedFirstValue: opening.stream[0],
  proverUrl: "http://127.0.0.1:3001",
});
await wallet.signAndExecuteTransaction({
  transaction: buildOpenWithProofTx({
    packageId, commitmentObjectId, claimedFirstValue: opening.stream[0], proofBytes,
  }),
});
```

## API surface

- **Envelopes** — `seal`, `open`, `WhisperClient.prepareSend`,
  `WhisperClient.decryptEnvelope`, `fetchEnvelope`, `buildPostEnvelopeTx`
- **Commitments** — `commit`, `verifyOpening`, `fetchCommitment`,
  `buildCommitTx`, `buildOpenTx`
- **Proofs** — `proveCommitmentOpening`, `buildOpenWithProofTx`,
  `DEFAULT_PROVER_URL`
- **Keys** — `deriveFromSignature`, `deriveFromWalletSigner`,
  `canonicalMessage`, `buildRegisterKeyTx`, `fetchRegistryEntries`,
  `fetchRegistryEntry`
- **Protocol** — `assertWriteCompatible`, `readOnChainProtocolVersion`,
  `SDK_PROTOCOL_VERSION`
- **WASM** — `cryptoWasm` (the full BJJ + Poseidon + encoding surface)

### Sub-exports

- `@whisper-protocol/sdk` — main entry
- `@whisper-protocol/sdk/networks` — `LOCALNET` / `DEVNET` / `TESTNET` / `MAINNET` deployment constants
- `@whisper-protocol/sdk/feed` — `fetchFeed`, gas helpers (UI-oriented)

## Versioning

The SDK ships `SDK_PROTOCOL_VERSION`; the deployed Move package exposes a
matching `protocol_version()`. Call `WhisperClient.assertWriteCompatible()`
at startup to refuse writing against a mismatched deployment.

## License

MIT.
