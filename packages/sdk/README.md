# @whisper-protocol/sdk

[![npm version](https://img.shields.io/npm/v/@whisper-protocol/sdk.svg)](https://www.npmjs.com/package/@whisper-protocol/sdk)
[![provenance](https://img.shields.io/badge/npm-provenance-brightgreen)](https://docs.npmjs.com/generating-provenance-statements)

Client SDK for the **Whisper Protocol** — Sui-based private messaging where the ciphertext, sender, recipient, schema, and key version are public on chain but the plaintext is only legible to the addressed recipient.

The SDK exposes pure primitives — encryption, decryption, transaction building, registry queries — and one optional convenience facade (`WhisperClient`). It holds **no secrets**; every encryption call takes the caller's keys as explicit input.

## Read the writeup

The design rationale and threat model live at:

> **[Decentralized Pairwise Secret Communication Protocol over SUI Blockchain](https://thoughtfolio.xyz/Decentralized+Pairwise+Secret+Communication+Protocol+over+SUI+Blockchain)**

This README assumes you've skimmed it and just want to integrate.

## Live demo

Try it without installing anything: **<https://0xergod.github.io/whisper-protocol/>** (Sui testnet). You will need a Sui wallet (Slush, Suiet, etc.) set to **Testnet**.

## Install

```bash
npm install @whisper-protocol/sdk
# or
pnpm add @whisper-protocol/sdk
```

Peer-required: a `SuiClient` from `@mysten/sui` and a way to sign transactions (a wallet adapter, dapp-kit, or a raw `Keypair`).

## Quick start

```ts
import { SuiClient } from "@mysten/sui/client";
import { WhisperClient } from "@whisper-protocol/sdk";
import { TESTNET } from "@whisper-protocol/sdk/networks";

const suiClient = new SuiClient({ url: TESTNET.rpcUrl });
const whisper = new WhisperClient({
  suiClient,
  packageId: TESTNET.packageId!,
  registryId: TESTNET.registryId!,
});

// Optional but recommended: assert the deployed Move package's
// protocol_version() matches what this SDK was built for.
await whisper.assertProtocolCompatible();

// Build an unsigned transaction that posts an encrypted secret to the
// recipient. Caller signs and executes it via their wallet.
const { tx, payload, keyVersion } = await whisper.prepareSend({
  senderAddress: myAddress,
  recipientAddress: bobAddress,
  plaintext: "fortress at x=42 y=9",
});

const result = await wallet.signAndExecuteTransaction({
  transaction: tx,
  chain: "sui:testnet",
});

// Recipient side: pull the inbox and decrypt envelopes addressed to you.
const inbox = await whisper.fetchInbox(myAddress);
for (const env of inbox) {
  const text = whisper.decryptEnvelopeUtf8({
    envelope: env,
    recipientAddress: myAddress,
    recipientPrivateKey: myX25519PrivateKey,
  });
  if (text !== null) console.log(`${env.sender}: ${text}`);
}
```

## Where do encryption keys come from?

The SDK is agnostic about how you produce an X25519 keypair. Three common paths:

- **Wallet-signature derivation (recommended for end-user dApps).** The user's wallet signs a fixed canonical message; HKDF-SHA256 over the signature bytes produces a stable X25519 seed. Use [`@whisper-protocol/wallet-derived-keys`](https://www.npmjs.com/package/@whisper-protocol/wallet-derived-keys).
- **From an Ed25519 seed (scripted demos / integration tests).** Derive X25519 from the Ed25519 seed via SHA-512 + Curve25519 clamping.
- **Random ephemeral keys (one-shot conversations).** Generate fresh keys per session and discard.

Whichever path you pick, register the public key on the on-chain `KeyRegistry` so other senders can address you. Use `whisper.buildRegisterKeyTx(publicKey)` and have your wallet sign it.

## API surface

### Convenience facade

```ts
new WhisperClient({ suiClient, packageId, registryId, protocolVersion? })
```

| Method | Returns | Notes |
|---|---|---|
| `assertProtocolCompatible()` | `Promise<number>` | Reads on-chain `protocol_version()`, throws on mismatch. Memoised. |
| `prepareSend({ senderAddress, recipientAddress, plaintext, schema?, context? })` | `Promise<PreparedSend>` | Looks up recipient, encrypts, builds unsigned tx. |
| `decryptEnvelope({ envelope, recipientAddress, recipientPrivateKey })` | `Uint8Array \| null` | Returns null on any failure. |
| `decryptEnvelopeUtf8(...)` | `string \| null` | Same, decodes as UTF-8. |
| `fetchRegistry()` | `Promise<RegistryEntry[]>` | All registered keys. |
| `fetchRegistryEntry(account)` | `Promise<RegistryEntry \| null>` | One account's entry. |
| `fetchInbox(ownerAddress)` | `Promise<OnChainEnvelope[]>` | Owned envelopes for an address. |
| `fetchEnvelope(envelopeId)` | `Promise<OnChainEnvelope \| null>` | Single envelope by id. |
| `buildRegisterKeyTx(publicKey, scheme?)` | `Transaction` | Unsigned. |

### Pure primitives (no client needed)

```ts
import {
  encryptForRecipient, tryDecrypt, tryDecryptUtf8,
  buildPostEnvelopeTx, buildRegisterKeyTx,
  fetchRegistryEntries, fetchRegistryEntry,
  fetchInbox, fetchEnvelope,
  readOnChainProtocolVersion,
  normalizeAddress, shortAddress,
} from "@whisper-protocol/sdk";
```

### Sub-exports

- `@whisper-protocol/sdk` — main entry: client, primitives, address utils
- `@whisper-protocol/sdk/networks` — `LOCALNET` / `TESTNET` / `MAINNET` deployment constants
- `@whisper-protocol/sdk/feed` — `fetchFeed`, gas enrichment helpers (UI-oriented; optional)

## Versioning

The SDK ships an `SDK_PROTOCOL_VERSION` constant. The deployed Move module exposes a matching `protocol_version()` view function. Call `WhisperClient.assertProtocolCompatible()` at startup to verify the SDK and the deployed package agree on wire format — bumping either side without the other will throw.

| SDK | Contract `protocol_version` | Notes              |
| --- | --------------------------- | ------------------ |
| 0.1.x | 1 | Initial release.   |

## Threat model summary

Whisper provides:

- Payload confidentiality against public chain observers, indexers, and other users.
- Sender-authenticated delivery via Sui transaction signing.
- Recipient-only decryption.

Whisper does **not** provide:

- Forward secrecy (a wallet compromise reveals every past encryption key).
- Recipient anonymity (recipient address is public on the envelope).
- Deniability (the keypair is wallet-attributable).
- Metadata privacy (sender, recipient, schema, key version, sizes, and timestamps are all public).

See the [writeup](https://thoughtfolio.xyz/Decentralized+Pairwise+Secret+Communication+Protocol+over+SUI+Blockchain) and the [protocol specs](https://github.com/0xErgod/whisper-protocol/tree/main/specs) for the full accounting.

## Repository

Source, issues, and protocol specs: <https://github.com/0xErgod/whisper-protocol>

## License

MIT.
