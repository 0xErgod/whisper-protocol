# @whisper-protocol/sdk

Client SDK for the [Whisper Protocol](https://github.com/0xErgod/whisper-protocol) — Sui-based private messaging where the ciphertext is public on chain but the plaintext is only legible to the addressed recipient.

The SDK exposes pure primitives — encryption, decryption, transaction building, registry queries — and one optional convenience facade (`WhisperClient`). It holds **no secrets**; every encryption call takes the caller's keys as explicit input.

## Install

```bash
npm install @whisper-protocol/sdk
# or
pnpm add @whisper-protocol/sdk
```

## Quick Start

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

// Build an unsigned tx that posts an encrypted secret. Caller signs.
const { tx, payload, keyVersion } = await whisper.prepareSend({
  senderAddress: myAddress,
  recipientAddress: bobAddress,
  plaintext: "fortress at x=42 y=9",
});

// Hand off to a wallet (dapp-kit, Sui dApp Standard, custom Signer, …)
const result = await wallet.signAndExecuteTransaction({ transaction: tx });

// Later, on the recipient side:
const inbox = await whisper.fetchInbox(myAddress);
for (const env of inbox) {
  const plaintext = whisper.decryptEnvelopeUtf8({
    envelope: env,
    recipientAddress: myAddress,
    recipientPrivateKey: myX25519PrivateKey,
  });
  if (plaintext !== null) console.log(`${env.sender}: ${plaintext}`);
}
```

## Where do encryption keys come from?

The SDK does not opine. You get an X25519 keypair however you like:

- **Wallet-signature derivation** (recommended for real users) — see [`@whisper-protocol/wallet-derived-keys`](../wallet-derived-keys), which derives the keypair from a domain-separated personal-message signature.
- **From an Ed25519 seed** — for scripted demos or test fixtures, derive X25519 from the Ed25519 seed via SHA-512 + Curve25519 clamping.
- **Random** — generate per-session keys for ephemeral conversations.

The encryption keypair is **public-key registered** with the on-chain `KeyRegistry` so other senders can encrypt to you. Use `whisper.buildRegisterKeyTx(publicKey)` and have your wallet sign it.

## Sub-exports

- `@whisper-protocol/sdk` — the main entry point: `WhisperClient`, `encryptForRecipient`, `tryDecrypt`, `buildPostEnvelopeTx`, `buildRegisterKeyTx`, registry/envelope helpers, address utilities.
- `@whisper-protocol/sdk/networks` — `LOCALNET`, `TESTNET`, `MAINNET` deployment constants.
- `@whisper-protocol/sdk/feed` — `fetchFeed`, gas-cost enrichment. Optional; only import if you're building a UI.

## Versioning

| SDK         | Contract `protocol_version` | Notes                |
| ----------- | --------------------------- | -------------------- |
| `0.1.x`     | `1`                         | Initial release.     |

The SDK ships a `SDK_PROTOCOL_VERSION` constant. Future releases will surface a runtime check that reads the on-chain `protocol_version` and refuses to operate against a registry it does not understand.

## Threat model summary

Whisper provides **payload confidentiality** against public chain observers, indexers, and other users. It does **not** provide:

- Forward secrecy (a wallet compromise reveals every past encryption key).
- Recipient anonymity (recipient address is public on the envelope).
- Deniability (the keypair is wallet-attributable).

See the protocol spec for the full threat model.

## License

MIT.
