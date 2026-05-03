# @whisper-protocol/wallet-derived-keys

[![npm version](https://img.shields.io/npm/v/@whisper-protocol/wallet-derived-keys.svg)](https://www.npmjs.com/package/@whisper-protocol/wallet-derived-keys)
[![provenance](https://img.shields.io/badge/npm-provenance-brightgreen)](https://docs.npmjs.com/generating-provenance-statements)

Derive a stable X25519 encryption keypair from a Sui wallet's personal-message signature, **without ever exporting the wallet's private key**.

The user signs one fixed, domain-separated canonical message with their wallet. The signature bytes are run through HKDF-SHA256 to produce a 32-byte X25519 seed. The corresponding public key is then published to Whisper's on-chain `KeyRegistry` so other senders can encrypt to the user.

This is the production-shaped key-management path for Whisper Protocol. Companion package: [`@whisper-protocol/sdk`](https://www.npmjs.com/package/@whisper-protocol/sdk).

## Read the writeup

Background, threat model, and design rationale:

> **[Decentralized Pairwise Secret Communication Protocol over SUI Blockchain](https://thoughtfolio.xyz/Decentralized+Pairwise+Secret+Communication+Protocol+over+SUI+Blockchain)**

Full spec: [`specs/wallet-signature-derived-keys.md`](https://github.com/0xErgod/whisper-protocol/blob/main/specs/wallet-signature-derived-keys.md).

## How it works

```
                        Sui wallet
                            │
                            │  signPersonalMessage(canonical_message)
                            ▼
                     signature_bytes (Ed25519, deterministic)
                            │
                            │  HKDF-SHA256
                            ▼
                  encryption_private_key  (32-byte X25519 seed)
                            │
                            │  scalarMult
                            ▼
                  encryption_public_key   ──► register on KeyRegistry
```

The whole construction depends on the wallet producing the **same signature bytes** for the same `(private_key, message)` every time. This is true for **Ed25519** (Sui's default — guaranteed deterministic by RFC 8032), but **not** for ECDSA secp256k1/secp256r1, zkLogin, or passkey signatures, which are non-deterministic by spec. The package provides a `requireEd25519(account)` helper to gate registration on supported wallets.

## Install

```bash
npm install @whisper-protocol/wallet-derived-keys
# or
pnpm add @whisper-protocol/wallet-derived-keys
```

No runtime peer dependencies — pure crypto, no Sui SDK or React requirement. Pair with `@whisper-protocol/sdk` for the on-chain side and a wallet adapter (e.g. [`@mysten/dapp-kit`](https://www.npmjs.com/package/@mysten/dapp-kit)) for signing.

## Usage with `@mysten/dapp-kit`

```ts
import { useSignPersonalMessage, useCurrentAccount } from "@mysten/dapp-kit";
import {
  canonicalMessageBytes,
  deriveFromWalletSigner,
  readCachedKeypair,
  writeCachedKeypair,
  requireEd25519,
} from "@whisper-protocol/wallet-derived-keys";
import { sha256 } from "@noble/hashes/sha256";

function fromBase64(b64: string): Uint8Array {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function useEncryptionKeypair() {
  const account = useCurrentAccount();
  const { mutateAsync: signPersonalMessage } = useSignPersonalMessage();

  return async () => {
    if (!account) throw new Error("No connected wallet");

    // Refuse non-Ed25519 wallets — they'd produce a non-deterministic
    // signature and silently lose access to past messages.
    requireEd25519(account);

    const message = { address: account.address, version: 1, scope: "root" };
    const cacheKey = {
      address: account.address,
      version: 1,
      scope: "root",
      canonicalMessageDigest: sha256(canonicalMessageBytes(message)),
    };

    // Same wallet on the same device? Re-use the cached keypair.
    const cached = await readCachedKeypair(cacheKey);
    if (cached) return cached;

    // First time on this device: prompt for one signature, derive,
    // cache for the future.
    const keypair = await deriveFromWalletSigner(async (bytes) => {
      const { signature } = await signPersonalMessage({
        message: bytes,
        chain: "sui:testnet",
      });
      return { signature: fromBase64(signature) };
    }, message);

    await writeCachedKeypair(cacheKey, keypair);
    return keypair;
  };
}
```

## API

### Pure derivation (works in Node, browsers, anywhere)

| Function | Returns | Notes |
|---|---|---|
| `canonicalMessage(input)` | `string` | The exact bytes the wallet signs. |
| `canonicalMessageBytes(input)` | `Uint8Array` | UTF-8 encoded. |
| `deriveFromSignature(signatureBytes, message)` | `DerivedEncryptionKeypair` | Pure HKDF + clamp. Treat the input bytes as long-lived secret material. |
| `deriveFromWalletSigner(signer, message)` | `Promise<DerivedEncryptionKeypair>` | Convenience wrapper. |

### Wallet-scheme detection

| Function | Returns | Notes |
|---|---|---|
| `detectSchemeFromAccount({ address, publicKey })` | `SuiSignatureScheme \| null` | BLAKE2b address-derivation reverse lookup. |
| `requireEd25519(account)` | `"ED25519"` | Throws on unsupported schemes. Use this before calling `deriveFromWalletSigner`. |
| `suiAddressFromPublicKey(flag, pubkey)` | `string` | Standalone helper. |

### IndexedDB cache (browser only)

| Function | Returns | Notes |
|---|---|---|
| `makeCacheKey({ address, version, scope, canonicalMessageDigest })` | `string` | Derived deterministic key. |
| `readCachedKeypair(key)` | `Promise<DerivedEncryptionKeypair \| null>` | |
| `writeCachedKeypair(key, keypair)` | `Promise<void>` | |
| `clearCachedKeypair(key)` | `Promise<void>` | |

The cache key includes the canonical-message digest, so any change to the message format auto-invalidates old cached keys.

## Canonical message format

Locked byte-for-byte. UTF-8, LF line endings, no trailing newline. Any change invalidates every previously-derived keypair.

```
whisper-protocol
version: 1
purpose: encryption-keypair
address: 0x<lowercased sui address with 0x prefix>
scope: root
```

The `version` line is the supported way to derive a new keypair from the same wallet — bump it for rotation.

## Threat model

This derivation gives **any-device decryption tied to wallet control**. It does **not** give:

- **Forward secrecy.** A wallet compromise — now or in the future — reveals every encryption key derivable under any version, retroactively. Add a Signal-style ratchet on top if you need this.
- **Phishing immunity.** A malicious dApp can ask the user to "sign in" with a string that matches the canonical message and steal the encryption key. Including the address in the message is partial mitigation; wallet-side message-preview UIs are out of our control.
- **Deniability.** The keypair is wallet-attributable by construction — you can prove a given user controls a given encryption pubkey.
- **Cross-scheme support.** ECDSA wallets that don't implement RFC 6979, zkLogin, and passkey wallets all produce non-deterministic signatures and would silently break the scheme. Use `requireEd25519` to refuse them.

See the [spec](https://github.com/0xErgod/whisper-protocol/blob/main/specs/wallet-signature-derived-keys.md) for the full accounting and the roadmap (ratchet layer, post-quantum migration, per-scope subkeys).

## What this package doesn't include

- **Signature verification** — this package only derives.
- **Wallet connection** — use [`@mysten/dapp-kit`](https://www.npmjs.com/package/@mysten/dapp-kit) or the Sui dApp Standard.
- **On-chain registration** — use [`@whisper-protocol/sdk`](https://www.npmjs.com/package/@whisper-protocol/sdk)'s `buildRegisterKeyTx` to publish the derived public key.

## Repository

Source, issues, and protocol specs: <https://github.com/0xErgod/whisper-protocol>

## License

MIT.
