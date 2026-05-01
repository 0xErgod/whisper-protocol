# @whisper-protocol/wallet-derived-keys

Derive a stable X25519 encryption keypair from a Sui wallet's personal-message signature, without ever exporting the wallet's private key.

This package implements the design in [`specs/wallet-signature-derived-keys.md`](../../specs/wallet-signature-derived-keys.md).

## How it works

1. The user's wallet signs a fixed, domain-separated canonical message (`whisper-protocol\nversion: 1\npurpose: encryption-keypair\naddress: 0x…\nscope: root`).
2. The signature bytes are run through HKDF-SHA256 to produce a 32-byte X25519 seed.
3. The corresponding public key is registered on chain via Whisper's `KeyRegistry` so other senders can encrypt to the user.

The whole construction depends on **the wallet producing the same signature bytes for the same `(private_key, message)` every time**. This is true for Ed25519 (Sui's default) but **not** for ECDSA wallets unless they implement RFC 6979. Gate registration on `keypair.getKeyScheme() === "ED25519"`.

## Install

```bash
pnpm add @whisper-protocol/wallet-derived-keys
```

## Usage with Sui dApp Kit

```ts
import { useSignPersonalMessage, useCurrentAccount } from "@mysten/dapp-kit";
import {
  deriveFromWalletSigner,
  readCachedKeypair,
  writeCachedKeypair,
  makeCacheKey,
  canonicalMessageBytes,
} from "@whisper-protocol/wallet-derived-keys";
import { sha256 } from "@noble/hashes/sha256";

function useWhisperKeys() {
  const account = useCurrentAccount();
  const { mutateAsync: signPersonalMessage } = useSignPersonalMessage();

  return async () => {
    if (!account) throw new Error("No connected wallet");
    const message = { address: account.address, version: 1, scope: "root" };

    const cacheKey = {
      address: account.address,
      version: 1,
      scope: "root",
      canonicalMessageDigest: sha256(canonicalMessageBytes(message)),
    };

    const cached = await readCachedKeypair(cacheKey);
    if (cached) return cached;

    const keypair = await deriveFromWalletSigner(async (bytes) => {
      const { signature } = await signPersonalMessage({ message: bytes });
      // dApp Kit returns a base64 string; decode to bytes.
      return { signature: base64ToBytes(signature) };
    }, message);

    await writeCachedKeypair(cacheKey, keypair);
    return keypair;
  };
}
```

## What the SDK doesn't include

- **Signature verification.** This package consumes signatures, doesn't verify them.
- **Wallet connection.** Use [`@mysten/dapp-kit`](https://www.npmjs.com/package/@mysten/dapp-kit) or the Sui dApp Standard.
- **On-chain registration.** Use `@whisper-protocol/sdk`'s `buildRegisterKeyTx` to publish the derived public key.

## Threat model

This derivation gives "any-device decryption tied to wallet control". It does **not** give:

- **Forward secrecy.** A wallet compromise reveals every encryption key derivable under any version → every past message is decryptable. Add a Signal-style ratchet on top if you need this.
- **Phishing immunity.** A malicious dapp can ask the user to "sign in" with the same canonical message and steal the encryption key. The address-in-message is partial mitigation.
- **Deniability.** The keypair is wallet-attributable by construction.

See the spec for the full trade-off accounting.

## License

MIT.
