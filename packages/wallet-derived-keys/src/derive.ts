import { x25519 } from "@noble/curves/ed25519";
import { hkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha256";
import {
  canonicalMessage,
  canonicalMessageBytes,
} from "./message.js";
import type { CanonicalMessageInput } from "./message.js";

const SALT = new TextEncoder().encode("whisper/v1/encryption-keypair");
const INFO = new TextEncoder().encode("x25519");

export interface DerivedEncryptionKeypair {
  /** 32-byte X25519 private key (already clamped). */
  encryptionPrivateKey: Uint8Array;
  /** 32-byte X25519 public key. */
  encryptionPublicKey: Uint8Array;
  /** The signed canonical message bytes (handy for debugging / receipts). */
  canonicalMessage: string;
  /** SHA-256 of the canonical message bytes — used as a cache key. */
  canonicalMessageDigest: Uint8Array;
}

/**
 * Pure derivation. Takes the raw signature bytes the wallet returned and
 * produces the X25519 keypair via HKDF-SHA256.
 *
 * **Treat the signature bytes as long-lived high-value secret key material.**
 * Do not log, do not transmit, do not persist. Pass them in here, get the
 * derived keypair out, drop the signature reference. See the trade-offs
 * section of the spec for the threat model.
 */
export function deriveFromSignature(
  signatureBytes: Uint8Array,
  message: CanonicalMessageInput,
): DerivedEncryptionKeypair {
  const seed = hkdf(sha256, signatureBytes, SALT, INFO, 32);

  // x25519 private keys are clamped 32-byte scalars. @noble/curves accepts
  // raw 32-byte input and clamps internally, so we don't need to clamp by
  // hand before deriving the public key.
  const encryptionPrivateKey = seed;
  const encryptionPublicKey = x25519.getPublicKey(encryptionPrivateKey);
  const canonical = canonicalMessage(message);
  const digest = sha256(canonicalMessageBytes(message));

  return {
    encryptionPrivateKey,
    encryptionPublicKey,
    canonicalMessage: canonical,
    canonicalMessageDigest: digest,
  };
}

/**
 * Wallet abstraction: supply a function that produces a personal-message
 * signature, and this helper builds the canonical message, calls the
 * signer, and runs HKDF.
 *
 * The signer should:
 *   - Use Ed25519 (Sui default).
 *   - Sign with `signPersonalMessage` semantics — the wallet is expected
 *     to wrap the bytes in Sui's `PersonalMessage` intent prefix before
 *     signing.
 *   - Be deterministic on `(privateKey, message)`.
 *
 * Non-Ed25519 wallets are not supported. Gate on `keypair.getKeyScheme()`
 * before calling this.
 */
export async function deriveFromWalletSigner(
  signer: (messageBytes: Uint8Array) => Promise<{ signature: Uint8Array }>,
  message: CanonicalMessageInput,
): Promise<DerivedEncryptionKeypair> {
  const messageBytes = canonicalMessageBytes(message);
  const { signature } = await signer(messageBytes);
  return deriveFromSignature(signature, message);
}

/**
 * Deterministic-sign wallet abstraction (e.g. EVE Vault's
 * `misc:deriveSignature` feature).
 *
 * This path exists because zkLogin wallets can't sign personal messages
 * deterministically — the user signature is produced by an ephemeral
 * keypair that rotates every session, so the resulting bytes drift.
 * Wallets that expose a deterministic-sign feature derive a stable
 * Ed25519 sub-key per `(user, scope)` and sign with it instead.
 *
 * The signer should:
 *   - Be byte-deterministic for `(identity, scope, message)` — same input
 *     produces the same signature across sessions and devices.
 *   - Wrap the dApp-supplied bytes in a wallet-controlled canonical
 *     envelope before signing (so the resulting signature can't be
 *     replayed as a transaction). The wallet returns the wrapped bytes
 *     it actually signed; we HKDF the signature only — the wrapped
 *     bytes are surfaced in the result for receipts/debugging.
 *
 * The HKDF salt/info are identical to `deriveFromSignature`, so the only
 * difference between paths is which signature bytes feed the HKDF. That
 * means the X25519 keypair derived via the deterministic-sign path will
 * NOT match the keypair a user previously derived via the
 * personal-message path — these are two different wallets producing
 * different signatures. That's intentional: keys are pinned to their
 * derivation path, not portable across paths.
 */
export async function deriveFromDeterministicSigner(
  signer: (
    scope: string,
    messageBytes: Uint8Array,
  ) => Promise<{ signature: Uint8Array }>,
  message: CanonicalMessageInput,
  scope: string,
): Promise<DerivedEncryptionKeypair> {
  const messageBytes = canonicalMessageBytes(message);
  const { signature } = await signer(scope, messageBytes);
  return deriveFromSignature(signature, message);
}
