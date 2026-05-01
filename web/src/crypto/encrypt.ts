import { x25519 } from "@noble/curves/ed25519";
import { hkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha256";
import { chacha20poly1305 } from "@noble/ciphers/chacha";
import { randomBytes } from "@noble/hashes/utils";
import type { Identity } from "./identities";
import { normalizeAddress } from "./identities";

const INFO = new TextEncoder().encode("sui-secret-sharing-poc-v1");

export const ENCRYPTION_SCHEME =
  "x25519-ed25519-derived+hkdf-sha256+chacha20poly1305";

export interface EncryptedPayload {
  ephPubkey: Uint8Array;
  nonce: Uint8Array;
  ciphertext: Uint8Array;
  encryptionScheme: string;
}

function deriveAeadKey(shared: Uint8Array, sender: string, recipient: string): Uint8Array {
  const salt = new TextEncoder().encode(`${sender}->${recipient}`);
  return hkdf(sha256, shared, salt, INFO, 32);
}

export function encryptForRecipient(
  sender: Identity,
  recipientPublicKey: Uint8Array,
  recipientAddress: string,
  plaintext: string,
): EncryptedPayload {
  const ephPriv = x25519.utils.randomPrivateKey();
  const ephPub = x25519.getPublicKey(ephPriv);
  const shared = x25519.getSharedSecret(ephPriv, recipientPublicKey);
  const senderHex = normalizeAddress(sender.suiAddress);
  const recipientHex = normalizeAddress(recipientAddress);
  const key = deriveAeadKey(shared, senderHex, recipientHex);
  const nonce = randomBytes(12);
  const cipher = chacha20poly1305(key, nonce);
  const ciphertext = cipher.encrypt(new TextEncoder().encode(plaintext));
  return {
    ephPubkey: ephPub,
    nonce,
    ciphertext,
    encryptionScheme: ENCRYPTION_SCHEME,
  };
}
