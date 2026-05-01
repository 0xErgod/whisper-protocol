import { x25519 } from "@noble/curves/ed25519";
import { hkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha256";
import { chacha20poly1305 } from "@noble/ciphers/chacha";
import { randomBytes } from "@noble/hashes/utils";
import { normalizeAddress } from "./address.js";
import { ENCRYPTION_SCHEME, HKDF_INFO } from "./constants.js";

const INFO_BYTES = new TextEncoder().encode(HKDF_INFO);

export interface EncryptedPayload {
  ephPubkey: Uint8Array;
  nonce: Uint8Array;
  ciphertext: Uint8Array;
  encryptionScheme: string;
}

export interface DecryptInput {
  recipientPrivateKey: Uint8Array;
  senderAddress: string;
  recipientAddress: string;
  ephPubkey: Uint8Array;
  nonce: Uint8Array;
  ciphertext: Uint8Array;
}

export interface EncryptInput {
  senderAddress: string;
  recipientAddress: string;
  recipientPublicKey: Uint8Array;
  plaintext: Uint8Array | string;
}

function deriveAeadKey(shared: Uint8Array, sender: string, recipient: string): Uint8Array {
  const salt = new TextEncoder().encode(`${sender}->${recipient}`);
  return hkdf(sha256, shared, salt, INFO_BYTES, 32);
}

function asBytes(plaintext: Uint8Array | string): Uint8Array {
  return typeof plaintext === "string" ? new TextEncoder().encode(plaintext) : plaintext;
}

export function encryptForRecipient(input: EncryptInput): EncryptedPayload {
  const ephPriv = x25519.utils.randomPrivateKey();
  const ephPub = x25519.getPublicKey(ephPriv);
  const shared = x25519.getSharedSecret(ephPriv, input.recipientPublicKey);
  const senderHex = normalizeAddress(input.senderAddress);
  const recipientHex = normalizeAddress(input.recipientAddress);
  const key = deriveAeadKey(shared, senderHex, recipientHex);
  const nonce = randomBytes(12);
  const cipher = chacha20poly1305(key, nonce);
  const ciphertext = cipher.encrypt(asBytes(input.plaintext));
  return {
    ephPubkey: ephPub,
    nonce,
    ciphertext,
    encryptionScheme: ENCRYPTION_SCHEME,
  };
}

export function tryDecrypt(input: DecryptInput): Uint8Array | null {
  try {
    const shared = x25519.getSharedSecret(input.recipientPrivateKey, input.ephPubkey);
    const senderHex = normalizeAddress(input.senderAddress);
    const recipientHex = normalizeAddress(input.recipientAddress);
    const key = deriveAeadKey(shared, senderHex, recipientHex);
    const cipher = chacha20poly1305(key, input.nonce);
    return cipher.decrypt(input.ciphertext);
  } catch {
    return null;
  }
}

export function tryDecryptUtf8(input: DecryptInput): string | null {
  const bytes = tryDecrypt(input);
  return bytes === null ? null : new TextDecoder().decode(bytes);
}
