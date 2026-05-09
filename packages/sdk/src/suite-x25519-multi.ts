import { chacha20poly1305 } from "@noble/ciphers/chacha";
import { x25519 } from "@noble/curves/ed25519";
import { hkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha256";
import { randomBytes } from "@noble/hashes/utils";
import { normalizeAddress } from "./address.js";
import { ENCRYPTION_SCHEME_MULTI, HKDF_INFO_MULTI_WRAP } from "./constants.js";

const INFO_BYTES = new TextEncoder().encode(HKDF_INFO_MULTI_WRAP);

function deriveWrapKey(
  shared: Uint8Array,
  sender: string,
  recipient: string,
): Uint8Array {
  // Domain-separated from the v2 single-recipient AEAD-key derivation:
  // "wrap:" prefix means a v3 wrap key for (sender, recipient[i]) cannot
  // collide with a v2 envelope key for the same pair.
  const salt = new TextEncoder().encode(`wrap:${sender}->${recipient}`);
  return hkdf(sha256, shared, salt, INFO_BYTES, 32);
}

function asBytes(plaintext: Uint8Array | string): Uint8Array {
  return typeof plaintext === "string" ? new TextEncoder().encode(plaintext) : plaintext;
}

export interface MultiEncryptRecipient {
  address: string;
  publicKey: Uint8Array;
}

export interface MultiEncryptInput {
  encryptionScheme?: string;
  senderAddress: string;
  recipients: MultiEncryptRecipient[];
  plaintext: Uint8Array | string;
}

export interface MultiEncryptedPayload {
  encryptionScheme: string;
  ephPubkey: Uint8Array;
  payloadNonce: Uint8Array;
  ciphertext: Uint8Array;
  wrappedKeys: Uint8Array[];
  wrapNonces: Uint8Array[];
}

export interface MultiDecryptInput {
  encryptionScheme?: string;
  senderAddress: string;
  recipientAddress: string;
  recipientPrivateKey: Uint8Array;
  ephPubkey: Uint8Array;
  payloadNonce: Uint8Array;
  ciphertext: Uint8Array;
  wrappedKey: Uint8Array;
  wrapNonce: Uint8Array;
}

export interface MultiRecipientEncryptionSuite {
  id: string;
  encrypt(input: MultiEncryptInput): MultiEncryptedPayload;
  decrypt(input: MultiDecryptInput): Uint8Array | null;
}

export const x25519MultiSuite: MultiRecipientEncryptionSuite = {
  id: ENCRYPTION_SCHEME_MULTI,

  encrypt(input: MultiEncryptInput): MultiEncryptedPayload {
    if (input.recipients.length === 0) {
      throw new Error("multi-recipient encrypt requires at least one recipient");
    }
    const ephPriv = x25519.utils.randomPrivateKey();
    const ephPub = x25519.getPublicKey(ephPriv);
    const senderHex = normalizeAddress(input.senderAddress);

    // K_msg is random per envelope. The plaintext is encrypted once
    // under K_msg; K_msg is then wrapped separately for each recipient.
    const messageKey = randomBytes(32);
    const payloadNonce = randomBytes(12);
    const payloadCipher = chacha20poly1305(messageKey, payloadNonce);
    const ciphertext = payloadCipher.encrypt(asBytes(input.plaintext));

    const wrappedKeys: Uint8Array[] = [];
    const wrapNonces: Uint8Array[] = [];
    for (const recipient of input.recipients) {
      const recipientHex = normalizeAddress(recipient.address);
      const shared = x25519.getSharedSecret(ephPriv, recipient.publicKey);
      const wrapKey = deriveWrapKey(shared, senderHex, recipientHex);
      const wrapNonce = randomBytes(12);
      const wrapCipher = chacha20poly1305(wrapKey, wrapNonce);
      wrappedKeys.push(wrapCipher.encrypt(messageKey));
      wrapNonces.push(wrapNonce);
    }

    return {
      encryptionScheme: ENCRYPTION_SCHEME_MULTI,
      ephPubkey: ephPub,
      payloadNonce,
      ciphertext,
      wrappedKeys,
      wrapNonces,
    };
  },

  decrypt(input: MultiDecryptInput): Uint8Array | null {
    try {
      const senderHex = normalizeAddress(input.senderAddress);
      const recipientHex = normalizeAddress(input.recipientAddress);
      const shared = x25519.getSharedSecret(input.recipientPrivateKey, input.ephPubkey);
      const wrapKey = deriveWrapKey(shared, senderHex, recipientHex);
      const wrapCipher = chacha20poly1305(wrapKey, input.wrapNonce);
      const messageKey = wrapCipher.decrypt(input.wrappedKey);
      if (messageKey.length !== 32) return null;
      const payloadCipher = chacha20poly1305(messageKey, input.payloadNonce);
      return payloadCipher.decrypt(input.ciphertext);
    } catch {
      return null;
    }
  },
};
