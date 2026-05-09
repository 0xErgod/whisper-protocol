import { chacha20poly1305 } from "@noble/ciphers/chacha";
import { x25519 } from "@noble/curves/ed25519";
import { hkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha256";
import { randomBytes } from "@noble/hashes/utils";
import { normalizeAddress } from "./address.js";
import { ENCRYPTION_SCHEME_UNIFIED, HKDF_INFO_WRAP } from "./constants.js";

const INFO_BYTES = new TextEncoder().encode(HKDF_INFO_WRAP);

function deriveWrapKey(
  shared: Uint8Array,
  sender: string,
  recipient: string,
): Uint8Array {
  // Domain-separated from every prior envelope key derivation:
  //   v2 used "<sender>-><recipient>"
  //   v3 used "wrap:<sender>-><recipient>" with HKDF_INFO_MULTI_WRAP
  //   v5 uses "wrap:<sender>-><recipient>" with HKDF_INFO_WRAP
  // The info string difference cleanly separates v3 and v5 wrap keys
  // for the same (sender, recipient) pair, so historical v3 envelopes
  // remain decryptable under their own suite without colliding with
  // v5 suite outputs.
  const salt = new TextEncoder().encode(`wrap:${sender}->${recipient}`);
  return hkdf(sha256, shared, salt, INFO_BYTES, 32);
}

function asBytes(plaintext: Uint8Array | string): Uint8Array {
  return typeof plaintext === "string" ? new TextEncoder().encode(plaintext) : plaintext;
}

export interface UnifiedEncryptRecipient {
  address: string;
  publicKey: Uint8Array;
}

export interface UnifiedEncryptInput {
  encryptionScheme?: string;
  senderAddress: string;
  recipients: UnifiedEncryptRecipient[];
  plaintext: Uint8Array | string;
}

export interface UnifiedEncryptedPayload {
  encryptionScheme: string;
  ephPubkey: Uint8Array;
  payloadNonce: Uint8Array;
  ciphertext: Uint8Array;
  wrappedKeys: Uint8Array[];
  wrapNonces: Uint8Array[];
}

export interface UnifiedDecryptInput {
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

export interface UnifiedEncryptionSuite {
  id: string;
  encrypt(input: UnifiedEncryptInput): UnifiedEncryptedPayload;
  decrypt(input: UnifiedDecryptInput): Uint8Array | null;
}

/**
 * Hybrid construction used by every v5 envelope, including N=1.
 *
 * The N=1 case is intentionally NOT special-cased: a degenerate
 * one-recipient group is the same primitive as a multi-recipient
 * group. The slight extra work (one HKDF + one AEAD on a 32-byte
 * message key) is the price of having one cryptographic suite
 * instead of two.
 */
export const x25519UnifiedSuite: UnifiedEncryptionSuite = {
  id: ENCRYPTION_SCHEME_UNIFIED,

  encrypt(input: UnifiedEncryptInput): UnifiedEncryptedPayload {
    if (input.recipients.length === 0) {
      throw new Error("v5 envelope encrypt requires at least one recipient");
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
      encryptionScheme: ENCRYPTION_SCHEME_UNIFIED,
      ephPubkey: ephPub,
      payloadNonce,
      ciphertext,
      wrappedKeys,
      wrapNonces,
    };
  },

  decrypt(input: UnifiedDecryptInput): Uint8Array | null {
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
