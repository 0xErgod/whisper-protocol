import { ENCRYPTION_SCHEME } from "./constants.js";
import { getEncryptionSuite, requireEncryptionSuite } from "./suites.js";

export interface EncryptedPayload {
  ephPubkey: Uint8Array;
  nonce: Uint8Array;
  ciphertext: Uint8Array;
  encryptionScheme: string;
}

export interface DecryptInput {
  encryptionScheme?: string;
  recipientPrivateKey: Uint8Array;
  senderAddress: string;
  recipientAddress: string;
  ephPubkey: Uint8Array;
  nonce: Uint8Array;
  ciphertext: Uint8Array;
}

export interface EncryptInput {
  encryptionScheme?: string;
  senderAddress: string;
  recipientAddress: string;
  recipientPublicKey: Uint8Array;
  plaintext: Uint8Array | string;
}

export function encryptForRecipient(input: EncryptInput): EncryptedPayload {
  const encryptionScheme = input.encryptionScheme ?? ENCRYPTION_SCHEME;
  return requireEncryptionSuite(encryptionScheme).encrypt({
    ...input,
    encryptionScheme,
  });
}

export function tryDecrypt(input: DecryptInput): Uint8Array | null {
  const encryptionScheme = input.encryptionScheme ?? ENCRYPTION_SCHEME;
  const suite = getEncryptionSuite(encryptionScheme);
  if (!suite) return null;
  return suite.decrypt({
    ...input,
    encryptionScheme,
  });
}

export function tryDecryptUtf8(input: DecryptInput): string | null {
  const bytes = tryDecrypt(input);
  return bytes === null ? null : new TextDecoder().decode(bytes);
}
