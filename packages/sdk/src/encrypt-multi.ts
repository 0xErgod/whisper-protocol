import { ENCRYPTION_SCHEME_MULTI } from "./constants.js";
import {
  getMultiEncryptionSuite,
  requireMultiEncryptionSuite,
} from "./suites-multi.js";
import type {
  MultiDecryptInput,
  MultiEncryptInput,
  MultiEncryptedPayload,
} from "./suite-x25519-multi.js";

export type {
  MultiDecryptInput,
  MultiEncryptInput,
  MultiEncryptedPayload,
  MultiEncryptRecipient,
  MultiRecipientEncryptionSuite,
} from "./suite-x25519-multi.js";

export function encryptForRecipients(input: MultiEncryptInput): MultiEncryptedPayload {
  const encryptionScheme = input.encryptionScheme ?? ENCRYPTION_SCHEME_MULTI;
  return requireMultiEncryptionSuite(encryptionScheme).encrypt({
    ...input,
    encryptionScheme,
  });
}

export function tryDecryptMulti(input: MultiDecryptInput): Uint8Array | null {
  const encryptionScheme = input.encryptionScheme ?? ENCRYPTION_SCHEME_MULTI;
  const suite = getMultiEncryptionSuite(encryptionScheme);
  if (!suite) return null;
  return suite.decrypt({
    ...input,
    encryptionScheme,
  });
}

export function tryDecryptMultiUtf8(input: MultiDecryptInput): string | null {
  const bytes = tryDecryptMulti(input);
  return bytes === null ? null : new TextDecoder().decode(bytes);
}
