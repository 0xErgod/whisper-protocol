import { ENCRYPTION_SCHEME_UNIFIED } from "./constants.js";
import {
  getUnifiedEncryptionSuite,
  requireUnifiedEncryptionSuite,
} from "./suites-unified.js";
import type {
  UnifiedDecryptInput,
  UnifiedEncryptInput,
  UnifiedEncryptedPayload,
} from "./suite-x25519-unified.js";

export type {
  UnifiedDecryptInput,
  UnifiedEncryptInput,
  UnifiedEncryptedPayload,
  UnifiedEncryptRecipient,
  UnifiedEncryptionSuite,
} from "./suite-x25519-unified.js";

export function encryptForRecipientsV5(input: UnifiedEncryptInput): UnifiedEncryptedPayload {
  const encryptionScheme = input.encryptionScheme ?? ENCRYPTION_SCHEME_UNIFIED;
  return requireUnifiedEncryptionSuite(encryptionScheme).encrypt({
    ...input,
    encryptionScheme,
  });
}

export function tryDecryptV5(input: UnifiedDecryptInput): Uint8Array | null {
  const encryptionScheme = input.encryptionScheme ?? ENCRYPTION_SCHEME_UNIFIED;
  const suite = getUnifiedEncryptionSuite(encryptionScheme);
  if (!suite) return null;
  return suite.decrypt({
    ...input,
    encryptionScheme,
  });
}

export function tryDecryptV5Utf8(input: UnifiedDecryptInput): string | null {
  const bytes = tryDecryptV5(input);
  return bytes === null ? null : new TextDecoder().decode(bytes);
}
