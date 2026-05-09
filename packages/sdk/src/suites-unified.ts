import { UnsupportedEncryptionSchemeError } from "./errors.js";
import {
  x25519UnifiedSuite,
  type UnifiedEncryptionSuite,
} from "./suite-x25519-unified.js";

const unifiedSuites = new Map<string, UnifiedEncryptionSuite>([
  [x25519UnifiedSuite.id, x25519UnifiedSuite],
]);

export function getUnifiedEncryptionSuite(
  encryptionScheme: string,
): UnifiedEncryptionSuite | null {
  return unifiedSuites.get(encryptionScheme) ?? null;
}

export function requireUnifiedEncryptionSuite(
  encryptionScheme: string,
): UnifiedEncryptionSuite {
  const suite = getUnifiedEncryptionSuite(encryptionScheme);
  if (!suite) throw new UnsupportedEncryptionSchemeError(encryptionScheme);
  return suite;
}

export function supportsUnifiedEncryptionScheme(encryptionScheme: string): boolean {
  return unifiedSuites.has(encryptionScheme);
}
