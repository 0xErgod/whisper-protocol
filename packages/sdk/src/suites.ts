import { UnsupportedEncryptionSchemeError } from "./errors.js";
import { x25519DerivedSuite } from "./suite-x25519.js";
import type { DecryptInput, EncryptInput, EncryptedPayload } from "./encrypt.js";

export interface EncryptionSuite {
  id: string;
  encrypt(input: EncryptInput): EncryptedPayload;
  decrypt(input: DecryptInput): Uint8Array | null;
}

const suites = new Map<string, EncryptionSuite>([
  [x25519DerivedSuite.id, x25519DerivedSuite],
]);

export function getEncryptionSuite(encryptionScheme: string): EncryptionSuite | null {
  return suites.get(encryptionScheme) ?? null;
}

export function requireEncryptionSuite(encryptionScheme: string): EncryptionSuite {
  const suite = getEncryptionSuite(encryptionScheme);
  if (!suite) throw new UnsupportedEncryptionSchemeError(encryptionScheme);
  return suite;
}

export function supportsEncryptionScheme(encryptionScheme: string): boolean {
  return suites.has(encryptionScheme);
}
