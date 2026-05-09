import { UnsupportedEncryptionSchemeError } from "./errors.js";
import {
  x25519MultiSuite,
  type MultiRecipientEncryptionSuite,
} from "./suite-x25519-multi.js";

const multiSuites = new Map<string, MultiRecipientEncryptionSuite>([
  [x25519MultiSuite.id, x25519MultiSuite],
]);

export function getMultiEncryptionSuite(
  encryptionScheme: string,
): MultiRecipientEncryptionSuite | null {
  return multiSuites.get(encryptionScheme) ?? null;
}

export function requireMultiEncryptionSuite(
  encryptionScheme: string,
): MultiRecipientEncryptionSuite {
  const suite = getMultiEncryptionSuite(encryptionScheme);
  if (!suite) throw new UnsupportedEncryptionSchemeError(encryptionScheme);
  return suite;
}

export function supportsMultiEncryptionScheme(encryptionScheme: string): boolean {
  return multiSuites.has(encryptionScheme);
}
