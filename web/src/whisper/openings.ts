import { bytesToHex, hexToBytes } from "@noble/hashes/utils";

const STORAGE_KEY_PREFIX = "whisper:opening:";

export interface StoredOpening {
  encodedSecret: Uint8Array;
  salt: Uint8Array;
  commitment: Uint8Array;
  plaintext: string;
}

interface SerializedOpening {
  encodedSecretHex: string;
  saltHex: string;
  commitmentHex: string;
  plaintext: string;
}

function storageKey(commitmentId: string): string {
  return `${STORAGE_KEY_PREFIX}${commitmentId}`;
}

export function saveOpening(commitmentId: string, opening: StoredOpening): void {
  try {
    const serialized: SerializedOpening = {
      encodedSecretHex: bytesToHex(opening.encodedSecret),
      saltHex: bytesToHex(opening.salt),
      commitmentHex: bytesToHex(opening.commitment),
      plaintext: opening.plaintext,
    };
    localStorage.setItem(storageKey(commitmentId), JSON.stringify(serialized));
  } catch {
    // Best-effort: private mode / quota errors silently drop the
    // opening. The commitment becomes unrecoverable, which the caller
    // should warn about in the UI eventually.
  }
}

export function loadOpening(commitmentId: string): StoredOpening | null {
  try {
    const raw = localStorage.getItem(storageKey(commitmentId));
    if (!raw) return null;
    const parsed = JSON.parse(raw) as SerializedOpening;
    return {
      encodedSecret: hexToBytes(parsed.encodedSecretHex),
      salt: hexToBytes(parsed.saltHex),
      commitment: hexToBytes(parsed.commitmentHex),
      plaintext: parsed.plaintext,
    };
  } catch {
    return null;
  }
}

export function forgetOpening(commitmentId: string): void {
  try {
    localStorage.removeItem(storageKey(commitmentId));
  } catch {
    // ignored
  }
}
