import type { DerivedEncryptionKeypair } from "./derive.js";
import { bytesToHex, normalizeAddress } from "./utils.js";

/**
 * IndexedDB-backed cache of derived encryption keypairs.
 *
 * The cache key is `(address, scope, version, canonical-message-digest)`.
 * Including the message digest means any change to the canonical message
 * format invalidates old entries automatically.
 *
 * IndexedDB is origin-scoped but accessible to any script on the origin —
 * an XSS on the consumer dapp is sufficient to scrape this cache. The
 * cache exists for UX, not as a security boundary. See the trade-offs
 * section of the spec.
 *
 * Browser-only. In Node, callers should pass their own storage layer or
 * skip caching entirely.
 */

const DB_NAME = "whisper-keystore";
const STORE = "derived-keys";

interface CacheRecord {
  encryptionPrivateKey: Uint8Array;
  encryptionPublicKey: Uint8Array;
  canonicalMessage: string;
  canonicalMessageDigest: Uint8Array;
  derivedAtMs: number;
}

export interface CacheKeyInput {
  address: string;
  version: number;
  scope: string;
  canonicalMessageDigest: Uint8Array;
}

export function makeCacheKey(input: CacheKeyInput): string {
  return [
    normalizeAddress(input.address),
    input.scope,
    String(input.version),
    bytesToHex(input.canonicalMessageDigest),
  ].join("|");
}

function openDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    if (typeof indexedDB === "undefined") {
      reject(new Error("IndexedDB is not available in this environment"));
      return;
    }
    const req = indexedDB.open(DB_NAME, 1);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains(STORE)) {
        db.createObjectStore(STORE);
      }
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error ?? new Error("IndexedDB open failed"));
  });
}

export async function readCachedKeypair(
  key: CacheKeyInput,
): Promise<DerivedEncryptionKeypair | null> {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE, "readonly");
    const store = tx.objectStore(STORE);
    const req = store.get(makeCacheKey(key));
    req.onsuccess = () => {
      const v = req.result as CacheRecord | undefined;
      if (!v) {
        resolve(null);
        return;
      }
      resolve({
        encryptionPrivateKey: v.encryptionPrivateKey,
        encryptionPublicKey: v.encryptionPublicKey,
        canonicalMessage: v.canonicalMessage,
        canonicalMessageDigest: v.canonicalMessageDigest,
      });
    };
    req.onerror = () => reject(req.error ?? new Error("IndexedDB read failed"));
  });
}

export async function writeCachedKeypair(
  key: CacheKeyInput,
  keypair: DerivedEncryptionKeypair,
): Promise<void> {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE, "readwrite");
    const store = tx.objectStore(STORE);
    const record: CacheRecord = {
      encryptionPrivateKey: keypair.encryptionPrivateKey,
      encryptionPublicKey: keypair.encryptionPublicKey,
      canonicalMessage: keypair.canonicalMessage,
      canonicalMessageDigest: keypair.canonicalMessageDigest,
      derivedAtMs: Date.now(),
    };
    const req = store.put(record, makeCacheKey(key));
    req.onsuccess = () => resolve();
    req.onerror = () => reject(req.error ?? new Error("IndexedDB write failed"));
  });
}

export async function clearCachedKeypair(key: CacheKeyInput): Promise<void> {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE, "readwrite");
    const store = tx.objectStore(STORE);
    const req = store.delete(makeCacheKey(key));
    req.onsuccess = () => resolve();
    req.onerror = () => reject(req.error ?? new Error("IndexedDB delete failed"));
  });
}
