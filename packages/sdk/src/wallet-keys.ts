// Derive a Baby Jubjub keypair from a wallet's deterministic signature.
//
// The canonical-message scheme is preserved byte-for-byte from the
// previous wallet-key derivation: protocol name, version, purpose,
// address, scope, joined with LF and no trailing newline. What
// changes is the output — a BJJ keypair, derived by feeding the
// signature bytes straight into `crypto_wasm.keypair_from_seed`.
//
// **Why no intermediate key-derivation step.** Ed25519 signatures
// are 64 bytes — exactly the seed width `keypair_from_seed` accepts —
// and the canonical message we sign already pins the protocol name
// in its first line, so signatures over our messages cannot collide
// with another protocol that uses the same wallet. The signature
// bytes ARE the seed.
//
// Caching: IndexedDB-backed when `indexedDB` is in scope (the
// browser), no-op in Node tests. Cache key includes the canonical-
// message digest so any format change invalidates entries
// automatically. The digest itself is computed via Poseidon over
// the message bytes — keeps every cryptographic primitive on the
// BJJ + Poseidon stack.

import { cryptoWasm } from "./wasm.js";

// Identifier embedded as the first line of the canonical message.
const WHISPER_PROTOCOL_NAME = "whisper-protocol";

// Current canonical-message version. Bumping is the documented way
// to rotate keys forward without breaking past envelopes (which
// remain decryptable by re-deriving with the old version).
const CURRENT_DERIVATION_VERSION = 1;

// Scope tag for the default per-wallet keypair. Future per-conversation
// derivations would use scopes like `dm:0xabc...`.
const ROOT_SCOPE = "root";

/** Domain tag for the canonical-message digest used as a cache key. */
const CACHE_DIGEST_DOMAIN = "wallet-key-cache-digest";

/** Required signature length in bytes (Ed25519). */
const SIGNATURE_BYTES = 64;

export interface CanonicalMessageInput {
  /** Sui address of the wallet. Lowercased and `0x`-prefixed inside. */
  address: string;
  /** Defaults to `CURRENT_DERIVATION_VERSION`. */
  version?: number;
  /** Defaults to `ROOT_SCOPE`. */
  scope?: string;
  /** Defaults to "encryption-keypair". */
  purpose?: string;
}

export interface DerivedBabyJubKeypair {
  /** Public-key x coordinate, decimal string (matches crypto-wasm's wire form). */
  pubkeyX: string;
  /** Public-key y coordinate, decimal string. */
  pubkeyY: string;
  /**
   * The 64-byte BJJ seed (the wallet signature bytes verbatim).
   * Treat as long-lived secret key material.
   */
  seed: Uint8Array;
  /** The signed canonical message bytes (handy for debugging / receipts). */
  canonicalMessage: string;
  /** Poseidon digest of the canonical message — used as a cache key. */
  canonicalMessageDigest: string;
}

function normalizeAddress(addr: string): string {
  if (!addr) return addr;
  const lower = addr.toLowerCase();
  return lower.startsWith("0x") ? lower : `0x${lower}`;
}

export function canonicalMessage(input: CanonicalMessageInput): string {
  const address = normalizeAddress(input.address);
  const version = input.version ?? CURRENT_DERIVATION_VERSION;
  const scope = input.scope ?? ROOT_SCOPE;
  const purpose = input.purpose ?? "encryption-keypair";
  return [
    WHISPER_PROTOCOL_NAME,
    `version: ${version}`,
    `purpose: ${purpose}`,
    `address: ${address}`,
    `scope: ${scope}`,
  ].join("\n");
}

export function canonicalMessageBytes(input: CanonicalMessageInput): Uint8Array {
  return new TextEncoder().encode(canonicalMessage(input));
}

/**
 * Compute the cache-key digest for a canonical message. Exposed so
 * callers that want to probe the cache (without performing a real
 * derivation) can compute the same key the SDK would store under.
 */
export function canonicalMessageDigest(message: CanonicalMessageInput): string {
  return poseidonDigestOfBytes(CACHE_DIGEST_DOMAIN, canonicalMessageBytes(message));
}

/**
 * Hash a byte string to a single `Fq` element by chunking it into
 * 31-byte big-endian field elements and feeding them through the
 * Poseidon sponge under the supplied domain tag. 31 bytes is the
 * largest big-endian chunk that fits unambiguously in BN254's base
 * field. Used for the cache-key digest.
 */
function poseidonDigestOfBytes(domain: string, bytes: Uint8Array): string {
  const chunks: string[] = [];
  for (let i = 0; i < bytes.length; i += 31) {
    const slice = bytes.subarray(i, Math.min(i + 31, bytes.length));
    // Pad to 31 bytes with leading zeros so the chunk encodes its
    // numeric value unambiguously (length isn't otherwise carried —
    // a trailing partial chunk that happens to start with 0x00 would
    // collide with a full chunk of zeros).
    let acc = 0n;
    for (const b of slice) {
      acc = (acc << 8n) | BigInt(b);
    }
    chunks.push(acc.toString(10));
  }
  // Include the byte length as a final element so two messages
  // differing only by trailing zero bytes hash differently.
  chunks.push(bytes.length.toString(10));
  const domainTag = cryptoWasm.domain_tag(domain);
  return cryptoWasm.poseidon_hash_sponge(domainTag, chunks);
}

/**
 * Pure derivation. Takes the raw signature bytes the wallet returned and
 * produces a Baby Jubjub keypair via `crypto_wasm.keypair_from_seed`.
 *
 * **Treat the signature bytes as long-lived high-value secret key material.**
 * Do not log, do not transmit, do not persist. Pass them in here, get the
 * derived keypair out, drop the signature reference.
 */
export function deriveFromSignature(
  signatureBytes: Uint8Array,
  message: CanonicalMessageInput,
): DerivedBabyJubKeypair {
  if (signatureBytes.length !== SIGNATURE_BYTES) {
    throw new Error(
      `wallet signature must be exactly ${SIGNATURE_BYTES} bytes (Ed25519), got ${signatureBytes.length}`,
    );
  }
  const keypair = cryptoWasm.keypair_from_seed(signatureBytes);
  const canonical = canonicalMessage(message);
  const digest = canonicalMessageDigest(message);
  return {
    pubkeyX: keypair.pk_x,
    pubkeyY: keypair.pk_y,
    seed: signatureBytes,
    canonicalMessage: canonical,
    canonicalMessageDigest: digest,
  };
}

/**
 * Wallet abstraction: supply a function that produces a personal-message
 * signature, and this helper builds the canonical message, calls the
 * signer, and runs the derivation.
 */
export async function deriveFromWalletSigner(
  signer: (messageBytes: Uint8Array) => Promise<{ signature: Uint8Array }>,
  message: CanonicalMessageInput,
): Promise<DerivedBabyJubKeypair> {
  const messageBytes = canonicalMessageBytes(message);
  const { signature } = await signer(messageBytes);
  return deriveFromSignature(signature, message);
}

// --- IndexedDB cache --------------------------------------------------
//
// Keyed by `(address, scope, version, canonical-message-digest)`. The
// digest in the key means any change to the canonical message format
// invalidates old entries automatically. Browser-only; Node sees the
// cache as empty.

const DB_NAME = "whisper-keystore";
const STORE = "babyjub-derived-keys";

interface CacheRecord {
  seed: Uint8Array;
  pubkeyX: string;
  pubkeyY: string;
  canonicalMessage: string;
  canonicalMessageDigest: string;
  derivedAtMs: number;
}

export interface CacheKeyInput {
  address: string;
  version: number;
  scope: string;
  canonicalMessageDigest: string;
}

export function makeCacheKey(input: CacheKeyInput): string {
  return [
    normalizeAddress(input.address),
    input.scope,
    String(input.version),
    input.canonicalMessageDigest,
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
    req.onerror = () => reject(req.error);
  });
}

export async function loadCached(
  key: CacheKeyInput,
): Promise<DerivedBabyJubKeypair | null> {
  if (typeof indexedDB === "undefined") return null;
  const db = await openDb();
  return new Promise<DerivedBabyJubKeypair | null>((resolve, reject) => {
    const tx = db.transaction(STORE, "readonly");
    const store = tx.objectStore(STORE);
    const req = store.get(makeCacheKey(key));
    req.onsuccess = () => {
      const rec = req.result as CacheRecord | undefined;
      if (!rec) {
        resolve(null);
        return;
      }
      resolve({
        seed: rec.seed,
        pubkeyX: rec.pubkeyX,
        pubkeyY: rec.pubkeyY,
        canonicalMessage: rec.canonicalMessage,
        canonicalMessageDigest: rec.canonicalMessageDigest,
      });
    };
    req.onerror = () => reject(req.error);
  });
}

export async function saveCached(
  key: CacheKeyInput,
  value: DerivedBabyJubKeypair,
): Promise<void> {
  if (typeof indexedDB === "undefined") return;
  const db = await openDb();
  await new Promise<void>((resolve, reject) => {
    const tx = db.transaction(STORE, "readwrite");
    const store = tx.objectStore(STORE);
    const rec: CacheRecord = {
      seed: value.seed,
      pubkeyX: value.pubkeyX,
      pubkeyY: value.pubkeyY,
      canonicalMessage: value.canonicalMessage,
      canonicalMessageDigest: value.canonicalMessageDigest,
      derivedAtMs: Date.now(),
    };
    const req = store.put(rec, makeCacheKey(key));
    req.onsuccess = () => resolve();
    req.onerror = () => reject(req.error);
  });
}
