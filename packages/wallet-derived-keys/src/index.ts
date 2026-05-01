export {
  canonicalMessage,
  canonicalMessageBytes,
} from "./message.js";
export type { CanonicalMessageInput } from "./message.js";

export {
  deriveFromSignature,
  deriveFromWalletSigner,
} from "./derive.js";
export type { DerivedEncryptionKeypair } from "./derive.js";

export {
  makeCacheKey,
  readCachedKeypair,
  writeCachedKeypair,
  clearCachedKeypair,
} from "./cache.js";
export type { CacheKeyInput } from "./cache.js";
