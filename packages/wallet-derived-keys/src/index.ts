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

export {
  SUI_SIGNATURE_FLAGS,
  suiAddressFromPublicKey,
  detectSchemeFromAccount,
  requireEd25519,
} from "./scheme.js";
export type { SuiSignatureScheme } from "./scheme.js";
