export {
  CURRENT_DERIVATION_VERSION,
  DERIVE_SIGNATURE_FEATURE_SCOPE,
  ROOT_SCOPE,
  WHISPER_PROTOCOL_NAME,
} from "./constants.js";

export {
  canonicalMessage,
  canonicalMessageBytes,
} from "./message.js";
export type { CanonicalMessageInput } from "./message.js";

export {
  deriveFromDeterministicSigner,
  deriveFromSignature,
  deriveFromWalletSigner,
} from "./derive.js";
export type { DerivedEncryptionKeypair } from "./derive.js";

export { deriveEncryptionKeypairFromWallet } from "./fromWallet.js";
export type {
  DerivationPath,
  DeriveFromWalletOptions,
  DeriveFromWalletResult,
  WalletStandardAccountLike,
  WalletStandardWalletLike,
} from "./fromWallet.js";

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
