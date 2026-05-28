// Public SDK surface. Re-exports the operations a dApp composes —
// nothing more, nothing less.

export { WhisperClient } from "./client.js";
export type {
  WhisperClientConfig,
  PrepareSendArgs,
  PreparedSend,
} from "./client.js";

export { seal, open, WhisperOpenError } from "./suite.js";
export type { Envelope, Payload, OpenError } from "./suite.js";

export {
  fetchEnvelope,
  decodeEnvelopeFields,
  envelopeFromOnChain,
} from "./envelope.js";
export type { OnChainEnvelope } from "./envelope.js";

export {
  commit,
  verifyOpening,
  fetchCommitment,
  decodeCommitmentFields,
} from "./commitments.js";
export type {
  OnChainCommitment,
  Opening,
  CommitmentResult,
} from "./commitments.js";

export {
  buildRegisterKeyTx,
  buildPostEnvelopeTx,
  buildCommitTx,
  buildOpenTx,
} from "./tx.js";
export type {
  BuildRegisterKeyArgs,
  BuildPostEnvelopeArgs,
  BuildCommitTxArgs,
  BuildOpenTxArgs,
} from "./tx.js";

export {
  fetchRegistryEntries,
  fetchRegistryEntry,
  fetchEncryptionKeyRecord,
} from "./registry.js";
export type { RegistryEntry, EncryptionKeyRecord } from "./registry.js";

export {
  deriveFromSignature,
  deriveFromWalletSigner,
  canonicalMessage,
  canonicalMessageBytes,
  canonicalMessageDigest,
  makeCacheKey,
  loadCached,
  saveCached,
} from "./wallet-keys.js";
export type {
  DerivedBabyJubKeypair,
  CanonicalMessageInput,
  CacheKeyInput,
} from "./wallet-keys.js";

export { readOnChainProtocolVersion, assertWriteCompatible } from "./protocol.js";

export { WriteCompatibilityError } from "./errors.js";

export { normalizeAddress, shortAddress } from "./address.js";

export {
  MODULE,
  MODULE_FACADE,
  MODULE_REGISTRY,
  MODULE_ENVELOPES,
  MODULE_COMMITMENTS,
  MODULE_PROOFS,
  CLOCK_ID,
  SDK_PROTOCOL_VERSION,
} from "./constants.js";

export { cryptoWasm } from "./wasm.js";
