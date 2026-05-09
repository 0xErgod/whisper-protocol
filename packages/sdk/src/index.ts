export { WhisperClient } from "./client.js";
export type {
  WhisperClientConfig,
  PrepareSendV5Args,
  PreparedSendV5,
  RecipientKeyResolution,
} from "./client.js";

export {
  encryptForRecipientsV5,
  tryDecryptV5,
  tryDecryptV5Utf8,
} from "./encrypt-unified.js";
export type {
  UnifiedEncryptInput,
  UnifiedEncryptedPayload,
  UnifiedDecryptInput,
  UnifiedEncryptRecipient,
  UnifiedEncryptionSuite,
} from "./encrypt-unified.js";

export {
  buildPostV5EnvelopeTx,
  buildRegisterKeyTx,
} from "./tx.js";
export type {
  BuildPostV5EnvelopeArgs,
  BuildRegisterKeyArgs,
} from "./tx.js";

export {
  fetchRegistryEntries,
  fetchRegistryEntry,
  fetchEncryptionKeyRecord,
} from "./registry.js";
export type { RegistryEntry, EncryptionKeyRecord } from "./registry.js";

export {
  fetchV5Envelope,
  fetchV5Inbox,
  decodeV5EnvelopeFieldsTyped,
  recipientIndexInV5Envelope,
  canReadV5Envelope,
  assertCanReadV5Envelope,
} from "./envelope-unified.js";
export type { OnChainV5Envelope } from "./envelope-unified.js";

// Historical envelope decoders for v1/v2 (single-recipient owned)
// envelopes from prior deployments. The SDK no longer produces
// envelopes under this shape; this is read-only legacy support.
export {
  fetchEnvelope as fetchLegacyV2Envelope,
  decodeEnvelopeFields as decodeLegacyV2EnvelopeFields,
} from "./envelope.js";
export type { OnChainEnvelope as OnChainLegacyV2Envelope } from "./envelope.js";

export {
  encodeTextSecret,
  commitmentHash,
  createCommitment,
  verifyOpening,
  buildCommitTx,
  buildOpenTx,
  decodeCommitmentFields,
  fetchCommitment,
  encodeOpeningPlaintext,
  decodeOpeningPlaintext,
  prepareCommitWithSelfOpening,
  loadOpeningForCommitment,
} from "./commitments.js";
export type {
  OnChainCommitment,
  Opening,
  BuildCommitTxArgs,
  BuildOpenTxArgs,
  OpeningPayloadV1,
  PrepareCommitWithSelfOpeningArgs,
  PreparedCommitWithSelfOpening,
} from "./commitments.js";

export { readOnChainProtocolVersion, assertWriteCompatible } from "./protocol.js";

export {
  UnsupportedEnvelopeFormatVersionError,
  UnsupportedEncryptionSchemeError,
  UnsupportedHashSchemeError,
  WriteCompatibilityError,
} from "./errors.js";

export { poseidonCommitmentHash, MAX_POSEIDON_SECRET_BYTES } from "./hash-poseidon.js";

export { normalizeAddress, shortAddress } from "./address.js";

export {
  MODULE,
  MODULE_FACADE,
  MODULE_REGISTRY,
  MODULE_ENVELOPES,
  MODULE_COMMITMENTS,
  CLOCK_ID,
  SCHEMA_TEXT_SECRET_V1,
  SCHEMA_COMMITMENT_OPENING_V1,
  LEGACY_ENVELOPE_FORMAT_VERSION,
  ENVELOPE_FORMAT_VERSION_V2,
  ENVELOPE_FORMAT_VERSION_V3,
  CURRENT_ENVELOPE_FORMAT_VERSION,
  CURRENT_COMMITMENT_FORMAT_VERSION,
  MAX_RECIPIENTS,
  ENCRYPTION_SCHEME,
  ENCRYPTION_SCHEME_MULTI,
  ENCRYPTION_SCHEME_UNIFIED,
  HKDF_INFO,
  HKDF_INFO_WRAP,
  HASH_SCHEME_BLAKE2B_256,
  HASH_SCHEME_POSEIDON_BN254_CIRCOMLIB_V1,
  COMMITMENT_DOMAIN_V1,
  SDK_PROTOCOL_VERSION,
} from "./constants.js";
