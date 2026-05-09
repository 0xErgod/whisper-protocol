export { WhisperClient } from "./client.js";
export type {
  WhisperClientConfig,
  PrepareSendArgs,
  PreparedSend,
  PrepareSendMultiArgs,
  PreparedMultiSend,
  RecipientKeyResolution,
} from "./client.js";

export {
  encryptForRecipient,
  tryDecrypt,
  tryDecryptUtf8,
} from "./encrypt.js";
export type { EncryptedPayload, EncryptInput, DecryptInput } from "./encrypt.js";

export {
  encryptForRecipients,
  tryDecryptMulti,
  tryDecryptMultiUtf8,
} from "./encrypt-multi.js";
export type {
  MultiEncryptInput,
  MultiEncryptedPayload,
  MultiDecryptInput,
  MultiEncryptRecipient,
  MultiRecipientEncryptionSuite,
} from "./encrypt-multi.js";

export {
  buildPostEnvelopeTx,
  buildPostMultiEnvelopeTx,
  buildRegisterKeyTx,
} from "./tx.js";
export type {
  BuildPostEnvelopeArgs,
  BuildPostMultiEnvelopeArgs,
  BuildRegisterKeyArgs,
} from "./tx.js";

export {
  fetchRegistryEntries,
  fetchRegistryEntry,
  fetchEncryptionKeyRecord,
} from "./registry.js";
export type { RegistryEntry, EncryptionKeyRecord } from "./registry.js";

export {
  fetchEnvelope,
  fetchInbox,
  canReadEnvelope,
  assertCanReadEnvelope,
  decodeEnvelopeFields,
} from "./envelope.js";
export type { OnChainEnvelope } from "./envelope.js";

export {
  fetchMultiEnvelope,
  fetchMultiInbox,
  decodeMultiEnvelopeFields,
  recipientIndexInMultiEnvelope,
  canReadMultiEnvelope,
  assertCanReadMultiEnvelope,
} from "./multi-envelope.js";
export type { OnChainMultiEnvelope } from "./multi-envelope.js";

export {
  encodeTextSecret,
  commitmentHash,
  createCommitment,
  verifyOpening,
  buildCommitTx,
  buildOpenTx,
  decodeCommitmentFields,
  fetchCommitment,
} from "./commitments.js";
export type {
  OnChainCommitment,
  Opening,
  BuildCommitTxArgs,
  BuildOpenTxArgs,
} from "./commitments.js";

export { readOnChainProtocolVersion, assertWriteCompatible } from "./protocol.js";

export {
  UnsupportedEnvelopeFormatVersionError,
  UnsupportedEncryptionSchemeError,
  WriteCompatibilityError,
} from "./errors.js";

export { normalizeAddress, shortAddress } from "./address.js";

export {
  MODULE,
  MODULE_FACADE,
  MODULE_REGISTRY,
  MODULE_ENVELOPES,
  MODULE_MULTI_ENVELOPES,
  MODULE_COMMITMENTS,
  CLOCK_ID,
  SCHEMA_TEXT_SECRET_V1,
  SCHEMA_COMMITMENT_OPENING_V1,
  LEGACY_ENVELOPE_FORMAT_VERSION,
  CURRENT_ENVELOPE_FORMAT_VERSION,
  CURRENT_MULTI_ENVELOPE_FORMAT_VERSION,
  CURRENT_COMMITMENT_FORMAT_VERSION,
  MAX_RECIPIENTS,
  ENCRYPTION_SCHEME,
  ENCRYPTION_SCHEME_MULTI,
  HKDF_INFO,
  HKDF_INFO_MULTI_WRAP,
  HASH_SCHEME_BLAKE2B_256,
  COMMITMENT_DOMAIN_V1,
  SDK_PROTOCOL_VERSION,
} from "./constants.js";
