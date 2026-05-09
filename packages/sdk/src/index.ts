export { WhisperClient } from "./client.js";
export type {
  WhisperClientConfig,
  PrepareSendArgs,
  PreparedSend,
  RecipientKeyResolution,
} from "./client.js";

export {
  encryptForRecipient,
  tryDecrypt,
  tryDecryptUtf8,
} from "./encrypt.js";
export type { EncryptedPayload, EncryptInput, DecryptInput } from "./encrypt.js";

export { buildPostEnvelopeTx, buildRegisterKeyTx } from "./tx.js";
export type { BuildPostEnvelopeArgs, BuildRegisterKeyArgs } from "./tx.js";

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

export { readOnChainProtocolVersion, assertWriteCompatible } from "./protocol.js";

export {
  UnsupportedEnvelopeFormatVersionError,
  UnsupportedEncryptionSchemeError,
  WriteCompatibilityError,
} from "./errors.js";

export { normalizeAddress, shortAddress } from "./address.js";

export {
  MODULE,
  CLOCK_ID,
  SCHEMA_TEXT_SECRET_V1,
  LEGACY_ENVELOPE_FORMAT_VERSION,
  CURRENT_ENVELOPE_FORMAT_VERSION,
  ENCRYPTION_SCHEME,
  HKDF_INFO,
  SDK_PROTOCOL_VERSION,
} from "./constants.js";
