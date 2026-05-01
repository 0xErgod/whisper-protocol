export const MODULE = "secret_sharing";
export const CLOCK_ID = "0x6";
export const SCHEMA_TEXT_SECRET_V1 = "text_secret_v1";

export const HKDF_INFO = "sui-secret-sharing-poc-v1";

export const ENCRYPTION_SCHEME =
  "x25519-ed25519-derived+hkdf-sha256+chacha20poly1305";

// Bumped manually when wire-incompatible changes ship. The on-chain Move
// module exposes the same value via `protocol_version()` so the SDK can
// refuse to talk to a registry it doesn't understand.
export const SDK_PROTOCOL_VERSION = 1;
