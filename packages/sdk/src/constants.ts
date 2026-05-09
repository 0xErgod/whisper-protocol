export const MODULE = "secret_sharing";
export const CLOCK_ID = "0x6";
export const SCHEMA_TEXT_SECRET_V1 = "text_secret_v1";
export const LEGACY_ENVELOPE_FORMAT_VERSION = 1;
export const CURRENT_ENVELOPE_FORMAT_VERSION = 2;
export const CURRENT_MULTI_ENVELOPE_FORMAT_VERSION = 3;
export const MAX_RECIPIENTS = 8;

export const HKDF_INFO = "sui-secret-sharing-poc-v1";
export const HKDF_INFO_MULTI_WRAP = "sui-secret-sharing-poc-multi-wrap-v1";

export const ENCRYPTION_SCHEME =
  "x25519-ed25519-derived+hkdf-sha256+chacha20poly1305";

// Multi-recipient suite identifier. Hybrid encryption: the payload is
// encrypted once under a random K_msg, and K_msg is wrapped per recipient
// via X25519 + HKDF + ChaCha20-Poly1305 with a domain-separated salt.
export const ENCRYPTION_SCHEME_MULTI =
  "x25519-ed25519-derived+hkdf-sha256+chacha20poly1305+multi-wrap-v1";

// Bumped manually when wire-incompatible changes ship. The on-chain Move
// module exposes the same value via `protocol_version()` so the SDK can
// refuse to talk to a registry it doesn't understand.
export const SDK_PROTOCOL_VERSION = 3;
