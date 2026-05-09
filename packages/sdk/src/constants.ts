// Per-concern Move module names. The package was split into one
// module per primitive so the SDK has to address each by name.
export const MODULE_FACADE = "secret_sharing";
export const MODULE_REGISTRY = "registry";
export const MODULE_ENVELOPES = "envelopes";
export const MODULE_MULTI_ENVELOPES = "multi_envelopes";
export const MODULE_COMMITMENTS = "commitments";

/** @deprecated Use the per-concern MODULE_* constants. Kept for any
 *  external consumer that still imports `MODULE`. */
export const MODULE = MODULE_FACADE;

export const CLOCK_ID = "0x6";
export const SCHEMA_TEXT_SECRET_V1 = "text_secret_v1";
// Reserved schema for the future private-opening composition: an
// encrypted envelope whose plaintext carries `(commitmentId, encodedSecret, salt)`.
// Not implemented yet; see specs/provable-shared-secrets-extensions.md phase 2.
export const SCHEMA_COMMITMENT_OPENING_V1 = "commitment_opening_v1";

export const LEGACY_ENVELOPE_FORMAT_VERSION = 1;
export const CURRENT_ENVELOPE_FORMAT_VERSION = 2;
export const CURRENT_MULTI_ENVELOPE_FORMAT_VERSION = 3;
export const CURRENT_COMMITMENT_FORMAT_VERSION = 1;
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

// Hash schemes recognized for SecretCommitment.hash_scheme. The value
// is stored on chain so readers know which primitive produced the
// commitment bytes.
export const HASH_SCHEME_BLAKE2B_256 = "blake2b-256";

// Domain-separation tag for commitment hashing. Per the spec:
//   commitment = H(domain || encoded_secret || salt)
// The domain prevents the same secret/salt from hashing to the same
// value under a different protocol layer.
export const COMMITMENT_DOMAIN_V1 = "sui-secret-commitment-v1";

// Bumped manually when wire-incompatible changes ship. The on-chain Move
// module exposes the same value via `protocol_version()` so the SDK can
// refuse to talk to a registry it doesn't understand.
export const SDK_PROTOCOL_VERSION = 4;
