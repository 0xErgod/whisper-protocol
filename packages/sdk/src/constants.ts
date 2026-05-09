// Per-concern Move module names. The package was split into one
// module per primitive so the SDK has to address each by name.
export const MODULE_FACADE = "secret_sharing";
export const MODULE_REGISTRY = "registry";
export const MODULE_ENVELOPES = "envelopes";
export const MODULE_COMMITMENTS = "commitments";

/** @deprecated Use the per-concern MODULE_* constants. Kept for any
 *  external consumer that still imports `MODULE`. */
export const MODULE = MODULE_FACADE;

export const CLOCK_ID = "0x6";
export const SCHEMA_TEXT_SECRET_V1 = "text_secret_v1";
// Reserved schema for the private-opening composition: an
// encrypted envelope whose plaintext carries `(encoded_secret, salt)`.
// Wired up in PR #28 — commitments self-store their opening as a v5
// envelope addressed to the author with this schema.
export const SCHEMA_COMMITMENT_OPENING_V1 = "commitment_opening_v1";

// Historical envelope format versions. v1 was the pre-versioning
// shape, v2 was the single-recipient owned envelope, v3 was the
// multi-recipient frozen envelope. v5 is the unified frozen envelope
// (1..N recipients via hybrid construction). v4 was a write-compat
// marker bump only — no envelope shape changes.
export const LEGACY_ENVELOPE_FORMAT_VERSION = 1;
export const ENVELOPE_FORMAT_VERSION_V2 = 2;
export const ENVELOPE_FORMAT_VERSION_V3 = 3;
export const CURRENT_ENVELOPE_FORMAT_VERSION = 5;
export const CURRENT_COMMITMENT_FORMAT_VERSION = 1;
export const MAX_RECIPIENTS = 8;

export const HKDF_INFO = "sui-secret-sharing-poc-v1";
export const HKDF_INFO_WRAP = "sui-secret-sharing-poc-wrap-v1";

// Legacy single-recipient suite (v2 historical reads only — the SDK
// no longer produces envelopes under this scheme).
export const ENCRYPTION_SCHEME =
  "x25519-ed25519-derived+hkdf-sha256+chacha20poly1305";

// Legacy multi-recipient suite (v3 historical reads only). Same wrap
// construction the unified suite uses, kept as a separate identifier
// so v3 envelopes from older deployments stay decryptable.
export const ENCRYPTION_SCHEME_MULTI =
  "x25519-ed25519-derived+hkdf-sha256+chacha20poly1305+multi-wrap-v1";

// Unified suite. Hybrid encryption every time, even for N=1: payload
// encrypted once under a random K_msg; K_msg wrapped per recipient via
// X25519 ECDH + HKDF + ChaCha20-Poly1305 with a domain-separated salt.
export const ENCRYPTION_SCHEME_UNIFIED =
  "x25519-ed25519-derived+hkdf-sha256+chacha20poly1305+v5";

// Hash schemes recognized for SecretCommitment.hash_scheme. The value
// is stored on chain so readers know which primitive produced the
// commitment bytes.
export const HASH_SCHEME_BLAKE2B_256 = "blake2b-256";

// ZK-friendly commitment hash. Poseidon over BN254 with circomlib
// parameters; the parameter set is part of the suite identifier
// because two libraries that both call themselves "Poseidon BN254"
// can produce different hashes. circomlib parameters match Sui's
// future on-chain Groth16 verifier path and the broader JS/EVM ZK
// ecosystem (Semaphore, RLN, Tornado Cash, etc.).
//
// Future Rust prover (arkworks-rs) MUST instantiate Poseidon with
// circomlib's round constants and MDS matrix — see
// specs/poseidon-commitment-format.md.
export const HASH_SCHEME_POSEIDON_BN254_CIRCOMLIB_V1 = "poseidon-bn254-circomlib-v1";

// Domain-separation tag for commitment hashing. Per the spec:
//   commitment = H(domain || encoded_secret || salt)
// The domain prevents the same secret/salt from hashing to the same
// value under a different protocol layer.
export const COMMITMENT_DOMAIN_V1 = "sui-secret-commitment-v1";

// Bumped manually when wire-incompatible changes ship. The on-chain Move
// module exposes the same value via `protocol_version()` so the SDK can
// refuse to talk to a registry it doesn't understand.
export const SDK_PROTOCOL_VERSION = 5;
