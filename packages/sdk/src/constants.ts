// Per-concern Move module names. The package is split into one
// module per primitive so the SDK addresses each by name.
export const MODULE_FACADE = "whisper";
export const MODULE_REGISTRY = "registry";
export const MODULE_ENVELOPES = "envelopes";
export const MODULE_COMMITMENTS = "commitments";
export const MODULE_PROOFS = "proofs";

/** @deprecated Use the per-concern MODULE_* constants. Kept for any
 *  external consumer that still imports `MODULE`. */
export const MODULE = MODULE_FACADE;

// Sui's well-known shared `Clock` object id. Required by every
// entry function that timestamps its work.
export const CLOCK_ID = "0x6";

// The on-chain Move module exposes this via `protocol_version()`; the
// SDK reads it at boot and refuses to write if the deployed package
// doesn't match. Pinned at 1 for the whisper_protocol package — a
// schema break publishes a new package id rather than bumping this.
export const SDK_PROTOCOL_VERSION = 1;
