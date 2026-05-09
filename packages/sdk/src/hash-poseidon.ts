/// Poseidon-BN254 commitment hashing with circomlib parameters.
///
/// This is the ZK-friendly alternative to Blake2b-256 for commitment
/// hashing. The construction is deliberately simple and fixed-arity
/// so the future Rust prover (arkworks-rs + ark-crypto-primitives)
/// can mirror it byte-for-byte without ambiguity.
///
/// Input shape (fixed): poseidon12([
///   domain_constant_field,
///   secret_length_field,
///   salt_field,
///   secret_chunk_0,
///   secret_chunk_1,
///   ..,
///   secret_chunk_8
/// ])
///
/// Where:
/// - `domain_constant_field` = Blake2b256(COMMITMENT_DOMAIN_V1) mod p,
///   computed once at module load.
/// - `secret_length_field` = byteLength of encoded_secret (must be
///   <= MAX_POSEIDON_SECRET_BYTES = 9 * 31 = 279, but we cap at
///   9 * 31 - 23 = 256 for round numbers and to leave room for a
///   length prefix in case the format ever needs to grow).
/// - `salt_field` = 32 bytes of salt interpreted as a big-endian
///   integer reduced mod p. (Top 2 bits of the 256-bit salt may be
///   masked away; harmless since salt is uniform random.)
/// - `secret_chunk_i` = bytes [31i, 31(i+1)) of encoded_secret,
///   zero-padded on the right if the last chunk is short, interpreted
///   as a 31-byte big-endian integer (always fits in BN254 field).
///
/// The output is one BN254 field element, serialized as 32 big-endian
/// bytes — same width as Blake2b-256's output, so it slots into the
/// existing on-chain commitment byte field with no Move changes.
///
/// Parameter set: circomlib (the de facto JS/EVM ZK ecosystem default,
/// implemented by poseidon-lite). The Rust prover MUST use the same
/// circomlib parameters — see specs/poseidon-commitment-format.md
/// for the spec and a worked example fixture.

import { blake2b } from "@noble/hashes/blake2b";
import { bytesToHex } from "@noble/hashes/utils";
import { poseidon12 } from "poseidon-lite";
import { COMMITMENT_DOMAIN_V1 } from "./constants.js";

// BN254 (a.k.a. BN128/alt_bn128) scalar field prime. Same prime Sui's
// `sui::groth16` precompile uses for the BN254 curve verifier, and the
// field circomlib's Poseidon parameters are defined over.
const BN254_FIELD_MODULUS =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

// 9 chunks * 31 bytes = 279 bytes addressable. We cap secrets at 256
// bytes so there's headroom and round numbers in the spec; the chunk
// indices [256, 279) are always zero-padded.
const POSEIDON_CHUNK_COUNT = 9;
const POSEIDON_CHUNK_SIZE = 31;
export const MAX_POSEIDON_SECRET_BYTES = 256;

/**
 * Reduce a big-endian byte string mod the BN254 scalar field. Handles
 * inputs up to 32 bytes; the top bits beyond the field modulus get
 * masked away naturally via the modulo.
 */
function bytesToFieldBe(bytes: Uint8Array): bigint {
  let acc = 0n;
  for (const b of bytes) {
    acc = (acc << 8n) | BigInt(b);
  }
  return acc % BN254_FIELD_MODULUS;
}

/** Domain tag derived once: Blake2b-256(COMMITMENT_DOMAIN_V1) mod p. */
const DOMAIN_FIELD: bigint = (() => {
  const domainBytes = new TextEncoder().encode(COMMITMENT_DOMAIN_V1);
  const digest = blake2b(domainBytes, { dkLen: 32 });
  return bytesToFieldBe(digest);
})();

/**
 * Pack `encoded_secret` into POSEIDON_CHUNK_COUNT big-endian field
 * elements. Each chunk is 31 bytes (always fits in BN254 since
 * 31 * 8 = 248 < 254). Last chunk is zero-padded on the right.
 */
function packSecretChunks(encodedSecret: Uint8Array): bigint[] {
  if (encodedSecret.length > MAX_POSEIDON_SECRET_BYTES) {
    throw new Error(
      `Poseidon commitment secret must be at most ${MAX_POSEIDON_SECRET_BYTES} bytes, got ${encodedSecret.length}`,
    );
  }
  const chunks: bigint[] = [];
  for (let i = 0; i < POSEIDON_CHUNK_COUNT; i++) {
    const start = i * POSEIDON_CHUNK_SIZE;
    const end = Math.min(start + POSEIDON_CHUNK_SIZE, encodedSecret.length);
    const slice = new Uint8Array(POSEIDON_CHUNK_SIZE);
    if (start < encodedSecret.length) {
      slice.set(encodedSecret.subarray(start, end), 0);
    }
    chunks.push(bytesToFieldBe(slice));
  }
  return chunks;
}

/**
 * Serialize a BN254 field element as 32 big-endian bytes. The output
 * matches Blake2b-256's width so v5 envelope `commitment` byte field
 * accepts both schemes interchangeably.
 */
function fieldToBytesBe(value: bigint): Uint8Array {
  const out = new Uint8Array(32);
  let v = value;
  for (let i = 31; i >= 0; i--) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

/**
 * Compute the Poseidon-BN254 commitment hash for a given
 * `(encoded_secret, salt)` pair.
 *
 * The TS implementation here and the future Rust verifier MUST agree
 * byte-for-byte on:
 *   - The BN254 field prime
 *   - The Poseidon parameter set (circomlib t=13 / poseidon12)
 *   - The 31-byte big-endian chunking
 *   - The domain field derivation (Blake2b-256 over the domain string,
 *     reduced mod p)
 *   - The 32-byte big-endian output serialization
 *
 * The fixture in specs/poseidon-commitment-format.md is the
 * cross-language compatibility contract: any implementation that
 * produces a different hash for that input is wrong.
 */
export function poseidonCommitmentHash(
  encodedSecret: Uint8Array,
  salt: Uint8Array,
): Uint8Array {
  if (salt.length !== 32) {
    throw new Error(`Poseidon commitment salt must be 32 bytes, got ${salt.length}`);
  }
  const lengthField = BigInt(encodedSecret.length);
  const saltField = bytesToFieldBe(salt);
  const chunks = packSecretChunks(encodedSecret);
  const inputs: bigint[] = [DOMAIN_FIELD, lengthField, saltField, ...chunks];
  if (inputs.length !== 12) {
    throw new Error(`internal: expected 12 Poseidon inputs, got ${inputs.length}`);
  }
  const digest = poseidon12(inputs);
  return fieldToBytesBe(digest);
}

/** Exposed for testing and the spec's worked example. */
export const _poseidonInternals = {
  BN254_FIELD_MODULUS,
  DOMAIN_FIELD,
  POSEIDON_CHUNK_COUNT,
  POSEIDON_CHUNK_SIZE,
  bytesToFieldBe,
  fieldToBytesBe,
  packSecretChunks,
  domainFieldHex: () => bytesToHex(fieldToBytesBe(DOMAIN_FIELD)),
};
