import { blake2b } from "@noble/hashes/blake2b";
import { randomBytes } from "@noble/hashes/utils";
import { Transaction } from "@mysten/sui/transactions";
import type { SuiClient } from "@mysten/sui/client";
import { normalizeAddress } from "./address.js";
import {
  CLOCK_ID,
  COMMITMENT_DOMAIN_V1,
  CURRENT_COMMITMENT_FORMAT_VERSION,
  HASH_SCHEME_BLAKE2B_256,
  MODULE_COMMITMENTS,
} from "./constants.js";
import { bytesFromArray, stringFromBytes } from "./envelope-codec.js";

export interface OnChainCommitment {
  commitmentId: string;
  formatVersion: number;
  author: string;
  schema: string;
  hashScheme: string;
  commitment: Uint8Array;
  createdAtMs: number;
  opened: boolean;
  openedAtMs: number;
}

export interface Opening {
  encodedSecret: Uint8Array;
  salt: Uint8Array;
  commitment: Uint8Array;
}

export interface BuildCommitTxArgs {
  packageId: string;
  schema: string;
  hashScheme?: string;
  commitment: Uint8Array;
}

export interface BuildOpenTxArgs {
  packageId: string;
  commitmentObjectId: string;
  encodedSecret: Uint8Array;
  salt: Uint8Array;
}

const DOMAIN_BYTES = new TextEncoder().encode(COMMITMENT_DOMAIN_V1);

/**
 * Stable byte encoding for a text secret.
 *
 * Per [provable-shared-secrets-extensions.md], text secrets are
 * UTF-8 with line endings normalized to `\n`. Other normalizations
 * are intentionally NOT applied so the user's text round-trips
 * exactly.
 */
export function encodeTextSecret(text: string): Uint8Array {
  const normalized = text.replace(/\r\n/g, "\n").replace(/\r/g, "\n");
  return new TextEncoder().encode(normalized);
}

/**
 * Compute commitment bytes for an already-encoded secret.
 *
 * `commitment = Blake2b-256(domain || encoded_secret || salt)`
 *
 * The domain prefix prevents cross-protocol collisions; the salt
 * prevents brute-force opening of low-entropy secrets like
 * `attack=north`.
 */
export function commitmentHash(
  encodedSecret: Uint8Array,
  salt: Uint8Array,
): Uint8Array {
  const buffer = new Uint8Array(DOMAIN_BYTES.length + encodedSecret.length + salt.length);
  buffer.set(DOMAIN_BYTES, 0);
  buffer.set(encodedSecret, DOMAIN_BYTES.length);
  buffer.set(salt, DOMAIN_BYTES.length + encodedSecret.length);
  return blake2b(buffer, { dkLen: 32 });
}

/**
 * Generate a fresh salt and produce the commitment bytes for it.
 *
 * The returned `salt` MUST be stored alongside `encodedSecret` to
 * later open the commitment. Losing it means the commitment can
 * never be re-opened by anyone.
 */
export function createCommitment(encodedSecret: Uint8Array): {
  commitment: Uint8Array;
  salt: Uint8Array;
} {
  const salt = randomBytes(32);
  const commitment = commitmentHash(encodedSecret, salt);
  return { commitment, salt };
}

/**
 * Verify that an opening matches a previously-posted commitment.
 *
 * Re-hashes `(domain || encoded_secret || salt)` and compares to the
 * commitment bytes byte-by-byte. Returns false on any mismatch
 * including length mismatches; never throws.
 */
export function verifyOpening(
  encodedSecret: Uint8Array,
  salt: Uint8Array,
  expectedCommitment: Uint8Array,
): boolean {
  const computed = commitmentHash(encodedSecret, salt);
  if (computed.length !== expectedCommitment.length) return false;
  let acc = 0;
  for (let i = 0; i < computed.length; i++) {
    acc |= computed[i]! ^ expectedCommitment[i]!;
  }
  return acc === 0;
}

export function buildCommitTx(args: BuildCommitTxArgs): Transaction {
  const tx = new Transaction();
  const schemaBytes = new TextEncoder().encode(args.schema);
  const hashSchemeBytes = new TextEncoder().encode(
    args.hashScheme ?? HASH_SCHEME_BLAKE2B_256,
  );
  tx.moveCall({
    target: `${args.packageId}::${MODULE_COMMITMENTS}::commit_secret`,
    arguments: [
      tx.pure.vector("u8", Array.from(schemaBytes)),
      tx.pure.vector("u8", Array.from(hashSchemeBytes)),
      tx.pure.vector("u8", Array.from(args.commitment)),
      tx.object(CLOCK_ID),
    ],
  });
  return tx;
}

export function buildOpenTx(args: BuildOpenTxArgs): Transaction {
  const tx = new Transaction();
  tx.moveCall({
    target: `${args.packageId}::${MODULE_COMMITMENTS}::open_secret`,
    arguments: [
      tx.object(args.commitmentObjectId),
      tx.pure.vector("u8", Array.from(args.encodedSecret)),
      tx.pure.vector("u8", Array.from(args.salt)),
      tx.object(CLOCK_ID),
    ],
  });
  return tx;
}

export function decodeCommitmentFields(
  commitmentId: string,
  fields: Record<string, unknown>,
): OnChainCommitment {
  return {
    commitmentId,
    formatVersion: Number(fields.format_version ?? CURRENT_COMMITMENT_FORMAT_VERSION),
    author: normalizeAddress(String(fields.author ?? "")),
    schema: stringFromBytes(fields.schema),
    hashScheme: stringFromBytes(fields.hash_scheme),
    commitment: bytesFromArray(fields.commitment),
    createdAtMs: Number(fields.created_at_ms ?? 0),
    opened: Boolean(fields.opened),
    openedAtMs: Number(fields.opened_at_ms ?? 0),
  };
}

export async function fetchCommitment(
  suiClient: SuiClient,
  commitmentObjectId: string,
): Promise<OnChainCommitment | null> {
  const obj = await suiClient.getObject({
    id: commitmentObjectId,
    options: { showContent: true },
  });
  if (!obj.data?.content) return null;
  const f = (obj.data.content as { fields?: Record<string, unknown> }).fields;
  if (!f) return null;
  return decodeCommitmentFields(commitmentObjectId, f);
}
