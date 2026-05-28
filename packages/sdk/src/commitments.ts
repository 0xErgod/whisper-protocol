// Vector Pedersen commitments — the TS mirror of
// `crates/protocol::commitment` and the on-chain
// `whisper_protocol::commitments` module.
//
// The construction is pinned in `specs/protocol-commitment.md`:
//
//     point = encoding_id · G_0
//           + stream[0]    · G_1
//           + ...
//           + stream[n-1]  · G_n
//           + blinding     · H
//
// `crypto-wasm.pedersen_commit` does this exact computation (it
// commits to the literal stream the caller supplies — we pre-augment
// `[encoding_id, ...stream]` here on the TS side, matching the spec
// and the on-chain shape).
//
// Hash-scheme dispatch is gone: there is one commitment scheme now.

import type { SuiClient } from "@mysten/sui/client";
import { normalizeAddress } from "./address.js";
import { cryptoWasm } from "./wasm.js";

/**
 * A vector Pedersen commitment as it lives on chain.
 * Field elements are decimal strings (matching Sui JSON-RPC's `u256`).
 */
export interface OnChainCommitment {
  commitmentId: string;
  author: string;
  encodingId: string;
  commitmentX: string;
  commitmentY: string;
  createdAtMs: string;
  opened: boolean;
  openedAtMs: string;
}

/**
 * An opening: the augmented stream the commitment was computed over.
 * `encodingId` is already on the on-chain struct; the caller just
 * needs to remember `stream` + `blinding` to open later.
 */
export interface Opening {
  encodingId: string;
  stream: string[];
  blinding: string;
}

/** Result of building a fresh commitment client-side. */
export interface CommitmentResult {
  /** Pedersen point x coordinate (decimal string). */
  commitmentX: string;
  /** Pedersen point y coordinate (decimal string). */
  commitmentY: string;
  /** The opening — keep this until `open_secret` time. */
  opening: Opening;
}

/**
 * Build the augmented stream `[encoding_id, ...stream]` exactly as
 * the spec requires. Internal helper so the rule lives in one place,
 * shared by `commit` and `verifyOpening`.
 */
function augmentedStream(encodingId: string, stream: string[]): string[] {
  return [encodingId, ...stream];
}

/**
 * Commit to `(encodingId, stream)` under a caller-supplied `blinding`.
 *
 * The blinding MUST be a uniformly random scalar in `F_l` (the BJJ
 * scalar field). Reusing a blinding across commitments to different
 * streams is a hiding-failure footgun — generate a fresh one per call.
 *
 * `blinding` is a decimal-string scalar; the caller produces it via
 * `crypto.getRandomValues` reduced mod the BJJ scalar order (or any
 * other CSPRNG). The SDK doesn't generate randomness on the caller's
 * behalf so it never sees blindings except when the caller passes them.
 */
export function commit(args: {
  encodingId: string;
  stream: string[];
  blinding: string;
}): CommitmentResult {
  const augmented = augmentedStream(args.encodingId, args.stream);
  const point = cryptoWasm.pedersen_commit(augmented, args.blinding);
  return {
    commitmentX: point.x,
    commitmentY: point.y,
    opening: {
      encodingId: args.encodingId,
      stream: args.stream,
      blinding: args.blinding,
    },
  };
}

/**
 * Verify an opening against a commitment by recomputing the point.
 *
 * Returns true iff `commit(opening)` produces the same `(x, y)` pair.
 * Mirrors the spec's verify rule:
 *
 *     verify_opening(commitment, opening) =
 *         expected = commit(opening.encoding_id, opening.stream, opening.blinding)
 *         expected.point == commitment.point
 *
 * Caller is responsible for fetching the commitment's `(x, y)` from chain
 * via `fetchCommitment`.
 */
export function verifyOpening(
  commitmentX: string,
  commitmentY: string,
  opening: Opening,
): boolean {
  const recomputed = cryptoWasm.pedersen_commit(
    augmentedStream(opening.encodingId, opening.stream),
    opening.blinding,
  );
  return recomputed.x === commitmentX && recomputed.y === commitmentY;
}

interface CommitmentMoveFields {
  author: string;
  encoding_id: string;
  commitment_x: string;
  commitment_y: string;
  created_at_ms: string;
  opened: boolean;
  opened_at_ms: string;
}

export function decodeCommitmentFields(
  commitmentId: string,
  fields: CommitmentMoveFields,
): OnChainCommitment {
  return {
    commitmentId,
    author: normalizeAddress(fields.author),
    encodingId: fields.encoding_id,
    commitmentX: fields.commitment_x,
    commitmentY: fields.commitment_y,
    createdAtMs: fields.created_at_ms,
    opened: Boolean(fields.opened),
    openedAtMs: fields.opened_at_ms,
  };
}

/**
 * Fetch a `SecretCommitment` object from chain by id and decode it.
 * Returns `null` if the object isn't a Move struct or doesn't carry
 * the expected fields. Throws on RPC error.
 */
export async function fetchCommitment(
  client: SuiClient,
  commitmentObjectId: string,
): Promise<OnChainCommitment | null> {
  const resp = await client.getObject({
    id: commitmentObjectId,
    options: { showContent: true },
  });
  const content = resp.data?.content;
  if (!content || content.dataType !== "moveObject") return null;
  const fields = (content as unknown as { fields: CommitmentMoveFields }).fields;
  if (!fields || typeof fields.commitment_x !== "string") return null;
  return decodeCommitmentFields(commitmentObjectId, fields);
}
