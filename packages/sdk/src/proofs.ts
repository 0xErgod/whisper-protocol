// Groth16 proof generation + on-chain verification glue.
//
// Proving is off-chain and compute-heavy, so it lives in the Rust
// `prover-server` (HTTP). This module is the thin client: it shapes
// the request body the server expects, POSTs it, and hands back the
// proof bytes. The companion `buildOpenWithProofTx` wraps the proof
// into the `commitments::open_with_proof` PTB.
//
// The proof bytes are arkworks' compressed canonical encoding — the
// same form Sui's `groth16::proof_points_from_bytes` consumes (see
// `crates/prover::serialize_proof` and the encoding decision pinned
// in `specs/zk/stack.md`). No re-encoding on the JS side.

import { Transaction } from "@mysten/sui/transactions";
import { CLOCK_ID, MODULE_COMMITMENTS } from "./constants.js";
import type { Opening } from "./commitments.js";

/**
 * Default prover-server URL — matches the server's default bind
 * (`PROVER_BIND_ADDR`, `127.0.0.1:3001`). Overridable per-call (and
 * the dApp wires it to a Vite env). The server exposes
 * `POST /prove/<circuit>` and returns proof bytes as
 * `application/octet-stream`.
 */
export const DEFAULT_PROVER_URL = "http://127.0.0.1:3001";

/** The `pedersen_opens_to` circuit's stream length (matches text-utf8-v1). */
const STREAM_LEN = 9;

export interface ProveCommitmentOpeningArgs {
  /** Commitment point x-coordinate (decimal string). */
  commitmentX: string;
  /** Commitment point y-coordinate (decimal string). */
  commitmentY: string;
  /** The opening held since `commit` — its stream + blinding + encoding id. */
  opening: Opening;
  /**
   * The value being proven public: the payload's `stream[0]`. Must
   * equal `opening.stream[0]` or the proof won't satisfy the circuit.
   */
  claimedFirstValue: string;
  /** Prover-server base URL. Defaults to `DEFAULT_PROVER_URL`. */
  proverUrl?: string;
}

/**
 * Request body for `POST /prove/pedersen_opens_to`. Mirrors the Rust
 * `circuits::pedersen_opens_to::PedersenOpensToInputs` field-for-field
 * (all decimal strings; `stream` is exactly `STREAM_LEN` elements).
 */
interface PedersenOpensToInputs {
  commitment_x: string;
  commitment_y: string;
  encoding_id: string;
  claimed_first_value: string;
  stream: string[];
  blinding: string;
}

/**
 * Generate a Groth16 proof that the prover knows an opening of the
 * commitment whose `stream[0]` equals `claimedFirstValue`, without
 * revealing the rest of the opening.
 *
 * Calls the prover-server's `/prove/pedersen_opens_to`. Returns the
 * proof bytes (arkworks compressed), ready to pass to
 * `buildOpenWithProofTx`.
 *
 * Throws if the opening stream isn't exactly `STREAM_LEN` elements
 * (the circuit is fixed-arity), or if the server returns non-2xx.
 */
export async function proveCommitmentOpening(
  args: ProveCommitmentOpeningArgs,
): Promise<Uint8Array> {
  if (args.opening.stream.length !== STREAM_LEN) {
    throw new Error(
      `pedersen_opens_to circuit requires exactly ${STREAM_LEN} stream elements, got ${args.opening.stream.length}`,
    );
  }
  const body: PedersenOpensToInputs = {
    commitment_x: args.commitmentX,
    commitment_y: args.commitmentY,
    encoding_id: args.opening.encodingId,
    claimed_first_value: args.claimedFirstValue,
    stream: args.opening.stream,
    blinding: args.opening.blinding,
  };

  const url = `${args.proverUrl ?? DEFAULT_PROVER_URL}/prove/pedersen_opens_to`;
  const resp = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!resp.ok) {
    const text = await resp.text().catch(() => "");
    throw new Error(`prover /prove/pedersen_opens_to ${resp.status}: ${text}`);
  }
  const buf = await resp.arrayBuffer();
  return new Uint8Array(buf);
}

export interface BuildOpenWithProofTxArgs {
  packageId: string;
  /** The on-chain SecretCommitment object id. */
  commitmentObjectId: string;
  /** The proven public value (`stream[0]`), decimal string. */
  claimedFirstValue: string;
  /** Proof bytes from `proveCommitmentOpening`. */
  proofBytes: Uint8Array;
}

/**
 * Build the `commitments::open_with_proof` PTB. The Move entry
 * reconstructs the proof's public inputs from the commitment object's
 * own fields, so we only pass the object, the claimed value, and the
 * proof bytes — the point coordinates and encoding id come from chain.
 */
export function buildOpenWithProofTx(args: BuildOpenWithProofTxArgs): Transaction {
  const tx = new Transaction();
  tx.moveCall({
    target: `${args.packageId}::${MODULE_COMMITMENTS}::open_with_proof`,
    arguments: [
      tx.object(args.commitmentObjectId),
      tx.pure.u256(BigInt(args.claimedFirstValue)),
      tx.pure.vector("u8", Array.from(args.proofBytes)),
      tx.object(CLOCK_ID),
    ],
  });
  return tx;
}
