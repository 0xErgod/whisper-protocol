import { Transaction } from "@mysten/sui/transactions";
import type { SuiClient } from "@mysten/sui/client";
import { MODULE } from "./constants.js";

const ZERO_ADDRESS = "0x0000000000000000000000000000000000000000000000000000000000000000";

/**
 * Read the deployed Move module's `protocol_version()` view function via
 * `devInspectTransactionBlock`. Returns the `u32` value, or throws if the
 * package doesn't expose `protocol_version` (i.e., it predates the SDK
 * compatibility check).
 *
 * Uses the zero address as the dev-inspect sender — the call is a pure
 * view, doesn't read or mutate any objects, so any address works.
 */
export async function readOnChainProtocolVersion(
  suiClient: SuiClient,
  packageId: string,
): Promise<number> {
  const tx = new Transaction();
  tx.moveCall({ target: `${packageId}::${MODULE}::protocol_version` });

  const result = await suiClient.devInspectTransactionBlock({
    sender: ZERO_ADDRESS,
    transactionBlock: tx,
  });

  if (result.error) {
    throw new Error(
      `dev-inspect of ${packageId}::${MODULE}::protocol_version failed: ${result.error}`,
    );
  }

  const returns = result.results?.[0]?.returnValues;
  if (!returns || returns.length === 0) {
    throw new Error(
      `${packageId}::${MODULE}::protocol_version returned no value — is this a pre-protocol_version deployment?`,
    );
  }

  // returnValues is [bytes, type][]. u32 = 4 bytes little-endian.
  const [bytes, type] = returns[0]!;
  if (type !== "u32") {
    throw new Error(
      `${packageId}::${MODULE}::protocol_version returned ${type}, expected u32`,
    );
  }
  if (bytes.length < 4) {
    throw new Error(
      `${packageId}::${MODULE}::protocol_version returned only ${bytes.length} bytes`,
    );
  }
  return (
    bytes[0]! |
    (bytes[1]! << 8) |
    (bytes[2]! << 16) |
    (bytes[3]! << 24)
  ) >>> 0;
}
