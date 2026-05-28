import { Transaction } from "@mysten/sui/transactions";
import type { SuiClient } from "@mysten/sui/client";
import { MODULE_FACADE } from "./constants.js";
import { WriteCompatibilityError } from "./errors.js";

const ZERO_ADDRESS = "0x0000000000000000000000000000000000000000000000000000000000000000";

/**
 * Read the deployed package's `protocol_version()` via dev-inspect.
 *
 * The single-suite design means there's no encryption-scheme dispatch
 * to verify against — the package id uniquely identifies the schema.
 * This function just answers "is the deployed package the version
 * this SDK was built against?".
 */
export async function readOnChainProtocolVersion(
  suiClient: SuiClient,
  packageId: string,
): Promise<number> {
  const tx = new Transaction();
  tx.moveCall({ target: `${packageId}::${MODULE_FACADE}::protocol_version` });

  const result = await suiClient.devInspectTransactionBlock({
    sender: ZERO_ADDRESS,
    transactionBlock: tx,
  });

  if (result.error) {
    throw new Error(
      `dev-inspect of ${packageId}::${MODULE_FACADE}::protocol_version failed: ${result.error}`,
    );
  }

  const returns = result.results?.[0]?.returnValues;
  if (!returns || returns.length === 0) {
    throw new Error(
      `${packageId}::${MODULE_FACADE}::protocol_version returned no value — is this a pre-protocol_version deployment?`,
    );
  }

  const [bytes, type] = returns[0]!;
  if (type !== "u32") {
    throw new Error(
      `${packageId}::${MODULE_FACADE}::protocol_version returned ${type}, expected u32`,
    );
  }
  if (bytes.length < 4) {
    throw new Error(
      `${packageId}::${MODULE_FACADE}::protocol_version returned only ${bytes.length} bytes`,
    );
  }
  return (
    bytes[0]! |
    (bytes[1]! << 8) |
    (bytes[2]! << 16) |
    (bytes[3]! << 24)
  ) >>> 0;
}

export interface AssertWriteCompatibleOptions {
  expectedProtocolVersion: number;
}

/**
 * Refuse to write against a deployment whose `protocol_version`
 * doesn't match what this SDK was built against.
 *
 * Returns the on-chain version on success; throws
 * `WriteCompatibilityError` on mismatch.
 */
export async function assertWriteCompatible(
  suiClient: SuiClient,
  packageId: string,
  options: AssertWriteCompatibleOptions,
): Promise<number> {
  const onChain = await readOnChainProtocolVersion(suiClient, packageId);
  if (onChain !== options.expectedProtocolVersion) {
    throw new WriteCompatibilityError(
      `Whisper write compatibility mismatch: deployed package ${packageId} reports protocol_version=${onChain}, but this SDK expects ${options.expectedProtocolVersion}.`,
    );
  }
  return onChain;
}
