import { Transaction } from "@mysten/sui/transactions";
import type { SuiClient } from "@mysten/sui/client";
import {
  CURRENT_ENVELOPE_FORMAT_VERSION,
  ENCRYPTION_SCHEME,
  MODULE_FACADE,
} from "./constants.js";
import { WriteCompatibilityError } from "./errors.js";
import { assertSupportedEnvelopeFormatVersion } from "./envelope-codec.js";
import { requireEncryptionSuite } from "./suites.js";

const ZERO_ADDRESS = "0x0000000000000000000000000000000000000000000000000000000000000000";

export interface AssertWriteCompatibleOptions {
  expectedProtocolVersion: number;
  formatVersion?: number;
  encryptionScheme?: string;
}

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

export async function assertWriteCompatible(
  suiClient: SuiClient,
  packageId: string,
  options: AssertWriteCompatibleOptions,
): Promise<number> {
  const formatVersion = options.formatVersion ?? CURRENT_ENVELOPE_FORMAT_VERSION;
  const encryptionScheme = options.encryptionScheme ?? ENCRYPTION_SCHEME;
  assertSupportedEnvelopeFormatVersion(formatVersion);
  requireEncryptionSuite(encryptionScheme);

  const onChain = await readOnChainProtocolVersion(suiClient, packageId);
  if (onChain !== options.expectedProtocolVersion) {
    throw new WriteCompatibilityError(
      `Whisper write compatibility mismatch: deployed package ${packageId} reports protocol_version=${onChain}, but this SDK expects ${options.expectedProtocolVersion} for format_version=${formatVersion} and suite=${encryptionScheme}.`,
    );
  }
  return onChain;
}
