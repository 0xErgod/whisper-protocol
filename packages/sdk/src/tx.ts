import { Transaction } from "@mysten/sui/transactions";
import {
  CLOCK_ID,
  CURRENT_ENVELOPE_FORMAT_VERSION,
  MODULE_ENVELOPES,
  MODULE_REGISTRY,
  SCHEMA_TEXT_SECRET_V1,
  ENCRYPTION_SCHEME,
} from "./constants.js";
import type { UnifiedEncryptedPayload } from "./suite-x25519-unified.js";

export interface BuildPostV5EnvelopeArgs {
  packageId: string;
  registryId: string;
  recipients: Array<{
    address: string;
    keyId: string;
    keyVersion: number;
  }>;
  schema?: string;
  context?: Uint8Array;
  formatVersion?: number;
  payload: UnifiedEncryptedPayload;
}

export interface BuildRegisterKeyArgs {
  packageId: string;
  registryId: string;
  encryptionPublicKey: Uint8Array;
  encryptionScheme?: string;
}

/**
 * Build the move call for the unified v5 envelope.
 *
 * Same shape used for direct messages (recipients.length === 1) and
 * group messages (recipients.length > 1). The on-chain entry point
 * makes no distinction.
 */
export function buildPostV5EnvelopeTx(args: BuildPostV5EnvelopeArgs): Transaction {
  const tx = new Transaction();
  const schemaBytes = new TextEncoder().encode(args.schema ?? SCHEMA_TEXT_SECRET_V1);
  if (args.recipients.length === 0) {
    throw new Error("buildPostV5EnvelopeTx requires at least one recipient");
  }
  if (args.payload.wrappedKeys.length !== args.recipients.length) {
    throw new Error(
      `wrappedKeys length (${args.payload.wrappedKeys.length}) must match recipients (${args.recipients.length})`,
    );
  }
  if (args.payload.wrapNonces.length !== args.recipients.length) {
    throw new Error(
      `wrapNonces length (${args.payload.wrapNonces.length}) must match recipients (${args.recipients.length})`,
    );
  }
  const recipientAddresses = args.recipients.map((r) => r.address);
  const recipientKeyIds = args.recipients.map((r) => r.keyId);
  const recipientKeyVersions = args.recipients.map((r) => BigInt(r.keyVersion));
  const wrappedKeys = args.payload.wrappedKeys.map((w) => Array.from(w));
  const wrapNonces = args.payload.wrapNonces.map((n) => Array.from(n));
  tx.moveCall({
    target: `${args.packageId}::${MODULE_ENVELOPES}::post_envelope`,
    arguments: [
      tx.object(args.registryId),
      tx.pure.vector("address", recipientAddresses),
      tx.pure.vector("id", recipientKeyIds),
      tx.pure.vector("u64", recipientKeyVersions),
      tx.pure.vector("u8", Array.from(args.context ?? new Uint8Array())),
      tx.pure.vector("u8", Array.from(schemaBytes)),
      tx.pure.u16(args.formatVersion ?? CURRENT_ENVELOPE_FORMAT_VERSION),
      tx.pure.vector("u8", Array.from(new TextEncoder().encode(args.payload.encryptionScheme))),
      tx.pure.vector("u8", Array.from(args.payload.ephPubkey)),
      tx.pure.vector("u8", Array.from(args.payload.payloadNonce)),
      tx.pure.vector("u8", Array.from(args.payload.ciphertext)),
      tx.pure.vector("vector<u8>", wrappedKeys),
      tx.pure.vector("vector<u8>", wrapNonces),
      tx.object(CLOCK_ID),
    ],
  });
  return tx;
}

export function buildRegisterKeyTx(args: BuildRegisterKeyArgs): Transaction {
  const tx = new Transaction();
  const schemeBytes = new TextEncoder().encode(args.encryptionScheme ?? ENCRYPTION_SCHEME);
  tx.moveCall({
    target: `${args.packageId}::${MODULE_REGISTRY}::register_encryption_key`,
    arguments: [
      tx.object(args.registryId),
      tx.pure.vector("u8", Array.from(schemeBytes)),
      tx.pure.vector("u8", Array.from(args.encryptionPublicKey)),
      tx.object(CLOCK_ID),
    ],
  });
  return tx;
}
