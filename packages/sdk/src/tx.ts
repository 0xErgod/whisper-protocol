import { Transaction } from "@mysten/sui/transactions";
import {
  CLOCK_ID,
  CURRENT_ENVELOPE_FORMAT_VERSION,
  CURRENT_MULTI_ENVELOPE_FORMAT_VERSION,
  MODULE_ENVELOPES,
  MODULE_MULTI_ENVELOPES,
  MODULE_REGISTRY,
  SCHEMA_TEXT_SECRET_V1,
  ENCRYPTION_SCHEME,
} from "./constants.js";
import type { EncryptedPayload } from "./encrypt.js";
import type { MultiEncryptedPayload } from "./suite-x25519-multi.js";

export interface BuildPostEnvelopeArgs {
  packageId: string;
  registryId: string;
  recipientAddress: string;
  schema?: string;
  context?: Uint8Array;
  formatVersion?: number;
  recipientKeyId: string;
  keyVersion: number;
  payload: EncryptedPayload;
}

export interface BuildPostMultiEnvelopeArgs {
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
  payload: MultiEncryptedPayload;
}

export interface BuildRegisterKeyArgs {
  packageId: string;
  registryId: string;
  encryptionPublicKey: Uint8Array;
  encryptionScheme?: string;
}

export function buildPostEnvelopeTx(args: BuildPostEnvelopeArgs): Transaction {
  const tx = new Transaction();
  const schemaBytes = new TextEncoder().encode(args.schema ?? SCHEMA_TEXT_SECRET_V1);
  tx.moveCall({
    target: `${args.packageId}::${MODULE_ENVELOPES}::post_envelope`,
    arguments: [
      tx.object(args.registryId),
      tx.pure.address(args.recipientAddress),
      tx.pure.vector("u8", Array.from(args.context ?? new Uint8Array())),
      tx.pure.vector("u8", Array.from(schemaBytes)),
      tx.pure.u16(args.formatVersion ?? CURRENT_ENVELOPE_FORMAT_VERSION),
      tx.pure.id(args.recipientKeyId),
      tx.pure.vector("u8", Array.from(new TextEncoder().encode(args.payload.encryptionScheme))),
      tx.pure.u64(BigInt(args.keyVersion)),
      tx.pure.vector("u8", Array.from(args.payload.ephPubkey)),
      tx.pure.vector("u8", Array.from(args.payload.nonce)),
      tx.pure.vector("u8", Array.from(args.payload.ciphertext)),
      tx.object(CLOCK_ID),
    ],
  });
  return tx;
}

export function buildPostMultiEnvelopeTx(args: BuildPostMultiEnvelopeArgs): Transaction {
  const tx = new Transaction();
  const schemaBytes = new TextEncoder().encode(args.schema ?? SCHEMA_TEXT_SECRET_V1);
  const recipientAddresses = args.recipients.map((r) => r.address);
  const recipientKeyIds = args.recipients.map((r) => r.keyId);
  const recipientKeyVersions = args.recipients.map((r) => BigInt(r.keyVersion));
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
  const wrappedKeys = args.payload.wrappedKeys.map((w) => Array.from(w));
  const wrapNonces = args.payload.wrapNonces.map((n) => Array.from(n));
  tx.moveCall({
    target: `${args.packageId}::${MODULE_MULTI_ENVELOPES}::post_multi_envelope`,
    arguments: [
      tx.object(args.registryId),
      tx.pure.vector("address", recipientAddresses),
      tx.pure.vector("id", recipientKeyIds),
      tx.pure.vector("u64", recipientKeyVersions),
      tx.pure.vector("u8", Array.from(args.context ?? new Uint8Array())),
      tx.pure.vector("u8", Array.from(schemaBytes)),
      tx.pure.u16(args.formatVersion ?? CURRENT_MULTI_ENVELOPE_FORMAT_VERSION),
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
