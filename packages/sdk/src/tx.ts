import { Transaction } from "@mysten/sui/transactions";
import {
  CLOCK_ID,
  CURRENT_ENVELOPE_FORMAT_VERSION,
  MODULE,
  SCHEMA_TEXT_SECRET_V1,
  ENCRYPTION_SCHEME,
} from "./constants.js";
import type { EncryptedPayload } from "./encrypt.js";

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
    target: `${args.packageId}::${MODULE}::post_envelope`,
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

export function buildRegisterKeyTx(args: BuildRegisterKeyArgs): Transaction {
  const tx = new Transaction();
  const schemeBytes = new TextEncoder().encode(args.encryptionScheme ?? ENCRYPTION_SCHEME);
  tx.moveCall({
    target: `${args.packageId}::${MODULE}::register_encryption_key`,
    arguments: [
      tx.object(args.registryId),
      tx.pure.vector("u8", Array.from(schemeBytes)),
      tx.pure.vector("u8", Array.from(args.encryptionPublicKey)),
      tx.object(CLOCK_ID),
    ],
  });
  return tx;
}
