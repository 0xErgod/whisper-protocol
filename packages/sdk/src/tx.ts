// PTB builders for the four `whisper_protocol` entry points:
//
//   registry::register_encryption_key   (pubkey_x, pubkey_y, clock)
//   envelopes::post_envelope            (single-recipient native-mirror shape)
//   commitments::commit_secret          (encoding_id, x, y, clock)
//   commitments::open_secret            (commitment, stream, blinding, clock)
//
// Field elements (BN254 base field) cross the JS↔chain boundary as
// `BigInt` because Sui's `tx.pure.u256` takes `bigint` natively. The
// SDK carries them as decimal strings internally (the crypto-wasm
// wire form); this file is the place where they get parsed.

import { Transaction } from "@mysten/sui/transactions";
import {
  CLOCK_ID,
  MODULE_COMMITMENTS,
  MODULE_ENVELOPES,
  MODULE_REGISTRY,
} from "./constants.js";
import type { Envelope } from "./suite.js";
import type { Opening } from "./commitments.js";

function bi(s: string): bigint {
  return BigInt(s);
}

export interface BuildRegisterKeyArgs {
  packageId: string;
  registryId: string;
  pubkeyX: string;
  pubkeyY: string;
}

export function buildRegisterKeyTx(args: BuildRegisterKeyArgs): Transaction {
  const tx = new Transaction();
  tx.moveCall({
    target: `${args.packageId}::${MODULE_REGISTRY}::register_encryption_key`,
    arguments: [
      tx.object(args.registryId),
      tx.pure.u256(bi(args.pubkeyX)),
      tx.pure.u256(bi(args.pubkeyY)),
      tx.object(CLOCK_ID),
    ],
  });
  return tx;
}

export interface BuildPostEnvelopeArgs {
  packageId: string;
  registryId: string;
  /** The recipient's Sui address. */
  recipient: string;
  /** Recipient's current `EncryptionKey` object id (from their registry entry). */
  recipientKeyId: string;
  /** Recipient's current key version (from their registry entry). */
  recipientKeyVersion: number;
  /** Sealed envelope produced by `suite.seal`. */
  envelope: Envelope;
}

export function buildPostEnvelopeTx(args: BuildPostEnvelopeArgs): Transaction {
  const tx = new Transaction();
  const ct = args.envelope.ciphertext.map(bi);
  tx.moveCall({
    target: `${args.packageId}::${MODULE_ENVELOPES}::post_envelope`,
    arguments: [
      tx.object(args.registryId),
      tx.pure.address(args.recipient),
      tx.pure.id(args.recipientKeyId),
      tx.pure.u64(BigInt(args.recipientKeyVersion)),
      tx.pure.u256(bi(args.envelope.senderPkX)),
      tx.pure.u256(bi(args.envelope.senderPkY)),
      tx.pure.u256(bi(args.envelope.recipientPkX)),
      tx.pure.u256(bi(args.envelope.recipientPkY)),
      tx.pure.u256(bi(args.envelope.envelopeId)),
      tx.pure.u256(bi(args.envelope.encodingId)),
      tx.pure.vector("u256", ct),
      tx.pure.u256(bi(args.envelope.macTag)),
      tx.object(CLOCK_ID),
    ],
  });
  return tx;
}

export interface BuildCommitTxArgs {
  packageId: string;
  encodingId: string;
  commitmentX: string;
  commitmentY: string;
}

export function buildCommitTx(args: BuildCommitTxArgs): Transaction {
  const tx = new Transaction();
  tx.moveCall({
    target: `${args.packageId}::${MODULE_COMMITMENTS}::commit_secret`,
    arguments: [
      tx.pure.u256(bi(args.encodingId)),
      tx.pure.u256(bi(args.commitmentX)),
      tx.pure.u256(bi(args.commitmentY)),
      tx.object(CLOCK_ID),
    ],
  });
  return tx;
}

export interface BuildOpenTxArgs {
  packageId: string;
  commitmentObjectId: string;
  opening: Opening;
}

export function buildOpenTx(args: BuildOpenTxArgs): Transaction {
  const tx = new Transaction();
  const stream = args.opening.stream.map(bi);
  tx.moveCall({
    target: `${args.packageId}::${MODULE_COMMITMENTS}::open_secret`,
    arguments: [
      tx.object(args.commitmentObjectId),
      tx.pure.vector("u256", stream),
      tx.pure.u256(bi(args.opening.blinding)),
      tx.object(CLOCK_ID),
    ],
  });
  return tx;
}
