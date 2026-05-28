// Wire codec for the on-chain `whisper_protocol::envelopes::Envelope`
// struct. The chain stores field elements as `u256` (BN254 base field
// fits in 254 bits); the SDK and crypto-wasm carry them as decimal
// strings. This file is the conversion boundary.
//
// Sui's JSON-RPC returns `u256` as a decimal *string*; we re-use that
// as the SDK's canonical form so there's no parse-then-re-stringify
// dance across the boundary.

import { SuiClient } from "@mysten/sui/client";
import type { Envelope } from "./suite.js";

/**
 * One on-chain envelope as it lands in `objectChanges` or
 * `getObject({ showContent: true })`. Field names mirror the Move
 * struct exactly so dApp code can index by the chain's vocabulary.
 */
export interface OnChainEnvelope {
  objectId: string;
  sender: string;
  recipient: string;
  recipientKeyId: string;
  recipientKeyVersion: string;
  senderPkX: string;
  senderPkY: string;
  recipientPkX: string;
  recipientPkY: string;
  envelopeId: string;
  encodingId: string;
  ciphertext: string[];
  macTag: string;
  createdAtMs: string;
}

interface EnvelopeMoveFields {
  sender: string;
  recipient: string;
  recipient_key_id: string;
  recipient_key_version: string;
  sender_pk_x: string;
  sender_pk_y: string;
  recipient_pk_x: string;
  recipient_pk_y: string;
  envelope_id: string;
  encoding_id: string;
  ciphertext: string[];
  mac_tag: string;
  created_at_ms: string;
}

/**
 * Convert raw Move struct fields (as returned by the Sui SDK's
 * `getObject` content path) into the SDK's `OnChainEnvelope` shape.
 * Field-by-field rename; no type conversion (everything stays as
 * decimal strings, which is what Sui's JSON-RPC emits for `u256`).
 */
export function decodeEnvelopeFields(
  objectId: string,
  fields: EnvelopeMoveFields,
): OnChainEnvelope {
  return {
    objectId,
    sender: fields.sender,
    recipient: fields.recipient,
    recipientKeyId: fields.recipient_key_id,
    recipientKeyVersion: fields.recipient_key_version,
    senderPkX: fields.sender_pk_x,
    senderPkY: fields.sender_pk_y,
    recipientPkX: fields.recipient_pk_x,
    recipientPkY: fields.recipient_pk_y,
    envelopeId: fields.envelope_id,
    encodingId: fields.encoding_id,
    ciphertext: fields.ciphertext,
    macTag: fields.mac_tag,
    createdAtMs: fields.created_at_ms,
  };
}

/**
 * Project an `OnChainEnvelope` down to the cryptographic shape the
 * suite layer consumes — drops chain-binding metadata. Lets a
 * recipient feed an envelope read from chain straight into
 * `suite.open` without rebuilding the struct.
 */
export function envelopeFromOnChain(onChain: OnChainEnvelope): Envelope {
  return {
    senderPkX: onChain.senderPkX,
    senderPkY: onChain.senderPkY,
    recipientPkX: onChain.recipientPkX,
    recipientPkY: onChain.recipientPkY,
    envelopeId: onChain.envelopeId,
    encodingId: onChain.encodingId,
    ciphertext: onChain.ciphertext,
    macTag: onChain.macTag,
  };
}

/**
 * Fetch an envelope object from chain by its object id and decode it.
 * Returns `null` if the object isn't a Move struct or doesn't carry
 * the expected fields. Throws on RPC error.
 */
export async function fetchEnvelope(
  client: SuiClient,
  objectId: string,
): Promise<OnChainEnvelope | null> {
  const resp = await client.getObject({
    id: objectId,
    options: { showContent: true },
  });
  const content = resp.data?.content;
  if (!content || content.dataType !== "moveObject") return null;
  const fields = (content as unknown as { fields: EnvelopeMoveFields }).fields;
  if (!fields || typeof fields.sender_pk_x !== "string") return null;
  return decodeEnvelopeFields(objectId, fields);
}
