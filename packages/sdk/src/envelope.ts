import type { SuiClient } from "@mysten/sui/client";
import { normalizeAddress } from "./address.js";
import { LEGACY_ENVELOPE_FORMAT_VERSION, MODULE } from "./constants.js";
import {
  assertSupportedEnvelopeFormatVersion,
  bytesFromArray,
  decodeEnvelopeCompatibilityMetadata,
  detectEnvelopeFormatVersion,
  idFromUnknown,
  stringFromBytes,
  type EnvelopeCompatibilityMetadata,
} from "./envelope-codec.js";
import { UnsupportedEncryptionSchemeError } from "./errors.js";
import { supportsEncryptionScheme } from "./suites.js";

export interface OnChainEnvelope extends EnvelopeCompatibilityMetadata {
  envelopeId: string;
  sender: string;
  recipient: string;
  recipientKeyId: string | null;
  context: Uint8Array;
  schema: string;
  keyVersion: number;
  ephPubkey: Uint8Array;
  nonce: Uint8Array;
  ciphertext: Uint8Array;
  createdAtMs: number;
}

function decodeV1Envelope(
  envelopeId: string,
  fields: Record<string, unknown>,
): OnChainEnvelope {
  return {
    envelopeId,
    ...decodeEnvelopeCompatibilityMetadata(fields),
    sender: normalizeAddress(String(fields.sender ?? "")),
    recipient: normalizeAddress(String(fields.recipient ?? "")),
    recipientKeyId: null,
    context: bytesFromArray(fields.context),
    schema: stringFromBytes(fields.schema),
    keyVersion: Number(fields.key_version ?? 0),
    ephPubkey: bytesFromArray(fields.eph_pubkey),
    nonce: bytesFromArray(fields.nonce),
    ciphertext: bytesFromArray(fields.ciphertext),
    createdAtMs: Number(fields.created_at_ms ?? 0),
  };
}

function decodeV2Envelope(
  envelopeId: string,
  fields: Record<string, unknown>,
): OnChainEnvelope {
  return {
    envelopeId,
    ...decodeEnvelopeCompatibilityMetadata(fields),
    sender: normalizeAddress(String(fields.sender ?? "")),
    recipient: normalizeAddress(String(fields.recipient ?? "")),
    recipientKeyId: idFromUnknown(fields.recipient_key_id),
    context: bytesFromArray(fields.context),
    schema: stringFromBytes(fields.schema),
    keyVersion: Number(fields.key_version ?? 0),
    ephPubkey: bytesFromArray(fields.eph_pubkey),
    nonce: bytesFromArray(fields.nonce),
    ciphertext: bytesFromArray(fields.ciphertext),
    createdAtMs: Number(fields.created_at_ms ?? 0),
  };
}

export function decodeEnvelopeFields(
  envelopeId: string,
  fields: Record<string, unknown>,
): OnChainEnvelope {
  const formatVersion = detectEnvelopeFormatVersion(fields);
  assertSupportedEnvelopeFormatVersion(formatVersion);
  return formatVersion === LEGACY_ENVELOPE_FORMAT_VERSION
    ? decodeV1Envelope(envelopeId, fields)
    : decodeV2Envelope(envelopeId, fields);
}

export function canReadEnvelope(
  envelope: Pick<OnChainEnvelope, "formatVersion" | "encryptionScheme">,
): boolean {
  try {
    assertCanReadEnvelope(envelope);
    return true;
  } catch {
    return false;
  }
}

export function assertCanReadEnvelope(
  envelope: Pick<OnChainEnvelope, "formatVersion" | "encryptionScheme">,
): void {
  assertSupportedEnvelopeFormatVersion(envelope.formatVersion);
  if (!supportsEncryptionScheme(envelope.encryptionScheme)) {
    throw new UnsupportedEncryptionSchemeError(envelope.encryptionScheme);
  }
}

export async function fetchEnvelope(
  suiClient: SuiClient,
  envelopeId: string,
): Promise<OnChainEnvelope | null> {
  const obj = await suiClient.getObject({
    id: envelopeId,
    options: { showContent: true },
  });
  if (!obj.data?.content) return null;
  const f = (obj.data.content as { fields?: Record<string, unknown> }).fields;
  if (!f) return null;
  return decodeEnvelopeFields(envelopeId, f);
}

export async function fetchInbox(
  suiClient: SuiClient,
  packageId: string,
  ownerAddress: string,
): Promise<OnChainEnvelope[]> {
  const envelopeType = `${packageId}::${MODULE}::EncryptedEnvelope`;
  const owned = await suiClient.getOwnedObjects({
    owner: ownerAddress,
    filter: { StructType: envelopeType },
    options: { showContent: true },
  });
  const out: OnChainEnvelope[] = [];
  for (const entry of owned.data) {
    const id = entry.data?.objectId;
    if (!id) continue;
    const f = (entry.data?.content as { fields?: Record<string, unknown> } | undefined)?.fields;
    if (!f) continue;
    out.push(decodeEnvelopeFields(id, f));
  }
  out.sort((a, b) => b.createdAtMs - a.createdAtMs);
  return out;
}
