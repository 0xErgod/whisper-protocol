import type { SuiClient } from "@mysten/sui/client";
import { normalizeAddress } from "./address.js";
import { MODULE_MULTI_ENVELOPES } from "./constants.js";
import {
  assertSupportedEnvelopeFormatVersion,
  bytesArrayFromUnknown,
  bytesFromArray,
  decodeEnvelopeCompatibilityMetadata,
  detectEnvelopeFormatVersion,
  idArrayFromUnknown,
  isMultiRecipientEnvelopeFormatVersion,
  numberArrayFromUnknown,
  stringFromBytes,
  type EnvelopeCompatibilityMetadata,
} from "./envelope-codec.js";
import {
  UnsupportedEncryptionSchemeError,
  UnsupportedEnvelopeFormatVersionError,
} from "./errors.js";
import { supportsMultiEncryptionScheme } from "./suites-multi.js";

export interface OnChainMultiEnvelope extends EnvelopeCompatibilityMetadata {
  envelopeId: string;
  sender: string;
  recipients: string[];
  recipientKeyIds: string[];
  recipientKeyVersions: number[];
  context: Uint8Array;
  schema: string;
  ephPubkey: Uint8Array;
  payloadNonce: Uint8Array;
  ciphertext: Uint8Array;
  wrappedKeys: Uint8Array[];
  wrapNonces: Uint8Array[];
  createdAtMs: number;
}

function decodeV3MultiEnvelope(
  envelopeId: string,
  fields: Record<string, unknown>,
): OnChainMultiEnvelope {
  return {
    envelopeId,
    ...decodeEnvelopeCompatibilityMetadata(fields),
    sender: normalizeAddress(String(fields.sender ?? "")),
    recipients: (Array.isArray(fields.recipients) ? (fields.recipients as unknown[]) : [])
      .map((entry) => normalizeAddress(String(entry ?? ""))),
    recipientKeyIds: idArrayFromUnknown(fields.recipient_key_ids),
    recipientKeyVersions: numberArrayFromUnknown(fields.recipient_key_versions),
    context: bytesFromArray(fields.context),
    schema: stringFromBytes(fields.schema),
    ephPubkey: bytesFromArray(fields.eph_pubkey),
    payloadNonce: bytesFromArray(fields.payload_nonce),
    ciphertext: bytesFromArray(fields.ciphertext),
    wrappedKeys: bytesArrayFromUnknown(fields.wrapped_keys),
    wrapNonces: bytesArrayFromUnknown(fields.wrap_nonces),
    createdAtMs: Number(fields.created_at_ms ?? 0),
  };
}

export function decodeMultiEnvelopeFields(
  envelopeId: string,
  fields: Record<string, unknown>,
): OnChainMultiEnvelope {
  const formatVersion = detectEnvelopeFormatVersion(fields);
  assertSupportedEnvelopeFormatVersion(formatVersion);
  if (!isMultiRecipientEnvelopeFormatVersion(formatVersion)) {
    throw new UnsupportedEnvelopeFormatVersionError(formatVersion);
  }
  return decodeV3MultiEnvelope(envelopeId, fields);
}

export function canReadMultiEnvelope(
  envelope: Pick<OnChainMultiEnvelope, "formatVersion" | "encryptionScheme">,
): boolean {
  try {
    assertCanReadMultiEnvelope(envelope);
    return true;
  } catch {
    return false;
  }
}

export function assertCanReadMultiEnvelope(
  envelope: Pick<OnChainMultiEnvelope, "formatVersion" | "encryptionScheme">,
): void {
  assertSupportedEnvelopeFormatVersion(envelope.formatVersion);
  if (!isMultiRecipientEnvelopeFormatVersion(envelope.formatVersion)) {
    throw new UnsupportedEnvelopeFormatVersionError(envelope.formatVersion);
  }
  if (!supportsMultiEncryptionScheme(envelope.encryptionScheme)) {
    throw new UnsupportedEncryptionSchemeError(envelope.encryptionScheme);
  }
}

export function recipientIndexInMultiEnvelope(
  envelope: Pick<OnChainMultiEnvelope, "recipients">,
  address: string,
): number {
  const target = normalizeAddress(address);
  return envelope.recipients.findIndex((r) => r === target);
}

export async function fetchMultiEnvelope(
  suiClient: SuiClient,
  envelopeId: string,
): Promise<OnChainMultiEnvelope | null> {
  const obj = await suiClient.getObject({
    id: envelopeId,
    options: { showContent: true },
  });
  if (!obj.data?.content) return null;
  const f = (obj.data.content as { fields?: Record<string, unknown> }).fields;
  if (!f) return null;
  return decodeMultiEnvelopeFields(envelopeId, f);
}

// v3 envelopes are frozen objects, not owned. Inbox discovery is
// event-driven: scan MultiEnvelopePosted events filtered by the
// recipient address, then fetch the underlying objects in bulk.
export async function fetchMultiInbox(
  suiClient: SuiClient,
  packageId: string,
  ownerAddress: string,
  options: { limit?: number } = {},
): Promise<OnChainMultiEnvelope[]> {
  const target = normalizeAddress(ownerAddress);
  const limit = options.limit ?? 100;
  const eventType = `${packageId}::${MODULE_MULTI_ENVELOPES}::MultiEnvelopePosted`;
  const res = await suiClient.queryEvents({
    query: { MoveEventType: eventType },
    limit,
    order: "descending",
  });
  const ids: string[] = [];
  for (const e of res.data) {
    const j = (e as unknown as { parsedJson: Record<string, unknown> }).parsedJson;
    const recipients = Array.isArray(j.recipients) ? (j.recipients as unknown[]) : [];
    if (!recipients.some((r) => normalizeAddress(String(r ?? "")) === target)) continue;
    const id = String(j.envelope_id ?? "");
    if (id) ids.push(id);
  }
  if (ids.length === 0) return [];
  const objs = await suiClient.multiGetObjects({
    ids,
    options: { showContent: true },
  });
  const out: OnChainMultiEnvelope[] = [];
  for (const o of objs) {
    const id = o.data?.objectId;
    if (!id) continue;
    const f = (o.data?.content as { fields?: Record<string, unknown> } | undefined)?.fields;
    if (!f) continue;
    try {
      out.push(decodeMultiEnvelopeFields(id, f));
    } catch {
      // Unknown format/scheme — skip rather than fail the whole inbox fetch.
    }
  }
  out.sort((a, b) => b.createdAtMs - a.createdAtMs);
  return out;
}
