import type { SuiClient } from "@mysten/sui/client";
import { normalizeAddress } from "./address.js";
import { MODULE_ENVELOPES } from "./constants.js";
import {
  assertSupportedEnvelopeFormatVersion,
  bytesArrayFromUnknown,
  bytesFromArray,
  decodeEnvelopeCompatibilityMetadata,
  detectEnvelopeFormatVersion,
  idArrayFromUnknown,
  isUnifiedEnvelopeFormatVersion,
  numberArrayFromUnknown,
  stringFromBytes,
  type EnvelopeCompatibilityMetadata,
} from "./envelope-codec.js";
import {
  UnsupportedEncryptionSchemeError,
  UnsupportedEnvelopeFormatVersionError,
} from "./errors.js";
import { supportsUnifiedEncryptionScheme } from "./suites-unified.js";

/**
 * On-chain shape of a v5 unified envelope.
 *
 * One struct, one lifecycle (always frozen), one cryptographic
 * construction (always hybrid). N=1 is a degenerate group of the
 * same primitive — no separate single-recipient code path.
 */
export interface OnChainV5Envelope extends EnvelopeCompatibilityMetadata {
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

function decodeV5EnvelopeFields(
  envelopeId: string,
  fields: Record<string, unknown>,
): OnChainV5Envelope {
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

/**
 * Decode a v5 envelope's on-chain fields into a typed object. Fails
 * closed if the format version is anything other than 5 — historical
 * v1/v2/v3 envelopes go through their own decoders so a v3 envelope
 * can never be silently mis-decoded as v5 or vice versa.
 */
export function decodeV5EnvelopeFieldsTyped(
  envelopeId: string,
  fields: Record<string, unknown>,
): OnChainV5Envelope {
  const formatVersion = detectEnvelopeFormatVersion(fields);
  assertSupportedEnvelopeFormatVersion(formatVersion);
  if (!isUnifiedEnvelopeFormatVersion(formatVersion)) {
    throw new UnsupportedEnvelopeFormatVersionError(formatVersion);
  }
  return decodeV5EnvelopeFields(envelopeId, fields);
}

export function recipientIndexInV5Envelope(
  envelope: Pick<OnChainV5Envelope, "recipients">,
  address: string,
): number {
  const target = normalizeAddress(address);
  return envelope.recipients.findIndex((r) => r === target);
}

export function canReadV5Envelope(
  envelope: Pick<OnChainV5Envelope, "formatVersion" | "encryptionScheme">,
): boolean {
  try {
    assertCanReadV5Envelope(envelope);
    return true;
  } catch {
    return false;
  }
}

export function assertCanReadV5Envelope(
  envelope: Pick<OnChainV5Envelope, "formatVersion" | "encryptionScheme">,
): void {
  assertSupportedEnvelopeFormatVersion(envelope.formatVersion);
  if (!isUnifiedEnvelopeFormatVersion(envelope.formatVersion)) {
    throw new UnsupportedEnvelopeFormatVersionError(envelope.formatVersion);
  }
  if (!supportsUnifiedEncryptionScheme(envelope.encryptionScheme)) {
    throw new UnsupportedEncryptionSchemeError(envelope.encryptionScheme);
  }
}

export async function fetchV5Envelope(
  suiClient: SuiClient,
  envelopeId: string,
): Promise<OnChainV5Envelope | null> {
  const obj = await suiClient.getObject({
    id: envelopeId,
    options: { showContent: true },
  });
  if (!obj.data?.content) return null;
  const f = (obj.data.content as { fields?: Record<string, unknown> }).fields;
  if (!f) return null;
  return decodeV5EnvelopeFieldsTyped(envelopeId, f);
}

/**
 * Recipient inbox for v5 envelopes.
 *
 * v5 envelopes are frozen — there's no single owner — so
 * `getOwnedObjects` doesn't surface them. Discovery is event-driven:
 * scan `EnvelopePosted` events filtered by recipient address, then
 * `multiGetObjects` to fetch the underlying envelopes in bulk.
 *
 * This is the same pattern v3 used for multi-recipient envelopes.
 * For v5 it's universal — direct messages and group messages share
 * one inbox query path.
 */
export async function fetchV5Inbox(
  suiClient: SuiClient,
  packageId: string,
  ownerAddress: string,
  options: { limit?: number } = {},
): Promise<OnChainV5Envelope[]> {
  const target = normalizeAddress(ownerAddress);
  const limit = options.limit ?? 100;
  const eventType = `${packageId}::${MODULE_ENVELOPES}::EnvelopePosted`;
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
  const out: OnChainV5Envelope[] = [];
  for (const o of objs) {
    const id = o.data?.objectId;
    if (!id) continue;
    const f = (o.data?.content as { fields?: Record<string, unknown> } | undefined)?.fields;
    if (!f) continue;
    try {
      out.push(decodeV5EnvelopeFieldsTyped(id, f));
    } catch {
      // Unknown format / scheme drift — skip rather than fail the
      // whole inbox fetch.
    }
  }
  out.sort((a, b) => b.createdAtMs - a.createdAtMs);
  return out;
}
