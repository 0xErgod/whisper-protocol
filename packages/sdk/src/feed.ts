import type { SuiClient } from "@mysten/sui/client";
import { MODULE, ENCRYPTION_SCHEME, LEGACY_ENVELOPE_FORMAT_VERSION } from "./constants.js";
import { normalizeAddress } from "./address.js";
import {
  bytesFromArray,
  detectEnvelopeFormatVersion,
  idFromUnknown,
  stringFromBytes,
} from "./envelope-codec.js";

export interface GasInfo {
  computationMist: bigint;
  storageMist: bigint;
  rebateMist: bigint;
  netMist: bigint;
}

export interface FeedKeyEvent {
  kind: "key";
  txDigest: string;
  timestampMs: number;
  keyObjectId: string | null;
  account: string;
  encryptionScheme: string;
  keyVersion: number;
  gas: GasInfo | null;
}

export interface FeedEnvelopeEvent {
  kind: "envelope";
  txDigest: string;
  timestampMs: number;
  envelopeId: string;
  formatVersion: number;
  sender: string;
  recipient: string;
  recipientKeyId: string | null;
  context: Uint8Array;
  schema: string;
  encryptionScheme: string;
  keyVersion: number;
  ephPubkey: Uint8Array;
  nonce: Uint8Array;
  ciphertext: Uint8Array;
  gas: GasInfo | null;
}

export type FeedEvent = FeedKeyEvent | FeedEnvelopeEvent;

interface SuiEventEnvelope {
  id: { txDigest: string; eventSeq: string };
  timestampMs?: string | null;
  parsedJson: Record<string, unknown>;
}

interface EnvelopeSnapshot {
  formatVersion: number;
  recipientKeyId: string | null;
  encryptionScheme: string;
  ephPubkey: Uint8Array;
  nonce: Uint8Array;
  ciphertext: Uint8Array;
}

async function fetchEnvelopeSnapshots(
  suiClient: SuiClient,
  envelopeIds: string[],
): Promise<Map<string, EnvelopeSnapshot>> {
  const out = new Map<string, EnvelopeSnapshot>();
  if (envelopeIds.length === 0) return out;
  const objs = await suiClient.multiGetObjects({
    ids: envelopeIds,
    options: { showContent: true },
  });
  for (const o of objs) {
    if (!o.data?.objectId || !o.data.content) continue;
    const f = (o.data.content as { fields?: Record<string, unknown> }).fields;
    if (!f) continue;
    out.set(o.data.objectId, {
      formatVersion: detectEnvelopeFormatVersion(f),
      recipientKeyId: idFromUnknown(f.recipient_key_id),
      encryptionScheme: "encryption_scheme" in f
        ? stringFromBytes(f.encryption_scheme)
        : ENCRYPTION_SCHEME,
      ephPubkey: bytesFromArray(f.eph_pubkey),
      nonce: bytesFromArray(f.nonce),
      ciphertext: bytesFromArray(f.ciphertext),
    });
  }
  return out;
}

async function fetchGasForTxs(
  suiClient: SuiClient,
  digests: string[],
): Promise<Map<string, GasInfo>> {
  const out = new Map<string, GasInfo>();
  if (digests.length === 0) return out;
  const unique = Array.from(new Set(digests));
  const chunkSize = 50;
  for (let i = 0; i < unique.length; i += chunkSize) {
    const chunk = unique.slice(i, i + chunkSize);
    const txs = await suiClient.multiGetTransactionBlocks({
      digests: chunk,
      options: { showEffects: true },
    });
    for (const t of txs) {
      const summary = t.effects?.gasUsed;
      if (!summary) continue;
      const computation = BigInt(summary.computationCost ?? "0");
      const storage = BigInt(summary.storageCost ?? "0");
      const rebate = BigInt(summary.storageRebate ?? "0");
      out.set(t.digest, {
        computationMist: computation,
        storageMist: storage,
        rebateMist: rebate,
        netMist: computation + storage - rebate,
      });
    }
  }
  return out;
}

export interface FetchFeedOptions {
  packageId: string;
  limit?: number;
  withGas?: boolean;
}

export async function fetchFeed(
  suiClient: SuiClient,
  options: FetchFeedOptions,
): Promise<FeedEvent[]> {
  const limit = options.limit ?? 50;
  const KEY_EVENT_TYPE = `${options.packageId}::${MODULE}::EncryptionKeyRegistered`;
  const ENVELOPE_EVENT_TYPE = `${options.packageId}::${MODULE}::EnvelopePosted`;

  const [keyRes, envRes] = await Promise.all([
    suiClient.queryEvents({
      query: { MoveEventType: KEY_EVENT_TYPE },
      limit,
      order: "descending",
    }),
    suiClient.queryEvents({
      query: { MoveEventType: ENVELOPE_EVENT_TYPE },
      limit,
      order: "descending",
    }),
  ]);

  const envelopeIds = (envRes.data as SuiEventEnvelope[]).map(
    (e) => String(e.parsedJson.envelope_id ?? ""),
  );
  const snapshots = await fetchEnvelopeSnapshots(suiClient, envelopeIds.filter(Boolean));

  const allDigests = [
    ...(keyRes.data as SuiEventEnvelope[]).map((e) => e.id.txDigest),
    ...(envRes.data as SuiEventEnvelope[]).map((e) => e.id.txDigest),
  ];
  const gas = options.withGas !== false
    ? await fetchGasForTxs(suiClient, allDigests)
    : new Map<string, GasInfo>();

  const keyEvents: FeedKeyEvent[] = (keyRes.data as SuiEventEnvelope[]).map((e) => {
    const j = e.parsedJson;
    return {
      kind: "key",
      txDigest: e.id.txDigest,
      timestampMs: Number(e.timestampMs ?? 0),
      keyObjectId: idFromUnknown(j.key_id),
      account: normalizeAddress(String(j.account ?? "")),
      encryptionScheme: stringFromBytes(j.encryption_scheme),
      keyVersion: Number(j.key_version ?? 0),
      gas: gas.get(e.id.txDigest) ?? null,
    };
  });

  const envelopeEvents: FeedEnvelopeEvent[] = (envRes.data as SuiEventEnvelope[]).map((e) => {
    const j = e.parsedJson;
    const envelopeId = String(j.envelope_id ?? "");
    const snapshot = snapshots.get(envelopeId);
    const formatVersion = "format_version" in j
      ? Number(j.format_version ?? 0)
      : snapshot?.formatVersion ?? LEGACY_ENVELOPE_FORMAT_VERSION;
    return {
      kind: "envelope",
      txDigest: e.id.txDigest,
      timestampMs: Number(e.timestampMs ?? 0),
      envelopeId,
      formatVersion,
      sender: normalizeAddress(String(j.sender ?? "")),
      recipient: normalizeAddress(String(j.recipient ?? "")),
      recipientKeyId: idFromUnknown(j.recipient_key_id) ?? snapshot?.recipientKeyId ?? null,
      context: bytesFromArray(j.context),
      schema: stringFromBytes(j.schema),
      encryptionScheme: "encryption_scheme" in j
        ? stringFromBytes(j.encryption_scheme)
        : snapshot?.encryptionScheme ?? ENCRYPTION_SCHEME,
      keyVersion: Number(j.key_version ?? 0),
      ephPubkey: snapshot?.ephPubkey ?? new Uint8Array(),
      nonce: snapshot?.nonce ?? new Uint8Array(),
      ciphertext: snapshot?.ciphertext ?? new Uint8Array(),
      gas: gas.get(e.id.txDigest) ?? null,
    };
  });

  const merged: FeedEvent[] = [...keyEvents, ...envelopeEvents];
  merged.sort((a, b) => b.timestampMs - a.timestampMs);
  return merged;
}
