import type { SuiClient } from "@mysten/sui/client";
import {
  MODULE_COMMITMENTS,
  MODULE_ENVELOPES,
  MODULE_REGISTRY,
} from "./constants.js";
import { normalizeAddress } from "./address.js";
import {
  bytesArrayFromUnknown,
  bytesFromArray,
  detectEnvelopeFormatVersion,
  idArrayFromUnknown,
  idFromUnknown,
  numberArrayFromUnknown,
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

/**
 * v5 envelope event. The unified primitive: 1..N recipients, hybrid
 * construction. The legacy `kind: "envelope"` and
 * `kind: "multi-envelope"` variants from prior protocol versions are
 * not surfaced by this feed — the current deployment only emits v5.
 */
export interface FeedEnvelopeEvent {
  kind: "envelope";
  txDigest: string;
  timestampMs: number;
  envelopeId: string;
  formatVersion: number;
  sender: string;
  recipients: string[];
  recipientKeyIds: string[];
  recipientKeyVersions: number[];
  context: Uint8Array;
  schema: string;
  encryptionScheme: string;
  ephPubkey: Uint8Array;
  payloadNonce: Uint8Array;
  ciphertext: Uint8Array;
  wrappedKeys: Uint8Array[];
  wrapNonces: Uint8Array[];
  gas: GasInfo | null;
}

export interface FeedCommittedEvent {
  kind: "committed";
  txDigest: string;
  timestampMs: number;
  commitmentId: string;
  formatVersion: number;
  author: string;
  schema: string;
  hashScheme: string;
  commitment: Uint8Array;
  gas: GasInfo | null;
}

export interface FeedOpenedEvent {
  kind: "opened";
  txDigest: string;
  timestampMs: number;
  commitmentId: string;
  author: string;
  schema: string;
  hashScheme: string;
  commitment: Uint8Array;
  encodedSecret: Uint8Array;
  salt: Uint8Array;
  gas: GasInfo | null;
}

export type FeedEvent =
  | FeedKeyEvent
  | FeedEnvelopeEvent
  | FeedCommittedEvent
  | FeedOpenedEvent;

interface SuiEventEnvelope {
  id: { txDigest: string; eventSeq: string };
  timestampMs?: string | null;
  parsedJson: Record<string, unknown>;
}

interface EnvelopeSnapshot {
  formatVersion: number;
  encryptionScheme: string;
  ephPubkey: Uint8Array;
  payloadNonce: Uint8Array;
  ciphertext: Uint8Array;
  wrappedKeys: Uint8Array[];
  wrapNonces: Uint8Array[];
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
      encryptionScheme: stringFromBytes(f.encryption_scheme),
      ephPubkey: bytesFromArray(f.eph_pubkey),
      payloadNonce: bytesFromArray(f.payload_nonce),
      ciphertext: bytesFromArray(f.ciphertext),
      wrappedKeys: bytesArrayFromUnknown(f.wrapped_keys),
      wrapNonces: bytesArrayFromUnknown(f.wrap_nonces),
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
  const KEY_EVENT_TYPE = `${options.packageId}::${MODULE_REGISTRY}::EncryptionKeyRegistered`;
  const ENVELOPE_EVENT_TYPE = `${options.packageId}::${MODULE_ENVELOPES}::EnvelopePosted`;
  const COMMITTED_EVENT_TYPE = `${options.packageId}::${MODULE_COMMITMENTS}::SecretCommitted`;
  const OPENED_EVENT_TYPE = `${options.packageId}::${MODULE_COMMITMENTS}::SecretOpened`;

  const [keyRes, envRes, committedRes, openedRes] = await Promise.all([
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
    suiClient.queryEvents({
      query: { MoveEventType: COMMITTED_EVENT_TYPE },
      limit,
      order: "descending",
    }),
    suiClient.queryEvents({
      query: { MoveEventType: OPENED_EVENT_TYPE },
      limit,
      order: "descending",
    }),
  ]);

  const envelopeIds = (envRes.data as SuiEventEnvelope[]).map((e) =>
    String(e.parsedJson.envelope_id ?? ""),
  );
  const snapshots = await fetchEnvelopeSnapshots(suiClient, envelopeIds.filter(Boolean));

  const allDigests = [
    ...(keyRes.data as SuiEventEnvelope[]).map((e) => e.id.txDigest),
    ...(envRes.data as SuiEventEnvelope[]).map((e) => e.id.txDigest),
    ...(committedRes.data as SuiEventEnvelope[]).map((e) => e.id.txDigest),
    ...(openedRes.data as SuiEventEnvelope[]).map((e) => e.id.txDigest),
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
    const recipients = Array.isArray(j.recipients)
      ? (j.recipients as unknown[]).map((r) => normalizeAddress(String(r ?? "")))
      : [];
    return {
      kind: "envelope",
      txDigest: e.id.txDigest,
      timestampMs: Number(e.timestampMs ?? 0),
      envelopeId,
      formatVersion: Number(j.format_version ?? snapshot?.formatVersion ?? 5),
      sender: normalizeAddress(String(j.sender ?? "")),
      recipients,
      recipientKeyIds: idArrayFromUnknown(j.recipient_key_ids),
      recipientKeyVersions: numberArrayFromUnknown(j.recipient_key_versions),
      context: bytesFromArray(j.context),
      schema: stringFromBytes(j.schema),
      encryptionScheme: stringFromBytes(j.encryption_scheme),
      ephPubkey: snapshot?.ephPubkey ?? new Uint8Array(),
      payloadNonce: snapshot?.payloadNonce ?? new Uint8Array(),
      ciphertext: snapshot?.ciphertext ?? new Uint8Array(),
      wrappedKeys: snapshot?.wrappedKeys ?? [],
      wrapNonces: snapshot?.wrapNonces ?? [],
      gas: gas.get(e.id.txDigest) ?? null,
    };
  });

  const committedEvents: FeedCommittedEvent[] = (committedRes.data as SuiEventEnvelope[]).map((e) => {
    const j = e.parsedJson;
    return {
      kind: "committed",
      txDigest: e.id.txDigest,
      timestampMs: Number(e.timestampMs ?? 0),
      commitmentId: String(j.commitment_id ?? ""),
      formatVersion: Number(j.format_version ?? 1),
      author: normalizeAddress(String(j.author ?? "")),
      schema: stringFromBytes(j.schema),
      hashScheme: stringFromBytes(j.hash_scheme),
      commitment: bytesFromArray(j.commitment),
      gas: gas.get(e.id.txDigest) ?? null,
    };
  });

  const openedEvents: FeedOpenedEvent[] = (openedRes.data as SuiEventEnvelope[]).map((e) => {
    const j = e.parsedJson;
    return {
      kind: "opened",
      txDigest: e.id.txDigest,
      timestampMs: Number(e.timestampMs ?? 0),
      commitmentId: String(j.commitment_id ?? ""),
      author: normalizeAddress(String(j.author ?? "")),
      schema: stringFromBytes(j.schema),
      hashScheme: stringFromBytes(j.hash_scheme),
      commitment: bytesFromArray(j.commitment),
      encodedSecret: bytesFromArray(j.encoded_secret),
      salt: bytesFromArray(j.salt),
      gas: gas.get(e.id.txDigest) ?? null,
    };
  });

  const merged: FeedEvent[] = [
    ...keyEvents,
    ...envelopeEvents,
    ...committedEvents,
    ...openedEvents,
  ];
  merged.sort((a, b) => b.timestampMs - a.timestampMs);
  return merged;
}
