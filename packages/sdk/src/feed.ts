// Read-side aggregator: queries the on-chain event log for the four
// event types this protocol emits and merges them into a single
// time-sorted feed for dApps to display.
//
// Event shapes match the modules they come from one-for-one:
//
//   EncryptionKeyRegistered  ← whisper_protocol::registry
//   EnvelopePosted           ← whisper_protocol::envelopes
//   SecretCommitted          ← whisper_protocol::commitments
//   SecretOpened             ← whisper_protocol::commitments
//
// All field elements arrive from Sui JSON-RPC as decimal strings
// (chain's `u256` encoding) — we keep them as strings end-to-end.

import type { SuiClient } from "@mysten/sui/client";
import {
  MODULE_COMMITMENTS,
  MODULE_ENVELOPES,
  MODULE_REGISTRY,
} from "./constants.js";
import { normalizeAddress } from "./address.js";

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
  pubkeyX: string;
  pubkeyY: string;
  keyVersion: number;
  gas: GasInfo | null;
}

export interface FeedEnvelopeEvent {
  kind: "envelope";
  txDigest: string;
  timestampMs: number;
  envelopeObjectId: string;
  sender: string;
  recipient: string;
  recipientKeyId: string;
  recipientKeyVersion: number;
  senderPkX: string;
  senderPkY: string;
  recipientPkX: string;
  recipientPkY: string;
  envelopeId: string;
  encodingId: string;
  macTag: string;
  gas: GasInfo | null;
}

export interface FeedCommittedEvent {
  kind: "committed";
  txDigest: string;
  timestampMs: number;
  commitmentId: string;
  author: string;
  encodingId: string;
  commitmentX: string;
  commitmentY: string;
  gas: GasInfo | null;
}

export interface FeedOpenedEvent {
  kind: "opened";
  txDigest: string;
  timestampMs: number;
  commitmentId: string;
  author: string;
  encodingId: string;
  commitmentX: string;
  commitmentY: string;
  stream: string[];
  blinding: string;
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

function idFromUnknown(raw: unknown): string | null {
  if (typeof raw === "string") return raw;
  if (raw && typeof raw === "object" && "id" in (raw as Record<string, unknown>)) {
    const inner = (raw as { id?: unknown }).id;
    if (typeof inner === "string") return inner;
  }
  return null;
}

function stringArrayOf(raw: unknown): string[] {
  if (!Array.isArray(raw)) return [];
  return (raw as unknown[]).map((x) => String(x ?? ""));
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
      pubkeyX: String(j.pubkey_x ?? "0"),
      pubkeyY: String(j.pubkey_y ?? "0"),
      keyVersion: Number(j.key_version ?? 0),
      gas: gas.get(e.id.txDigest) ?? null,
    };
  });

  const envelopeEvents: FeedEnvelopeEvent[] = (envRes.data as SuiEventEnvelope[]).map((e) => {
    const j = e.parsedJson;
    return {
      kind: "envelope",
      txDigest: e.id.txDigest,
      timestampMs: Number(e.timestampMs ?? 0),
      envelopeObjectId: String(j.envelope_object_id ?? ""),
      sender: normalizeAddress(String(j.sender ?? "")),
      recipient: normalizeAddress(String(j.recipient ?? "")),
      recipientKeyId: String(j.recipient_key_id ?? ""),
      recipientKeyVersion: Number(j.recipient_key_version ?? 0),
      senderPkX: String(j.sender_pk_x ?? "0"),
      senderPkY: String(j.sender_pk_y ?? "0"),
      recipientPkX: String(j.recipient_pk_x ?? "0"),
      recipientPkY: String(j.recipient_pk_y ?? "0"),
      envelopeId: String(j.envelope_id ?? "0"),
      encodingId: String(j.encoding_id ?? "0"),
      macTag: String(j.mac_tag ?? "0"),
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
      author: normalizeAddress(String(j.author ?? "")),
      encodingId: String(j.encoding_id ?? "0"),
      commitmentX: String(j.commitment_x ?? "0"),
      commitmentY: String(j.commitment_y ?? "0"),
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
      encodingId: String(j.encoding_id ?? "0"),
      commitmentX: String(j.commitment_x ?? "0"),
      commitmentY: String(j.commitment_y ?? "0"),
      stream: stringArrayOf(j.stream),
      blinding: String(j.blinding ?? "0"),
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
