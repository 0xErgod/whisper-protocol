import { client } from "./client";
import { MODULE, PACKAGE_ID, REGISTRY_ID } from "./config";
import { normalizeAddress } from "../crypto/identities";

export interface RegistryEntry {
  account: string;
  encryptionScheme: string;
  encryptionPubkey: Uint8Array;
  keyVersion: number;
  rotatedAtMs: number;
}

const decoder = new TextDecoder();

function base64ToBytes(b64: string): Uint8Array {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function fieldValue(content: unknown, key: string): unknown {
  if (
    typeof content !== "object" ||
    content === null ||
    !("dataType" in (content as Record<string, unknown>)) ||
    (content as { dataType?: string }).dataType !== "moveObject"
  ) {
    return undefined;
  }
  const fields = (content as { fields?: Record<string, unknown> }).fields;
  return fields ? fields[key] : undefined;
}

export async function fetchRegistryTableId(): Promise<string> {
  const obj = await client.getObject({
    id: REGISTRY_ID,
    options: { showContent: true },
  });
  const content = obj.data?.content;
  const entries = fieldValue(content, "entries") as
    | { fields?: { id?: { id?: string } } }
    | undefined;
  const tableId = entries?.fields?.id?.id;
  if (!tableId) throw new Error("Could not locate KeyRegistry table id");
  return tableId;
}

export async function fetchRegistryEntries(): Promise<RegistryEntry[]> {
  const tableId = await fetchRegistryTableId();
  const fields = await client.getDynamicFields({ parentId: tableId, limit: 50 });
  if (fields.data.length === 0) return [];
  const objects = await client.multiGetObjects({
    ids: fields.data.map((f) => f.objectId),
    options: { showContent: true },
  });

  const entries: RegistryEntry[] = [];
  for (const o of objects) {
    const content = o.data?.content;
    const name = fieldValue(content, "name") as string | undefined;
    const value = fieldValue(content, "value") as
      | {
          fields?: {
            encryption_scheme?: number[];
            encryption_pubkey?: number[];
            key_version?: string;
            rotated_at_ms?: string;
          };
        }
      | undefined;
    if (!name || !value?.fields) continue;
    const f = value.fields;
    entries.push({
      account: normalizeAddress(name),
      encryptionScheme: decoder.decode(Uint8Array.from(f.encryption_scheme ?? [])),
      encryptionPubkey: Uint8Array.from(f.encryption_pubkey ?? []),
      keyVersion: Number(f.key_version ?? 0),
      rotatedAtMs: Number(f.rotated_at_ms ?? 0),
    });
  }
  entries.sort((a, b) => a.rotatedAtMs - b.rotatedAtMs);
  return entries;
}

export type FeedEventKind = "key" | "envelope";

export interface FeedKeyEvent {
  kind: "key";
  txDigest: string;
  timestampMs: number;
  account: string;
  encryptionScheme: string;
  keyVersion: number;
}

export interface FeedEnvelopeEvent {
  kind: "envelope";
  txDigest: string;
  timestampMs: number;
  envelopeId: string;
  sender: string;
  recipient: string;
  context: Uint8Array;
  schema: string;
  keyVersion: number;
  ephPubkey: Uint8Array;
  nonce: Uint8Array;
  ciphertext: Uint8Array;
}

export type FeedEvent = FeedKeyEvent | FeedEnvelopeEvent;

interface SuiEventEnvelope {
  id: { txDigest: string; eventSeq: string };
  type: string;
  timestampMs?: string | null;
  parsedJson: Record<string, unknown>;
  bcs?: string;
}

const KEY_EVENT_TYPE = `${PACKAGE_ID}::${MODULE}::EncryptionKeyRegistered`;
const ENVELOPE_EVENT_TYPE = `${PACKAGE_ID}::${MODULE}::EnvelopePosted`;

function bytesFromArray(input: unknown): Uint8Array {
  if (input instanceof Uint8Array) return input;
  if (Array.isArray(input)) return Uint8Array.from(input as number[]);
  if (typeof input === "string") {
    if (input.startsWith("0x")) {
      const hex = input.slice(2);
      const out = new Uint8Array(hex.length / 2);
      for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
      return out;
    }
    return base64ToBytes(input);
  }
  return new Uint8Array();
}

function parseKeyEvent(e: SuiEventEnvelope): FeedKeyEvent {
  const j = e.parsedJson;
  const schemeBytes = bytesFromArray(j["encryption_scheme"]);
  return {
    kind: "key",
    txDigest: e.id.txDigest,
    timestampMs: Number(e.timestampMs ?? 0),
    account: normalizeAddress(String(j["account"] ?? "")),
    encryptionScheme: decoder.decode(schemeBytes),
    keyVersion: Number(j["key_version"] ?? 0),
  };
}

function parseEnvelopeEvent(
  e: SuiEventEnvelope,
  enrich: Map<string, EnvelopeFromObject>,
): FeedEnvelopeEvent {
  const j = e.parsedJson;
  const envelopeId = String(j["envelope_id"] ?? "");
  const meta = enrich.get(envelopeId);
  const schemaBytes = bytesFromArray(j["schema"]);
  const contextBytes = bytesFromArray(j["context"]);
  return {
    kind: "envelope",
    txDigest: e.id.txDigest,
    timestampMs: Number(e.timestampMs ?? 0),
    envelopeId,
    sender: normalizeAddress(String(j["sender"] ?? "")),
    recipient: normalizeAddress(String(j["recipient"] ?? "")),
    context: contextBytes,
    schema: decoder.decode(schemaBytes),
    keyVersion: Number(j["key_version"] ?? 0),
    ephPubkey: meta?.ephPubkey ?? new Uint8Array(),
    nonce: meta?.nonce ?? new Uint8Array(),
    ciphertext: meta?.ciphertext ?? new Uint8Array(),
  };
}

interface EnvelopeFromObject {
  ephPubkey: Uint8Array;
  nonce: Uint8Array;
  ciphertext: Uint8Array;
}

async function fetchEnvelopeBodies(
  envelopeIds: string[],
): Promise<Map<string, EnvelopeFromObject>> {
  if (envelopeIds.length === 0) return new Map();
  const objs = await client.multiGetObjects({
    ids: envelopeIds,
    options: { showContent: true },
  });
  const map = new Map<string, EnvelopeFromObject>();
  for (const o of objs) {
    if (!o.data?.objectId || !o.data.content) continue;
    const f = (o.data.content as { fields?: Record<string, unknown> }).fields;
    if (!f) continue;
    map.set(o.data.objectId, {
      ephPubkey: bytesFromArray(f.eph_pubkey),
      nonce: bytesFromArray(f.nonce),
      ciphertext: bytesFromArray(f.ciphertext),
    });
  }
  return map;
}

export async function fetchFeed(): Promise<FeedEvent[]> {
  const [keyRes, envRes] = await Promise.all([
    client.queryEvents({
      query: { MoveEventType: KEY_EVENT_TYPE },
      limit: 50,
      order: "descending",
    }),
    client.queryEvents({
      query: { MoveEventType: ENVELOPE_EVENT_TYPE },
      limit: 50,
      order: "descending",
    }),
  ]);

  const envelopeIds = (envRes.data as SuiEventEnvelope[]).map(
    (e) => String(e.parsedJson["envelope_id"] ?? ""),
  );
  // Some envelopes may already be deleted; multiGetObjects tolerates that and
  // returns errored entries we skip in fetchEnvelopeBodies.
  const bodies = await fetchEnvelopeBodies(envelopeIds.filter(Boolean));

  const keyEvents = (keyRes.data as SuiEventEnvelope[]).map(parseKeyEvent);
  const envelopeEvents = (envRes.data as SuiEventEnvelope[]).map((e) =>
    parseEnvelopeEvent(e, bodies),
  );

  const merged: FeedEvent[] = [...keyEvents, ...envelopeEvents];
  merged.sort((a, b) => b.timestampMs - a.timestampMs);
  return merged;
}
