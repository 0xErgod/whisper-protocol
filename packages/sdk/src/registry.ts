import type { SuiClient } from "@mysten/sui/client";
import { normalizeAddress } from "./address.js";
import { idFromUnknown, stringFromBytes } from "./envelope-codec.js";

export interface RegistryEntry {
  account: string;
  encryptionScheme: string;
  encryptionPubkey: Uint8Array;
  currentKeyId: string;
  keyVersion: number;
  rotatedAtMs: number;
}

export interface EncryptionKeyRecord {
  keyObjectId: string;
  account: string;
  encryptionScheme: string;
  encryptionPubkey: Uint8Array;
  keyVersion: number;
  rotatedAtMs: number;
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

interface RawKeyEntryFields {
  encryption_scheme?: unknown;
  encryption_pubkey?: number[];
  current_key_id?: unknown;
  key_version?: string;
  rotated_at_ms?: string;
}

interface RawEncryptionKeyFields extends RawKeyEntryFields {
  account?: string;
}

function decodeKeyEntry(account: string, fields: RawKeyEntryFields): RegistryEntry {
  return {
    account: normalizeAddress(account),
    encryptionScheme: stringFromBytes(fields.encryption_scheme),
    encryptionPubkey: Uint8Array.from(fields.encryption_pubkey ?? []),
    currentKeyId: idFromUnknown(fields.current_key_id) ?? "",
    keyVersion: Number(fields.key_version ?? 0),
    rotatedAtMs: Number(fields.rotated_at_ms ?? 0),
  };
}

function decodeEncryptionKeyRecord(
  keyObjectId: string,
  fields: RawEncryptionKeyFields,
): EncryptionKeyRecord {
  return {
    keyObjectId,
    account: normalizeAddress(String(fields.account ?? "")),
    encryptionScheme: stringFromBytes(fields.encryption_scheme),
    encryptionPubkey: Uint8Array.from(fields.encryption_pubkey ?? []),
    keyVersion: Number(fields.key_version ?? 0),
    rotatedAtMs: Number(fields.rotated_at_ms ?? 0),
  };
}

async function fetchRegistryTableId(suiClient: SuiClient, registryId: string): Promise<string> {
  const obj = await suiClient.getObject({
    id: registryId,
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

export async function fetchRegistryEntries(
  suiClient: SuiClient,
  registryId: string,
): Promise<RegistryEntry[]> {
  const tableId = await fetchRegistryTableId(suiClient, registryId);
  const fieldObjectIds: string[] = [];
  let cursor: string | null | undefined;
  const MAX_PAGES = 200;
  for (let page = 0; page < MAX_PAGES; page++) {
    const res = await suiClient.getDynamicFields({
      parentId: tableId,
      cursor,
    });
    for (const f of res.data) fieldObjectIds.push(f.objectId);
    if (!res.hasNextPage || !res.nextCursor) break;
    cursor = res.nextCursor;
  }
  if (fieldObjectIds.length === 0) return [];

  const CHUNK = 50;
  const entries: RegistryEntry[] = [];
  for (let i = 0; i < fieldObjectIds.length; i += CHUNK) {
    const chunk = fieldObjectIds.slice(i, i + CHUNK);
    const objects = await suiClient.multiGetObjects({
      ids: chunk,
      options: { showContent: true },
    });
    for (const o of objects) {
      const content = o.data?.content;
      const name = fieldValue(content, "name") as string | undefined;
      const value = fieldValue(content, "value") as
        | { fields?: RawKeyEntryFields }
        | undefined;
      if (!name || !value?.fields) continue;
      entries.push(decodeKeyEntry(name, value.fields));
    }
  }

  entries.sort((a, b) => a.rotatedAtMs - b.rotatedAtMs);
  return entries;
}

export async function fetchRegistryEntry(
  suiClient: SuiClient,
  registryId: string,
  account: string,
): Promise<RegistryEntry | null> {
  const tableId = await fetchRegistryTableId(suiClient, registryId);
  const target = normalizeAddress(account);
  let obj;
  try {
    obj = await suiClient.getDynamicFieldObject({
      parentId: tableId,
      name: { type: "address", value: target },
    });
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    if (
      msg.includes("dynamic field") ||
      msg.includes("not found") ||
      msg.includes("does not exist")
    ) {
      return null;
    }
    throw e;
  }
  if (obj.error || !obj.data?.content) return null;
  const value = fieldValue(obj.data.content, "value") as
    | { fields?: RawKeyEntryFields }
    | undefined;
  if (!value?.fields) return null;
  return decodeKeyEntry(target, value.fields);
}

export async function fetchEncryptionKeyRecord(
  suiClient: SuiClient,
  keyObjectId: string,
): Promise<EncryptionKeyRecord | null> {
  const obj = await suiClient.getObject({
    id: keyObjectId,
    options: { showContent: true },
  });
  const fields = (obj.data?.content as { fields?: RawEncryptionKeyFields } | undefined)?.fields;
  if (!fields) return null;
  return decodeEncryptionKeyRecord(keyObjectId, fields);
}
