import type { SuiClient } from "@mysten/sui/client";
import { normalizeAddress } from "./address.js";

export interface RegistryEntry {
  account: string;
  encryptionScheme: string;
  encryptionPubkey: Uint8Array;
  keyVersion: number;
  rotatedAtMs: number;
}

const decoder = new TextDecoder();

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
  encryption_scheme?: number[];
  encryption_pubkey?: number[];
  key_version?: string;
  rotated_at_ms?: string;
}

function decodeKeyEntry(
  account: string,
  fields: RawKeyEntryFields,
): RegistryEntry {
  return {
    account: normalizeAddress(account),
    encryptionScheme: decoder.decode(Uint8Array.from(fields.encryption_scheme ?? [])),
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

/**
 * Fetch every registered key.
 *
 * Pages through `getDynamicFields` with the default page size, then
 * batch-loads each field object via `multiGetObjects`. There is no
 * 50-entry cap. For very large registries the page-by-page RPC cost
 * scales linearly with the registry size; if you only need one entry,
 * use `fetchRegistryEntry` instead — that's a single direct lookup.
 *
 * Entries are returned sorted by `rotatedAtMs` ascending.
 */
export async function fetchRegistryEntries(
  suiClient: SuiClient,
  registryId: string,
): Promise<RegistryEntry[]> {
  const tableId = await fetchRegistryTableId(suiClient, registryId);

  // Walk every page. The fullnode caps each page at QUERY_MAX_RESULT_LIMIT
  // (~50 by default); we keep paging until hasNextPage is false.
  const fieldObjectIds: string[] = [];
  let cursor: string | null | undefined = undefined;
  // Hard upper bound to avoid an infinite loop if the fullnode misbehaves.
  // 200 pages × 50/page = 10,000 entries; well past anything realistic.
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

  // multiGetObjects has its own ~50-id cap per call — chunk to be safe.
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

/**
 * Fetch a single account's registered key in one RPC round trip.
 *
 * Uses `getDynamicFieldObject` keyed directly on the address rather
 * than fetching the whole registry and filtering — so this is correct
 * regardless of how many entries the registry holds and is cheaper
 * than `fetchRegistryEntries` even at small N.
 *
 * Returns `null` if the account has not registered.
 */
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
    // Sui fullnodes return an RPC error rather than `data: null` for
    // missing dynamic fields. Catch the not-found case and translate
    // to null; let any other error propagate.
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
