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
  const fields = await suiClient.getDynamicFields({ parentId: tableId, limit: 50 });
  if (fields.data.length === 0) return [];
  const objects = await suiClient.multiGetObjects({
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

export async function fetchRegistryEntry(
  suiClient: SuiClient,
  registryId: string,
  account: string,
): Promise<RegistryEntry | null> {
  const target = normalizeAddress(account);
  const all = await fetchRegistryEntries(suiClient, registryId);
  return all.find((e) => e.account === target) ?? null;
}
