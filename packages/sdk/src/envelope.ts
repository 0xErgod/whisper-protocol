import type { SuiClient } from "@mysten/sui/client";
import { normalizeAddress } from "./address.js";
import { MODULE } from "./constants.js";

export interface OnChainEnvelope {
  envelopeId: string;
  sender: string;
  recipient: string;
  context: Uint8Array;
  schema: string;
  keyVersion: number;
  ephPubkey: Uint8Array;
  nonce: Uint8Array;
  ciphertext: Uint8Array;
  createdAtMs: number;
}

const decoder = new TextDecoder();

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
    const bin = atob(input);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }
  return new Uint8Array();
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
  return {
    envelopeId,
    sender: normalizeAddress(String(f.sender ?? "")),
    recipient: normalizeAddress(String(f.recipient ?? "")),
    context: bytesFromArray(f.context),
    schema: decoder.decode(bytesFromArray(f.schema)),
    keyVersion: Number(f.key_version ?? 0),
    ephPubkey: bytesFromArray(f.eph_pubkey),
    nonce: bytesFromArray(f.nonce),
    ciphertext: bytesFromArray(f.ciphertext),
    createdAtMs: Number(f.created_at_ms ?? 0),
  };
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
    out.push({
      envelopeId: id,
      sender: normalizeAddress(String(f.sender ?? "")),
      recipient: normalizeAddress(String(f.recipient ?? "")),
      context: bytesFromArray(f.context),
      schema: decoder.decode(bytesFromArray(f.schema)),
      keyVersion: Number(f.key_version ?? 0),
      ephPubkey: bytesFromArray(f.eph_pubkey),
      nonce: bytesFromArray(f.nonce),
      ciphertext: bytesFromArray(f.ciphertext),
      createdAtMs: Number(f.created_at_ms ?? 0),
    });
  }
  out.sort((a, b) => b.createdAtMs - a.createdAtMs);
  return out;
}

export { bytesFromArray };
