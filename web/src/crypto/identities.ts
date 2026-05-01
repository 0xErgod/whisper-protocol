// Thin re-export of address utilities from the SDK plus a "known address"
// label resolver scoped to the current wallet only. Demo characters
// (Alice/Bob/Charlie) and their seeds were removed in the wallet-derived
// keys migration.

import { normalizeAddress, shortAddress } from "@whisper-protocol/sdk";

export { normalizeAddress, shortAddress };

/**
 * Render an address as a label. Without per-character demo identities,
 * the only "known" address is the connected wallet (caller passes it in
 * via labelForAddress). For unknown addresses, returns a shortened form.
 */
export function labelForAddress(addr: string, knownLabels?: Record<string, string>): string {
  if (knownLabels) {
    const norm = normalizeAddress(addr);
    if (knownLabels[norm]) return knownLabels[norm]!;
  }
  return shortAddress(addr);
}

export function isKnown(addr: string, knownLabels?: Record<string, string>): boolean {
  if (!knownLabels) return false;
  return Boolean(knownLabels[normalizeAddress(addr)]);
}

// Bytes helpers re-exported for convenience.
export { bytesToHex, hexToBytes } from "@noble/hashes/utils";
