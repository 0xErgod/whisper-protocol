import { sha512 } from "@noble/hashes/sha512";
import { x25519 } from "@noble/curves/ed25519";
import { hexToBytes, bytesToHex } from "@noble/hashes/utils";

export type CharacterName = "alice" | "bob" | "charlie";

export interface Identity {
  name: CharacterName;
  label: string;
  suiAddress: string;
  ed25519PrivateKey: Uint8Array;
  x25519PrivateKey: Uint8Array;
  x25519PublicKey: Uint8Array;
}

// These match the Ed25519 demo keys in the project's .env. Regenerate via
// `cargo run -- generate-env` and re-derive the Sui addresses if you change them.
const DEMO_KEYS: Record<CharacterName, { sui: string; ed25519PrivHex: string; label: string }> = {
  alice: {
    label: "ALICE",
    sui: "0xf4a988f613a08c5d4e8d56463ac1dba22bc12509a3a32031c549a2274b00ae73",
    ed25519PrivHex: "d34b2426b1567eb3a7b38156d39820b28da5a2e5da5a45145102d49588a6c108",
  },
  bob: {
    label: "BOB",
    sui: "0x73578a3bbabcd3b7d4490fbcdc3e9d1a46766268022d3a063b138ba61c6e1068",
    ed25519PrivHex: "39bfbb248c1e67e017c82d362c90e0c1d7dd6366c1c3651cb1c754f40d40fc67",
  },
  charlie: {
    label: "CHARLIE",
    sui: "0xd3c99880b24c309243e81324749ded9cf7e18f1ca2ea90bf7f68b0f407585442",
    ed25519PrivHex: "f86f95dfc04ce19028db5d52aacbcaf57f1e7c30f5b1fd28110bdf3c139de238",
  },
};

// Standard Ed25519 -> X25519 secret key conversion: SHA-512 the seed, take
// the first 32 bytes, then apply Curve25519 clamping. Same derivation that
// ed25519-dalek::SigningKey::to_curve25519_secret performs.
function ed25519SeedToX25519Secret(seed: Uint8Array): Uint8Array {
  const h = sha512(seed);
  const sk = h.slice(0, 32);
  sk[0] &= 248;
  sk[31] &= 127;
  sk[31] |= 64;
  return sk;
}

function buildIdentity(name: CharacterName): Identity {
  const meta = DEMO_KEYS[name];
  const ed25519PrivateKey = hexToBytes(meta.ed25519PrivHex);
  const x25519PrivateKey = ed25519SeedToX25519Secret(ed25519PrivateKey);
  const x25519PublicKey = x25519.getPublicKey(x25519PrivateKey);
  return {
    name,
    label: meta.label,
    suiAddress: meta.sui,
    ed25519PrivateKey,
    x25519PrivateKey,
    x25519PublicKey,
  };
}

export const IDENTITIES: Record<CharacterName, Identity> = {
  alice: buildIdentity("alice"),
  bob: buildIdentity("bob"),
  charlie: buildIdentity("charlie"),
};

export const IDENTITY_BY_ADDRESS = new Map<string, Identity>(
  Object.values(IDENTITIES).map((i) => [normalizeAddress(i.suiAddress), i]),
);

export function normalizeAddress(addr: string): string {
  if (!addr) return addr;
  const lower = addr.toLowerCase();
  return lower.startsWith("0x") ? lower : `0x${lower}`;
}

export function shortAddress(addr: string): string {
  const a = normalizeAddress(addr);
  if (a.length <= 12) return a;
  return `${a.slice(0, 6)}…${a.slice(-4)}`;
}

export function labelForAddress(addr: string): string {
  const id = IDENTITY_BY_ADDRESS.get(normalizeAddress(addr));
  return id ? id.label : shortAddress(addr);
}

export function isKnown(addr: string): boolean {
  return IDENTITY_BY_ADDRESS.has(normalizeAddress(addr));
}

// Bytes helpers re-exported for convenience.
export { bytesToHex, hexToBytes };
