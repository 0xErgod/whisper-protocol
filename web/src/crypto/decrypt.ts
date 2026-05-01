import { x25519 } from "@noble/curves/ed25519";
import { hkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha256";
import { chacha20poly1305 } from "@noble/ciphers/chacha";
import type { Identity } from "./identities";
import { normalizeAddress } from "./identities";

const INFO = new TextEncoder().encode("sui-secret-sharing-poc-v1");

// Mirrors the Rust derive_aead_key in crates/secret-sharing-cli/src/crypto.rs:
// HKDF-SHA256(salt = "{sender}->{recipient}", ikm = X25519 shared, info = protocol id) -> 32-byte key.
function deriveAeadKey(shared: Uint8Array, sender: string, recipient: string): Uint8Array {
  const salt = new TextEncoder().encode(`${sender}->${recipient}`);
  return hkdf(sha256, shared, salt, INFO, 32);
}

export interface EnvelopePayload {
  sender: string;
  recipient: string;
  ephPubkey: Uint8Array;
  nonce: Uint8Array;
  ciphertext: Uint8Array;
}

export function tryDecrypt(identity: Identity, env: EnvelopePayload): string | null {
  if (normalizeAddress(env.recipient) !== normalizeAddress(identity.suiAddress)) {
    return null;
  }
  try {
    const shared = x25519.getSharedSecret(identity.x25519PrivateKey, env.ephPubkey);
    const senderHex = normalizeAddress(env.sender);
    const recipientHex = normalizeAddress(env.recipient);
    const key = deriveAeadKey(shared, senderHex, recipientHex);
    const cipher = chacha20poly1305(key, env.nonce);
    const plain = cipher.decrypt(env.ciphertext);
    return new TextDecoder().decode(plain);
  } catch {
    return null;
  }
}
