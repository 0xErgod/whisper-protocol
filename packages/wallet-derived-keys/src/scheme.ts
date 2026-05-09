import { blake2b } from "@noble/hashes/blake2b";
import { bytesToHex, normalizeAddress } from "./utils.js";

/**
 * Sui signature schemes recognized by the wallet-standard. The flag byte
 * is what gets prefixed to the public key before BLAKE2b-hashing to derive
 * a Sui address.
 */
export const SUI_SIGNATURE_FLAGS = {
  ED25519: 0x00,
  Secp256k1: 0x01,
  Secp256r1: 0x02,
  MultiSig: 0x03,
  ZkLogin: 0x05,
  Passkey: 0x06,
} as const;

export type SuiSignatureScheme = keyof typeof SUI_SIGNATURE_FLAGS;

/**
 * Compute a Sui address from a (flag, publicKey) pair.
 *
 * Sui address = `BLAKE2b-256(flag_byte || pubkey_bytes)` rendered as hex
 * with a `0x` prefix. See https://docs.sui.io/concepts/cryptography/transaction-auth/keys-addresses.
 */
export function suiAddressFromPublicKey(
  flag: number,
  publicKey: Uint8Array,
): string {
  const buf = new Uint8Array(1 + publicKey.length);
  buf[0] = flag;
  buf.set(publicKey, 1);
  const hash = blake2b(buf, { dkLen: 32 });
  return `0x${bytesToHex(hash)}`;
}

/**
 * Detect the signature scheme of a connected wallet account by trying
 * each scheme's address derivation and matching against the account's
 * own address.
 *
 * Wallets expose `account.publicKey` in one of two shapes:
 *   - **Raw**: just the public key bytes (32 for Ed25519, 33 for
 *     Secp256k1/r1, etc.). The address is `BLAKE2b(flag || raw)`.
 *   - **Flagged**: the flag byte is already prepended to the key bytes.
 *     The address is `BLAKE2b(flagged)`.
 *
 * Both shapes show up in the wild — Slush, for example, prepends the
 * flag — so we try both interpretations before giving up. Returns null
 * if no combination matches, which usually means the account uses a
 * scheme we don't recognize (custom multisig, future scheme) and is a
 * signal to refuse derivation.
 */
export function detectSchemeFromAccount(account: {
  address: string;
  publicKey: ArrayLike<number>;
}): SuiSignatureScheme | null {
  const target = normalizeAddress(account.address);
  const bytes = Uint8Array.from(account.publicKey);

  // Raw-pubkey interpretation: try every known flag.
  for (const [scheme, flag] of Object.entries(SUI_SIGNATURE_FLAGS)) {
    if (suiAddressFromPublicKey(flag, bytes) === target) {
      return scheme as SuiSignatureScheme;
    }
  }

  // Flagged-pubkey interpretation: assume the first byte is already the
  // flag, hash the whole thing as-is, and check against the address.
  // We still verify the leading byte matches a known scheme so we don't
  // accept arbitrary inputs that happen to BLAKE2b-collide.
  if (bytes.length > 1) {
    const leadingFlag = bytes[0]!;
    const matchedScheme = (Object.entries(SUI_SIGNATURE_FLAGS) as Array<
      [SuiSignatureScheme, number]
    >).find(([, flag]) => flag === leadingFlag)?.[0];
    if (matchedScheme) {
      const hash = blake2b(bytes, { dkLen: 32 });
      if (`0x${bytesToHex(hash)}` === target) {
        return matchedScheme;
      }
    }
  }

  return null;
}

/**
 * Throw if the connected account is not Ed25519. Whisper's wallet-signature
 * derivation requires deterministic signing; only Ed25519 (Sui's default)
 * is deterministic by spec. ECDSA wallets that don't implement RFC 6979,
 * zkLogin signatures, and passkey signatures may all produce different
 * bytes for the same `(privateKey, message)` — which would silently make
 * every session derive a different encryption key and lose access to
 * previously-encrypted messages.
 *
 * Sui's default wallet generates Ed25519 keys, so in practice this
 * excludes very few users.
 */
export function requireEd25519(account: {
  address: string;
  publicKey: ArrayLike<number>;
}): SuiSignatureScheme {
  const scheme = detectSchemeFromAccount(account);
  if (scheme === null) {
    throw new Error(
      `Whisper requires an Ed25519 wallet. Could not determine the signature scheme of the connected account ${normalizeAddress(account.address)} — its public key shape is not one Whisper recognizes (Ed25519, Secp256k1, Secp256r1, MultiSig, ZkLogin, or Passkey).`,
    );
  }
  if (scheme !== "ED25519") {
    throw new Error(
      `Whisper requires an Ed25519 wallet. The connected wallet uses ${scheme}, which does not produce deterministic signatures — encryption keys derived from it would change between sessions and previously-encrypted messages would become undecryptable. Sui's default wallet generates Ed25519 keys; switch wallets or generate a fresh Ed25519 account.`,
    );
  }
  return scheme;
}
