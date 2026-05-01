/**
 * Canonical message construction for wallet-signature-derived encryption keys.
 *
 * Locked byte-for-byte. UTF-8, LF line endings, NO trailing newline. Any
 * change here invalidates every previously-derived encryption keypair.
 *
 * See specs/wallet-signature-derived-keys.md for the rationale and the
 * full threat model.
 */

const PROTOCOL_NAME = "whisper-protocol";

export interface CanonicalMessageInput {
  /** Sui address of the wallet. Lowercased and `0x`-prefixed inside. */
  address: string;
  /**
   * Derivation version. Bumping this is the only supported way to derive
   * a new encryption keypair from the same wallet. Defaults to 1.
   */
  version?: number;
  /**
   * Scope tag. `root` for the default per-wallet keypair. Future
   * per-conversation derivations will use `dm:0xabc…`.
   */
  scope?: string;
  /** Defaults to "encryption-keypair". */
  purpose?: string;
}

function normalizeAddress(addr: string): string {
  if (!addr) return addr;
  const lower = addr.toLowerCase();
  return lower.startsWith("0x") ? lower : `0x${lower}`;
}

export function canonicalMessage(input: CanonicalMessageInput): string {
  const address = normalizeAddress(input.address);
  const version = input.version ?? 1;
  const scope = input.scope ?? "root";
  const purpose = input.purpose ?? "encryption-keypair";

  // Layout:
  //   line 1: protocol name
  //   line 2: version: <n>
  //   line 3: purpose: <p>
  //   line 4: address: <0x...>
  //   line 5: scope: <s>
  // No trailing newline. UTF-8.
  return [
    PROTOCOL_NAME,
    `version: ${version}`,
    `purpose: ${purpose}`,
    `address: ${address}`,
    `scope: ${scope}`,
  ].join("\n");
}

export function canonicalMessageBytes(input: CanonicalMessageInput): Uint8Array {
  return new TextEncoder().encode(canonicalMessage(input));
}
