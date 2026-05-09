import { blake2b } from "@noble/hashes/blake2b";
import { bytesToHex, hexToBytes, randomBytes } from "@noble/hashes/utils";
import { Transaction } from "@mysten/sui/transactions";
import type { SuiClient } from "@mysten/sui/client";
import { normalizeAddress } from "./address.js";
import {
  CLOCK_ID,
  COMMITMENT_DOMAIN_V1,
  CURRENT_COMMITMENT_FORMAT_VERSION,
  CURRENT_ENVELOPE_FORMAT_VERSION,
  HASH_SCHEME_BLAKE2B_256,
  MODULE_COMMITMENTS,
  MODULE_ENVELOPES,
  SCHEMA_COMMITMENT_OPENING_V1,
} from "./constants.js";
import { encryptForRecipientsV5 } from "./encrypt-unified.js";
import { bytesFromArray, stringFromBytes } from "./envelope-codec.js";
import {
  fetchV5Inbox,
  recipientIndexInV5Envelope,
  type OnChainV5Envelope,
} from "./envelope-unified.js";
import { requireUnifiedEncryptionSuite } from "./suites-unified.js";
import type { RegistryEntry } from "./registry.js";

export interface OnChainCommitment {
  commitmentId: string;
  formatVersion: number;
  author: string;
  schema: string;
  hashScheme: string;
  commitment: Uint8Array;
  createdAtMs: number;
  opened: boolean;
  openedAtMs: number;
}

export interface Opening {
  encodedSecret: Uint8Array;
  salt: Uint8Array;
  commitment: Uint8Array;
}

export interface BuildCommitTxArgs {
  packageId: string;
  schema: string;
  hashScheme?: string;
  commitment: Uint8Array;
}

export interface BuildOpenTxArgs {
  packageId: string;
  commitmentObjectId: string;
  encodedSecret: Uint8Array;
  salt: Uint8Array;
}

const DOMAIN_BYTES = new TextEncoder().encode(COMMITMENT_DOMAIN_V1);

/**
 * Stable byte encoding for a text secret.
 *
 * Per [provable-shared-secrets-extensions.md], text secrets are
 * UTF-8 with line endings normalized to `\n`. Other normalizations
 * are intentionally NOT applied so the user's text round-trips
 * exactly.
 */
export function encodeTextSecret(text: string): Uint8Array {
  const normalized = text.replace(/\r\n/g, "\n").replace(/\r/g, "\n");
  return new TextEncoder().encode(normalized);
}

/**
 * Compute commitment bytes for an already-encoded secret.
 *
 * `commitment = Blake2b-256(domain || encoded_secret || salt)`
 *
 * The domain prefix prevents cross-protocol collisions; the salt
 * prevents brute-force opening of low-entropy secrets like
 * `attack=north`.
 */
export function commitmentHash(
  encodedSecret: Uint8Array,
  salt: Uint8Array,
): Uint8Array {
  const buffer = new Uint8Array(DOMAIN_BYTES.length + encodedSecret.length + salt.length);
  buffer.set(DOMAIN_BYTES, 0);
  buffer.set(encodedSecret, DOMAIN_BYTES.length);
  buffer.set(salt, DOMAIN_BYTES.length + encodedSecret.length);
  return blake2b(buffer, { dkLen: 32 });
}

/**
 * Generate a fresh salt and produce the commitment bytes for it.
 *
 * The returned `salt` MUST be stored alongside `encodedSecret` to
 * later open the commitment. Losing it means the commitment can
 * never be re-opened by anyone.
 */
export function createCommitment(encodedSecret: Uint8Array): {
  commitment: Uint8Array;
  salt: Uint8Array;
} {
  const salt = randomBytes(32);
  const commitment = commitmentHash(encodedSecret, salt);
  return { commitment, salt };
}

/**
 * Verify that an opening matches a previously-posted commitment.
 *
 * Re-hashes `(domain || encoded_secret || salt)` and compares to the
 * commitment bytes byte-by-byte. Returns false on any mismatch
 * including length mismatches; never throws.
 */
export function verifyOpening(
  encodedSecret: Uint8Array,
  salt: Uint8Array,
  expectedCommitment: Uint8Array,
): boolean {
  const computed = commitmentHash(encodedSecret, salt);
  if (computed.length !== expectedCommitment.length) return false;
  let acc = 0;
  for (let i = 0; i < computed.length; i++) {
    acc |= computed[i]! ^ expectedCommitment[i]!;
  }
  return acc === 0;
}

export function buildCommitTx(args: BuildCommitTxArgs): Transaction {
  const tx = new Transaction();
  const schemaBytes = new TextEncoder().encode(args.schema);
  const hashSchemeBytes = new TextEncoder().encode(
    args.hashScheme ?? HASH_SCHEME_BLAKE2B_256,
  );
  tx.moveCall({
    target: `${args.packageId}::${MODULE_COMMITMENTS}::commit_secret`,
    arguments: [
      tx.pure.vector("u8", Array.from(schemaBytes)),
      tx.pure.vector("u8", Array.from(hashSchemeBytes)),
      tx.pure.vector("u8", Array.from(args.commitment)),
      tx.object(CLOCK_ID),
    ],
  });
  return tx;
}

export function buildOpenTx(args: BuildOpenTxArgs): Transaction {
  const tx = new Transaction();
  tx.moveCall({
    target: `${args.packageId}::${MODULE_COMMITMENTS}::open_secret`,
    arguments: [
      tx.object(args.commitmentObjectId),
      tx.pure.vector("u8", Array.from(args.encodedSecret)),
      tx.pure.vector("u8", Array.from(args.salt)),
      tx.object(CLOCK_ID),
    ],
  });
  return tx;
}

export function decodeCommitmentFields(
  commitmentId: string,
  fields: Record<string, unknown>,
): OnChainCommitment {
  return {
    commitmentId,
    formatVersion: Number(fields.format_version ?? CURRENT_COMMITMENT_FORMAT_VERSION),
    author: normalizeAddress(String(fields.author ?? "")),
    schema: stringFromBytes(fields.schema),
    hashScheme: stringFromBytes(fields.hash_scheme),
    commitment: bytesFromArray(fields.commitment),
    createdAtMs: Number(fields.created_at_ms ?? 0),
    opened: Boolean(fields.opened),
    openedAtMs: Number(fields.opened_at_ms ?? 0),
  };
}

export async function fetchCommitment(
  suiClient: SuiClient,
  commitmentObjectId: string,
): Promise<OnChainCommitment | null> {
  const obj = await suiClient.getObject({
    id: commitmentObjectId,
    options: { showContent: true },
  });
  if (!obj.data?.content) return null;
  const f = (obj.data.content as { fields?: Record<string, unknown> }).fields;
  if (!f) return null;
  return decodeCommitmentFields(commitmentObjectId, f);
}

// ============================================================
// Self-envelope opening flow
// ============================================================

/**
 * Plaintext shape for an envelope addressed to oneself that carries a
 * commitment opening. Hex-encoded so the JSON survives any pipe that
 * isn't byte-clean. We deliberately do NOT carry `commitmentId` here:
 * the binding to a specific commitment is the on-chain transaction
 * digest containing both the `commit_secret` and `post_envelope`
 * calls. That binding is unforgeable by anyone other than the author
 * of the original PTB.
 */
export interface OpeningPayloadV1 {
  kind: "commitment_opening_v1";
  encodedSecretHex: string;
  saltHex: string;
}

export function encodeOpeningPlaintext(opening: {
  encodedSecret: Uint8Array;
  salt: Uint8Array;
}): Uint8Array {
  const payload: OpeningPayloadV1 = {
    kind: "commitment_opening_v1",
    encodedSecretHex: bytesToHex(opening.encodedSecret),
    saltHex: bytesToHex(opening.salt),
  };
  return new TextEncoder().encode(JSON.stringify(payload));
}

export function decodeOpeningPlaintext(plaintext: Uint8Array): OpeningPayloadV1 | null {
  try {
    const text = new TextDecoder().decode(plaintext);
    const parsed = JSON.parse(text) as Partial<OpeningPayloadV1>;
    if (
      parsed?.kind !== "commitment_opening_v1" ||
      typeof parsed.encodedSecretHex !== "string" ||
      typeof parsed.saltHex !== "string"
    ) {
      return null;
    }
    return parsed as OpeningPayloadV1;
  } catch {
    return null;
  }
}

export interface PrepareCommitWithSelfOpeningArgs {
  packageId: string;
  registryId: string;
  authorAddress: string;
  /** Author's registry entry — must be the same address as `authorAddress`. */
  authorRegistryEntry: RegistryEntry;
  schema: string;
  hashScheme?: string;
  /** Plaintext text the author wants to commit to. */
  plaintextSecret: string;
}

export interface PreparedCommitWithSelfOpening {
  /** PTB combining commit_secret + post_envelope-to-self. */
  tx: Transaction;
  /** Commitment hash bytes that get posted on chain. */
  commitment: Uint8Array;
  /** Salt produced for this commitment; same value is also encrypted in the self-envelope. */
  salt: Uint8Array;
  /** Encoded secret bytes (UTF-8 with normalized line endings). */
  encodedSecret: Uint8Array;
  /** The commitment_opening_v1 schema string actually used. */
  openingSchema: string;
}

/**
 * Build a single Transaction (PTB) that atomically:
 *   1. posts a SecretCommitment with the salted hash of the plaintext
 *   2. posts a v5 Envelope addressed to {author} (recipients.length == 1),
 *      with schema=commitment_opening_v1, carrying the (encoded_secret, salt)
 *      opening as its hybrid-encrypted plaintext.
 *
 * The author can later recover the opening from any device that
 * controls the same wallet — no localStorage required. The same
 * opening plaintext can be re-sent privately to allies by posting a
 * v5 multi-recipient envelope (recipients > 1) carrying the same
 * commitment_opening_v1 payload.
 *
 * If either move call aborts, neither lands — atomicity is the whole
 * point.
 */
export function prepareCommitWithSelfOpening(
  args: PrepareCommitWithSelfOpeningArgs,
): PreparedCommitWithSelfOpening {
  const author = normalizeAddress(args.authorAddress);
  const registryAuthor = normalizeAddress(args.authorRegistryEntry.account);
  if (author !== registryAuthor) {
    throw new Error(
      `authorAddress ${author} does not match the supplied registry entry account ${registryAuthor}`,
    );
  }

  const encodedSecret = encodeTextSecret(args.plaintextSecret);
  const { commitment, salt } = createCommitment(encodedSecret);

  const openingPlaintext = encodeOpeningPlaintext({ encodedSecret, salt });
  const payload = encryptForRecipientsV5({
    senderAddress: author,
    recipients: [
      {
        address: author,
        publicKey: args.authorRegistryEntry.encryptionPubkey,
      },
    ],
    plaintext: openingPlaintext,
  });

  const tx = new Transaction();

  // Move call 1: commit_secret
  const schemaBytes = new TextEncoder().encode(args.schema);
  const hashSchemeBytes = new TextEncoder().encode(
    args.hashScheme ?? HASH_SCHEME_BLAKE2B_256,
  );
  tx.moveCall({
    target: `${args.packageId}::${MODULE_COMMITMENTS}::commit_secret`,
    arguments: [
      tx.pure.vector("u8", Array.from(schemaBytes)),
      tx.pure.vector("u8", Array.from(hashSchemeBytes)),
      tx.pure.vector("u8", Array.from(commitment)),
      tx.object(CLOCK_ID),
    ],
  });

  // Move call 2: v5 post_envelope to self carrying the opening
  const openingSchemaBytes = new TextEncoder().encode(SCHEMA_COMMITMENT_OPENING_V1);
  if (payload.wrappedKeys.length !== 1 || payload.wrapNonces.length !== 1) {
    throw new Error("internal: self-envelope payload must have exactly one wrapped key");
  }
  tx.moveCall({
    target: `${args.packageId}::${MODULE_ENVELOPES}::post_envelope`,
    arguments: [
      tx.object(args.registryId),
      tx.pure.vector("address", [author]),
      tx.pure.vector("id", [args.authorRegistryEntry.currentKeyId]),
      tx.pure.vector("u64", [BigInt(args.authorRegistryEntry.keyVersion)]),
      tx.pure.vector("u8", Array.from(new Uint8Array())),
      tx.pure.vector("u8", Array.from(openingSchemaBytes)),
      tx.pure.u16(CURRENT_ENVELOPE_FORMAT_VERSION),
      tx.pure.vector("u8", Array.from(new TextEncoder().encode(payload.encryptionScheme))),
      tx.pure.vector("u8", Array.from(payload.ephPubkey)),
      tx.pure.vector("u8", Array.from(payload.payloadNonce)),
      tx.pure.vector("u8", Array.from(payload.ciphertext)),
      tx.pure.vector("vector<u8>", [Array.from(payload.wrappedKeys[0]!)]),
      tx.pure.vector("vector<u8>", [Array.from(payload.wrapNonces[0]!)]),
      tx.object(CLOCK_ID),
    ],
  });

  return {
    tx,
    commitment,
    salt,
    encodedSecret,
    openingSchema: SCHEMA_COMMITMENT_OPENING_V1,
  };
}

/**
 * Look up the opening for a given commitment by scanning the author's
 * v5 envelope inbox.
 *
 * The matching strategy:
 *   1. Filter the inbox to envelopes with schema=commitment_opening_v1
 *      where `sender == ownerAddress` and the owner is among
 *      `recipients` (handles both self-envelopes and shared-with-me
 *      openings someone else might forward in the future).
 *   2. For each candidate, decrypt the wrapped key targeted at the
 *      owner, decode the JSON opening payload, and check
 *      `verifyOpening(encodedSecret, salt, commitment)` against the
 *      target commitment bytes.
 *
 * The commitment hash IS the binding — verifyOpening matching is a
 * strictly stronger check than tx-digest correlation. tx-digest
 * correlation would only matter for distinguishing two commitments
 * that hash to the same bytes, which is a collision adversaries
 * cannot construct.
 */
export async function loadOpeningForCommitment(
  suiClient: SuiClient,
  packageId: string,
  ownerAddress: string,
  recipientPrivateKey: Uint8Array,
  targetCommitment: Uint8Array,
): Promise<{ encodedSecret: Uint8Array; salt: Uint8Array; envelope: OnChainV5Envelope } | null> {
  const owner = normalizeAddress(ownerAddress);
  const inbox = await fetchV5Inbox(suiClient, packageId, owner);

  for (const envelope of inbox) {
    if (envelope.schema !== SCHEMA_COMMITMENT_OPENING_V1) continue;
    const idx = recipientIndexInV5Envelope(envelope, owner);
    if (idx < 0) continue;
    const wrappedKey = envelope.wrappedKeys[idx];
    const wrapNonce = envelope.wrapNonces[idx];
    if (!wrappedKey || !wrapNonce) continue;
    let suite;
    try {
      suite = requireUnifiedEncryptionSuite(envelope.encryptionScheme);
    } catch {
      continue;
    }
    const plaintext = suite.decrypt({
      encryptionScheme: envelope.encryptionScheme,
      senderAddress: envelope.sender,
      recipientAddress: owner,
      recipientPrivateKey,
      ephPubkey: envelope.ephPubkey,
      payloadNonce: envelope.payloadNonce,
      ciphertext: envelope.ciphertext,
      wrappedKey,
      wrapNonce,
    });
    if (!plaintext) continue;
    const opening = decodeOpeningPlaintext(plaintext);
    if (!opening) continue;
    let encodedSecret: Uint8Array;
    let salt: Uint8Array;
    try {
      encodedSecret = hexToBytes(opening.encodedSecretHex);
      salt = hexToBytes(opening.saltHex);
    } catch {
      continue;
    }
    if (!verifyOpening(encodedSecret, salt, targetCommitment)) continue;
    return { encodedSecret, salt, envelope };
  }
  return null;
}
