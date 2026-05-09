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
import { encryptForRecipient, tryDecrypt } from "./encrypt.js";
import { bytesFromArray, stringFromBytes } from "./envelope-codec.js";
import { fetchInbox, type OnChainEnvelope } from "./envelope.js";
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
 *   2. posts an EncryptedEnvelope addressed to the author themselves,
 *      with schema=commitment_opening_v1, carrying the `(encoded_secret, salt)`
 *      opening as its plaintext.
 *
 * The author can later recover the opening from any device that
 * controls the same wallet — no localStorage required. The author can
 * also re-send the opening privately to allies via a separate
 * v2/v3 envelope using the same plaintext payload.
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
  const payload = encryptForRecipient({
    encryptionScheme: args.authorRegistryEntry.encryptionScheme,
    senderAddress: author,
    recipientAddress: author,
    recipientPublicKey: args.authorRegistryEntry.encryptionPubkey,
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

  // Move call 2: post_envelope to self carrying the opening
  const openingSchemaBytes = new TextEncoder().encode(SCHEMA_COMMITMENT_OPENING_V1);
  tx.moveCall({
    target: `${args.packageId}::${MODULE_ENVELOPES}::post_envelope`,
    arguments: [
      tx.object(args.registryId),
      tx.pure.address(author),
      tx.pure.vector("u8", Array.from(new Uint8Array())),
      tx.pure.vector("u8", Array.from(openingSchemaBytes)),
      tx.pure.u16(CURRENT_ENVELOPE_FORMAT_VERSION),
      tx.pure.id(args.authorRegistryEntry.currentKeyId),
      tx.pure.vector("u8", Array.from(new TextEncoder().encode(payload.encryptionScheme))),
      tx.pure.u64(BigInt(args.authorRegistryEntry.keyVersion)),
      tx.pure.vector("u8", Array.from(payload.ephPubkey)),
      tx.pure.vector("u8", Array.from(payload.nonce)),
      tx.pure.vector("u8", Array.from(payload.ciphertext)),
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
 * own envelope inbox.
 *
 * The matching strategy is two-step:
 *   1. Filter the inbox to envelopes with schema=commitment_opening_v1
 *      where `sender == recipient == ownerAddress` (self-addressed).
 *   2. For each candidate, decrypt → decode the JSON shape → if it's
 *      a valid v1 opening AND `verifyOpening(encodedSecret, salt, commitment)`
 *      matches the target commitment bytes, that's our opening.
 *
 * Note: we deliberately ignore the on-chain tx digest binding here.
 * `verifyOpening` against the target commitment bytes is a strictly
 * stronger check — the commitment hash IS the binding. tx-digest
 * correlation would only matter for distinguishing two equivalent
 * commitments that hash to the same bytes, which is a collision
 * adversaries couldn't construct anyway.
 */
export async function loadOpeningForCommitment(
  suiClient: SuiClient,
  packageId: string,
  ownerAddress: string,
  recipientPrivateKey: Uint8Array,
  targetCommitment: Uint8Array,
): Promise<{ encodedSecret: Uint8Array; salt: Uint8Array; envelope: OnChainEnvelope } | null> {
  const owner = normalizeAddress(ownerAddress);
  const inbox = await fetchInbox(suiClient, packageId, owner);

  for (const envelope of inbox) {
    if (envelope.schema !== SCHEMA_COMMITMENT_OPENING_V1) continue;
    if (envelope.sender !== owner || envelope.recipient !== owner) continue;
    const plaintext = tryDecrypt({
      recipientPrivateKey,
      encryptionScheme: envelope.encryptionScheme,
      senderAddress: envelope.sender,
      recipientAddress: envelope.recipient,
      ephPubkey: envelope.ephPubkey,
      nonce: envelope.nonce,
      ciphertext: envelope.ciphertext,
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
