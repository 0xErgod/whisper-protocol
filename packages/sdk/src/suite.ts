// Single-recipient authenticated, confidential envelope — TS mirror of
// `crates/protocol::envelope::{seal, open}`.
//
// Composition is exactly the spec:
//
//   shared       = ECDH(sender_sk, recipient_pk)
//   key_enc      = KDF(shared, [domain_tag("envelope-cipher-key"), envelope_id])
//   key_mac      = KDF(shared, [domain_tag("envelope-mac-key"),    envelope_id])
//   ciphertext   = cipher.encrypt(key_enc, payload.stream)
//   mac_tag      = mac(key_mac, [encoding_id, ...ciphertext])     // encoding_id bound
//
// `open` reverses this with MAC-before-decrypt discipline. The encoding
// id is a public envelope field (recipient needs it to pick a decoder
// before decryption) but authenticated by being folded into the MAC
// input — tampering with it breaks the MAC.
//
// Every primitive call routes through `crypto-wasm`, the Rust crate's
// WASM binding. Zero cryptographic logic in TypeScript.

import { cryptoWasm } from "./wasm.js";

/** Role tag for the per-envelope cipher key. */
const CIPHER_ROLE = "envelope-cipher-key";

/** Role tag for the per-envelope MAC key. */
const MAC_ROLE = "envelope-mac-key";

/**
 * A sealed envelope. Six fields, all public; nothing in here is
 * sensitive on its own. Only the recipient's secret can decrypt.
 *
 * All field elements are decimal-string `Fq` values — the wire form
 * crypto-wasm uses across the JS↔WASM boundary.
 */
export interface Envelope {
  /** Sender's public-key x coordinate. */
  senderPkX: string;
  /** Sender's public-key y coordinate. */
  senderPkY: string;
  /** Intended recipient's public-key x coordinate. */
  recipientPkX: string;
  /** Intended recipient's public-key y coordinate. */
  recipientPkY: string;
  /** Per-envelope binding scalar; must be unique per (sender, recipient). */
  envelopeId: string;
  /** Public payload-shape id, authenticated by being folded into the MAC. */
  encodingId: string;
  /** Cipher output; length matches the payload stream's length. */
  ciphertext: string[];
  /** Single Poseidon MAC tag over `[encoding_id, ...ciphertext]`. */
  macTag: string;
}

/**
 * Plaintext payload — the encoded stream of field elements paired with
 * the encoding id naming how to decode it. Mirrors `crypto::encoding::Payload`.
 */
export interface Payload {
  /** Encoding registry id (decimal string). */
  encodingId: string;
  /** Stream of field elements produced by an encoding. */
  stream: string[];
}

/** Why `open` rejected an envelope. */
export type OpenError =
  | { kind: "wrong-recipient" }
  | { kind: "mac-failure" };

export class WhisperOpenError extends Error {
  constructor(public readonly reason: OpenError) {
    super(
      reason.kind === "wrong-recipient"
        ? "envelope's recipient_pk does not match this recipient"
        : "envelope MAC verification failed: corrupt or forged",
    );
    this.name = "WhisperOpenError";
  }
}

function macInput(encodingId: string, ciphertext: string[]): string[] {
  return [encodingId, ...ciphertext];
}

/**
 * Seal a payload into an envelope.
 *
 * `senderSeed` is the 64-byte BJJ seed for the sender (produced by
 * `wallet-keys.ts`). `senderPkX/Y` and `recipientPkX/Y` are the BJJ
 * public-key coordinates as decimal strings. `envelopeId` MUST be
 * unique per `(sender, recipient)` pair — reusing it under the same
 * shared point yields the same cipher key, leaking plaintext-difference
 * information.
 *
 * The sender's public key is taken as an argument rather than derived
 * from the seed inside, mirroring the native API — the caller has both
 * halves from `deriveFromSignature` and re-deriving would mean one
 * extra scalar mul per seal.
 */
export function seal(args: {
  senderSeed: Uint8Array;
  senderPkX: string;
  senderPkY: string;
  recipientPkX: string;
  recipientPkY: string;
  envelopeId: string;
  payload: Payload;
}): Envelope {
  const shared = cryptoWasm.ecdh(args.senderSeed, args.recipientPkX, args.recipientPkY);

  const cipherRoleTag = cryptoWasm.domain_tag(CIPHER_ROLE);
  const macRoleTag = cryptoWasm.domain_tag(MAC_ROLE);

  const keyEnc = cryptoWasm.kdf_derive(shared.x, shared.y, [cipherRoleTag, args.envelopeId]);
  const keyMac = cryptoWasm.kdf_derive(shared.x, shared.y, [macRoleTag, args.envelopeId]);

  const ciphertext = cryptoWasm.cipher_encrypt(keyEnc, args.payload.stream);
  const tag = cryptoWasm.mac(keyMac, macInput(args.payload.encodingId, ciphertext));

  return {
    senderPkX: args.senderPkX,
    senderPkY: args.senderPkY,
    recipientPkX: args.recipientPkX,
    recipientPkY: args.recipientPkY,
    envelopeId: args.envelopeId,
    encodingId: args.payload.encodingId,
    ciphertext,
    macTag: tag,
  };
}

/**
 * Open an envelope, recovering the payload.
 *
 * Discipline pinned in the native impl + spec:
 *
 * 1. Recipient check — the envelope's `recipient_pk` must equal the
 *    caller's. Else `wrong-recipient`, no crypto runs.
 * 2. ECDH symmetry: `sk_b · sender_pk == sk_a · pk_b == shared`.
 * 3. Derive `key_mac`, verify the tag *before* decrypting. MAC-before-
 *    decrypt is non-negotiable — a recipient that decrypts first has
 *    voluntarily exposed itself to chosen-ciphertext attacks.
 * 4. Derive `key_enc`, decrypt.
 *
 * Throws `WhisperOpenError` on either failure mode. Returns the
 * recovered `Payload` (stream + authenticated encoding id) on success.
 */
export function open(args: {
  recipientSeed: Uint8Array;
  recipientPkX: string;
  recipientPkY: string;
  envelope: Envelope;
}): Payload {
  const { envelope } = args;

  if (envelope.recipientPkX !== args.recipientPkX || envelope.recipientPkY !== args.recipientPkY) {
    throw new WhisperOpenError({ kind: "wrong-recipient" });
  }

  const shared = cryptoWasm.ecdh(args.recipientSeed, envelope.senderPkX, envelope.senderPkY);

  const cipherRoleTag = cryptoWasm.domain_tag(CIPHER_ROLE);
  const macRoleTag = cryptoWasm.domain_tag(MAC_ROLE);

  const keyMac = cryptoWasm.kdf_derive(shared.x, shared.y, [macRoleTag, envelope.envelopeId]);
  if (!cryptoWasm.mac_verify(keyMac, macInput(envelope.encodingId, envelope.ciphertext), envelope.macTag)) {
    throw new WhisperOpenError({ kind: "mac-failure" });
  }

  const keyEnc = cryptoWasm.kdf_derive(shared.x, shared.y, [cipherRoleTag, envelope.envelopeId]);
  const stream = cryptoWasm.cipher_decrypt(keyEnc, envelope.ciphertext);

  return {
    encodingId: envelope.encodingId,
    stream,
  };
}
