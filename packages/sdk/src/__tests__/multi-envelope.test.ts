import { describe, expect, it } from "vitest";
import { x25519 } from "@noble/curves/ed25519";
import {
  CURRENT_MULTI_ENVELOPE_FORMAT_VERSION,
  ENCRYPTION_SCHEME_MULTI,
} from "../constants.js";
import { encryptForRecipients, tryDecryptMulti, tryDecryptMultiUtf8 } from "../encrypt-multi.js";
import {
  decodeMultiEnvelopeFields,
  recipientIndexInMultiEnvelope,
} from "../multi-envelope.js";
import { UnsupportedEnvelopeFormatVersionError } from "../errors.js";

interface Identity {
  address: string;
  privateKey: Uint8Array;
  publicKey: Uint8Array;
}

function makeIdentity(address: string): Identity {
  const privateKey = x25519.utils.randomPrivateKey();
  const publicKey = x25519.getPublicKey(privateKey);
  return { address, privateKey, publicKey };
}

const SENDER = "0xa11ce";
const PLAINTEXT = "PLAYWRIGHT-SMOKE-MARKER-multi-recipient";

describe("multi-recipient encrypt/decrypt round-trip", () => {
  it("each named recipient can decrypt; non-recipients cannot", () => {
    const bob = makeIdentity("0xb0b");
    const charlie = makeIdentity("0xc4a4");
    const edward = makeIdentity("0xed4ad");

    const payload = encryptForRecipients({
      senderAddress: SENDER,
      recipients: [
        { address: bob.address, publicKey: bob.publicKey },
        { address: charlie.address, publicKey: charlie.publicKey },
      ],
      plaintext: PLAINTEXT,
    });

    expect(payload.encryptionScheme).toBe(ENCRYPTION_SCHEME_MULTI);
    expect(payload.wrappedKeys).toHaveLength(2);
    expect(payload.wrapNonces).toHaveLength(2);

    // Bob decrypts via his wrapped key.
    const bobPlain = tryDecryptMultiUtf8({
      senderAddress: SENDER,
      recipientAddress: bob.address,
      recipientPrivateKey: bob.privateKey,
      ephPubkey: payload.ephPubkey,
      payloadNonce: payload.payloadNonce,
      ciphertext: payload.ciphertext,
      wrappedKey: payload.wrappedKeys[0]!,
      wrapNonce: payload.wrapNonces[0]!,
    });
    expect(bobPlain).toBe(PLAINTEXT);

    // Charlie decrypts via his wrapped key.
    const charliePlain = tryDecryptMultiUtf8({
      senderAddress: SENDER,
      recipientAddress: charlie.address,
      recipientPrivateKey: charlie.privateKey,
      ephPubkey: payload.ephPubkey,
      payloadNonce: payload.payloadNonce,
      ciphertext: payload.ciphertext,
      wrappedKey: payload.wrappedKeys[1]!,
      wrapNonce: payload.wrapNonces[1]!,
    });
    expect(charliePlain).toBe(PLAINTEXT);

    // Edward (not a recipient) cannot decrypt either wrapped key.
    expect(
      tryDecryptMulti({
        senderAddress: SENDER,
        recipientAddress: edward.address,
        recipientPrivateKey: edward.privateKey,
        ephPubkey: payload.ephPubkey,
        payloadNonce: payload.payloadNonce,
        ciphertext: payload.ciphertext,
        wrappedKey: payload.wrappedKeys[0]!,
        wrapNonce: payload.wrapNonces[0]!,
      }),
    ).toBeNull();
  });

  it("a recipient cannot decrypt another recipient's wrapped key", () => {
    const bob = makeIdentity("0xb0b");
    const charlie = makeIdentity("0xc4a4");

    const payload = encryptForRecipients({
      senderAddress: SENDER,
      recipients: [
        { address: bob.address, publicKey: bob.publicKey },
        { address: charlie.address, publicKey: charlie.publicKey },
      ],
      plaintext: PLAINTEXT,
    });

    // Bob with charlie's wrapped key → fail
    expect(
      tryDecryptMulti({
        senderAddress: SENDER,
        recipientAddress: bob.address,
        recipientPrivateKey: bob.privateKey,
        ephPubkey: payload.ephPubkey,
        payloadNonce: payload.payloadNonce,
        ciphertext: payload.ciphertext,
        wrappedKey: payload.wrappedKeys[1]!,
        wrapNonce: payload.wrapNonces[1]!,
      }),
    ).toBeNull();
  });

  it("rejects empty recipient list", () => {
    expect(() =>
      encryptForRecipients({
        senderAddress: SENDER,
        recipients: [],
        plaintext: PLAINTEXT,
      }),
    ).toThrowError(/at least one recipient/);
  });
});

describe("decodeMultiEnvelopeFields", () => {
  it("decodes v3 fields with parallel arrays into a typed envelope", () => {
    const envelope = decodeMultiEnvelopeFields("0xenv-multi", {
      format_version: "3",
      sender: "0xa11ce",
      recipients: ["0xb0b", "0xc4a4"],
      recipient_key_ids: [{ bytes: "0xkey-bob" }, { bytes: "0xkey-charlie" }],
      recipient_key_versions: ["1", "2"],
      context: [],
      schema: Array.from(new TextEncoder().encode("text_secret_v1")),
      encryption_scheme: Array.from(new TextEncoder().encode(ENCRYPTION_SCHEME_MULTI)),
      eph_pubkey: [1, 2, 3],
      payload_nonce: [4, 5, 6],
      ciphertext: [7, 8, 9],
      wrapped_keys: [
        [10, 11, 12],
        [20, 21, 22],
      ],
      wrap_nonces: [
        [30, 31, 32],
        [40, 41, 42],
      ],
      created_at_ms: "789",
    });

    expect(envelope.formatVersion).toBe(CURRENT_MULTI_ENVELOPE_FORMAT_VERSION);
    expect(envelope.recipients).toHaveLength(2);
    expect(envelope.recipientKeyIds).toEqual(["0xkey-bob", "0xkey-charlie"]);
    expect(envelope.recipientKeyVersions).toEqual([1, 2]);
    expect(envelope.wrappedKeys).toHaveLength(2);
    expect(envelope.wrapNonces).toHaveLength(2);
    expect(envelope.encryptionScheme).toBe(ENCRYPTION_SCHEME_MULTI);
    expect(envelope.schema).toBe("text_secret_v1");
  });

  it("refuses to decode a v2 single-recipient envelope as multi", () => {
    expect(() =>
      decodeMultiEnvelopeFields("0xenv-v2", {
        format_version: "2",
        sender: "0xabc",
        recipient: "0xdef",
        recipient_key_id: { bytes: "0xkey" },
        context: [],
        schema: [1, 2, 3],
        encryption_scheme: Array.from(new TextEncoder().encode("suite-v2")),
        key_version: "1",
        eph_pubkey: [],
        nonce: [],
        ciphertext: [],
        created_at_ms: "0",
      }),
    ).toThrowError(UnsupportedEnvelopeFormatVersionError);
  });
});

describe("recipientIndexInMultiEnvelope", () => {
  it("returns -1 when the address is not in the recipient list", () => {
    const idx = recipientIndexInMultiEnvelope(
      { recipients: ["0xb0b", "0xc4a4"] },
      "0xed4ad",
    );
    expect(idx).toBe(-1);
  });

  it("normalizes both stored recipients and the lookup address before comparing", () => {
    // Both inputs flow through normalizeAddress, so two different
    // textual representations of the same address resolve identically.
    const padded = "0x00000000000000000000000000000000000000000000000000000000000000b0";
    const idx = recipientIndexInMultiEnvelope({ recipients: [padded] }, padded);
    expect(idx).toBe(0);
  });
});
