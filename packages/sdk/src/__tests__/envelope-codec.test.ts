import { describe, expect, it } from "vitest";
import { ENCRYPTION_SCHEME, LEGACY_ENVELOPE_FORMAT_VERSION } from "../constants.js";
import { UnsupportedEnvelopeFormatVersionError } from "../errors.js";
import { decodeEnvelopeFields, canReadEnvelope } from "../envelope.js";

describe("decodeEnvelopeFields", () => {
  it("decodes legacy V1 envelopes through the compatibility adapter", () => {
    const envelope = decodeEnvelopeFields("0xenv1", {
      sender: "0xabc",
      recipient: "0xdef",
      context: [1, 2],
      schema: [116, 101, 120, 116],
      key_version: "7",
      eph_pubkey: [1, 2, 3],
      nonce: [4, 5, 6],
      ciphertext: [7, 8, 9],
      created_at_ms: "123",
    });

    expect(envelope.formatVersion).toBe(LEGACY_ENVELOPE_FORMAT_VERSION);
    expect(envelope.encryptionScheme).toBe(ENCRYPTION_SCHEME);
    expect(envelope.recipientKeyId).toBeNull();
    expect(envelope.keyVersion).toBe(7);
    expect(envelope.schema).toBe("text");
  });

  it("decodes V2 envelopes with explicit format, suite, and key anchor", () => {
    const envelope = decodeEnvelopeFields("0xenv2", {
      format_version: "2",
      sender: "0xabc",
      recipient: "0xdef",
      recipient_key_id: { bytes: "0xkey" },
      context: [1, 2],
      schema: [106, 115, 111, 110],
      encryption_scheme: Array.from(new TextEncoder().encode("suite-v2")),
      key_version: "3",
      eph_pubkey: [1, 2, 3],
      nonce: [4, 5, 6],
      ciphertext: [7, 8, 9],
      created_at_ms: "456",
    });

    expect(envelope.formatVersion).toBe(2);
    expect(envelope.encryptionScheme).toBe("suite-v2");
    expect(envelope.recipientKeyId).toBe("0xkey");
    expect(envelope.keyVersion).toBe(3);
    expect(envelope.schema).toBe("json");
  });

  it("rejects unknown future format versions", () => {
    expect(() =>
      decodeEnvelopeFields("0xenv3", {
        format_version: "99",
        sender: "0xabc",
        recipient: "0xdef",
      }),
    ).toThrowError(UnsupportedEnvelopeFormatVersionError);
  });
});

describe("canReadEnvelope", () => {
  it("returns true for supported suite/version pairs", () => {
    expect(canReadEnvelope({ formatVersion: 2, encryptionScheme: ENCRYPTION_SCHEME })).toBe(true);
  });

  it("returns false for unsupported suites without falling back silently", () => {
    expect(canReadEnvelope({ formatVersion: 2, encryptionScheme: "poseidon-demo-suite" })).toBe(false);
  });
});
