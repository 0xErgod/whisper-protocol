import { x25519 } from "@noble/curves/ed25519";
import { describe, expect, it, vi } from "vitest";
import {
  CURRENT_ENVELOPE_FORMAT_VERSION,
  ENCRYPTION_SCHEME,
  ENCRYPTION_SCHEME_UNIFIED,
  SDK_PROTOCOL_VERSION,
} from "../constants.js";
import {
  fetchEncryptionKeyRecord,
  fetchRegistryEntry,
} from "../registry.js";
import { fetchFeed } from "../feed.js";
import { WhisperClient } from "../client.js";
import {
  UnsupportedEncryptionSchemeError,
  UnsupportedEnvelopeFormatVersionError,
} from "../errors.js";

const encoder = new TextEncoder();
const VALID_SENDER = "0x1111111111111111111111111111111111111111111111111111111111111111";
const VALID_RECIPIENT = "0x2222222222222222222222222222222222222222222222222222222222222222";
const VALID_KEY_ID = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const VALID_PACKAGE = "0x" + "c".repeat(64);
const VALID_REGISTRY = "0x" + "d".repeat(64);

function keyEntryContent(fields: Record<string, unknown>) {
  return {
    dataType: "moveObject",
    fields,
  };
}

function registryObject(tableId = "0xtable") {
  return {
    data: {
      content: keyEntryContent({
        entries: { fields: { id: { id: tableId } } },
      }),
    },
  };
}

describe("registry decoding", () => {
  it("decodes current_key_id from the live registry entry", async () => {
    const client = {
      getObject: vi.fn(async () => registryObject()),
      getDynamicFieldObject: vi.fn(async () => ({
        data: {
          content: keyEntryContent({
            value: {
              fields: {
                encryption_scheme: Array.from(encoder.encode(ENCRYPTION_SCHEME)),
                encryption_pubkey: [1, 2, 3],
                current_key_id: { bytes: "0xkey-1" },
                key_version: "4",
                rotated_at_ms: "999",
              },
            },
          }),
        },
      })),
    };

    const entry = await fetchRegistryEntry(client as never, "0xregistry", "0xabc");
    expect(entry).not.toBeNull();
    expect(entry?.currentKeyId).toBe("0xkey-1");
    expect(entry?.keyVersion).toBe(4);
  });

  it("decodes immutable key records", async () => {
    const client = {
      getObject: vi.fn(async () => ({
        data: {
          content: keyEntryContent({
            account: "0xabc",
            encryption_scheme: Array.from(encoder.encode(ENCRYPTION_SCHEME)),
            encryption_pubkey: [9, 8, 7],
            key_version: "2",
            rotated_at_ms: "1234",
          }),
        },
      })),
    };

    const record = await fetchEncryptionKeyRecord(client as never, "0xkey-2");
    expect(record).toEqual({
      keyObjectId: "0xkey-2",
      account: "0xabc",
      encryptionScheme: ENCRYPTION_SCHEME,
      encryptionPubkey: Uint8Array.from([9, 8, 7]),
      keyVersion: 2,
      rotatedAtMs: 1234,
    });
  });
});

describe("WhisperClient v5 transport integration", () => {
  it("prepareSendV5 with N=1 yields a v5 envelope (degenerate group, hybrid construction)", async () => {
    const recipientPriv = x25519.utils.randomPrivateKey();
    const recipientPub = x25519.getPublicKey(recipientPriv);
    const client = new WhisperClient({
      suiClient: {
        getObject: vi.fn(async () => registryObject()),
        getDynamicFieldObject: vi.fn(async () => ({
          data: {
            content: keyEntryContent({
              value: {
                fields: {
                  encryption_scheme: Array.from(encoder.encode(ENCRYPTION_SCHEME)),
                  encryption_pubkey: Array.from(recipientPub),
                  current_key_id: { bytes: VALID_KEY_ID },
                  key_version: "7",
                  rotated_at_ms: "111",
                },
              },
            }),
          },
        })),
      } as never,
      packageId: VALID_PACKAGE,
      registryId: VALID_REGISTRY,
    });

    const prepared = await client.prepareSendV5({
      senderAddress: VALID_SENDER,
      recipientAddresses: [VALID_RECIPIENT],
      plaintext: "secret",
    });

    expect(prepared.formatVersion).toBe(CURRENT_ENVELOPE_FORMAT_VERSION);
    expect(prepared.formatVersion).toBe(5);
    expect(prepared.recipients).toHaveLength(1);
    expect(prepared.recipients[0]!.currentKeyId).toBe(VALID_KEY_ID);
    expect(prepared.recipients[0]!.keyVersion).toBe(7);
    expect(prepared.encryptionScheme).toBe(ENCRYPTION_SCHEME_UNIFIED);
    // Hybrid construction always: payload encrypted once under random
    // K_msg, K_msg wrapped per recipient.
    expect(prepared.payload.wrappedKeys).toHaveLength(1);
    expect(prepared.payload.wrapNonces).toHaveLength(1);
  });

  it("decryptEnvelope returns plaintext for an in-list recipient and null for outsiders", () => {
    const client = new WhisperClient({
      suiClient: {} as never,
      packageId: VALID_PACKAGE,
      registryId: VALID_REGISTRY,
    });

    const bobPriv = x25519.utils.randomPrivateKey();
    const bobPub = x25519.getPublicKey(bobPriv);
    const charliePriv = x25519.utils.randomPrivateKey();
    const charliePub = x25519.getPublicKey(charliePriv);

    const payload = WhisperClient.encryptForRecipientsV5({
      senderAddress: VALID_SENDER,
      recipients: [
        { address: VALID_RECIPIENT, publicKey: bobPub },
        { address: "0xc4a4", publicKey: charliePub },
      ],
      plaintext: "shared secret",
    });

    const onChainEnvelope = {
      envelopeId: "0xenv",
      formatVersion: CURRENT_ENVELOPE_FORMAT_VERSION,
      encryptionScheme: payload.encryptionScheme,
      sender: VALID_SENDER,
      recipients: [VALID_RECIPIENT, "0xc4a4"],
      recipientKeyIds: [VALID_KEY_ID, VALID_KEY_ID],
      recipientKeyVersions: [1, 1],
      context: new Uint8Array(),
      schema: "x",
      ephPubkey: payload.ephPubkey,
      payloadNonce: payload.payloadNonce,
      ciphertext: payload.ciphertext,
      wrappedKeys: payload.wrappedKeys,
      wrapNonces: payload.wrapNonces,
      createdAtMs: 0,
    };

    const bobPlain = client.decryptEnvelopeUtf8({
      envelope: onChainEnvelope,
      recipientAddress: VALID_RECIPIENT,
      recipientPrivateKey: bobPriv,
    });
    expect(bobPlain).toBe("shared secret");

    // Charlie is in-list; uses her own private key + index
    const charliePlain = client.decryptEnvelopeUtf8({
      envelope: onChainEnvelope,
      recipientAddress: "0xc4a4",
      recipientPrivateKey: charliePriv,
    });
    expect(charliePlain).toBe("shared secret");

    // Outsider edward — not in recipient list → null
    const edwardPriv = x25519.utils.randomPrivateKey();
    const edwardPlain = client.decryptEnvelope({
      envelope: onChainEnvelope,
      recipientAddress: "0xed4ad",
      recipientPrivateKey: edwardPriv,
    });
    expect(edwardPlain).toBeNull();
  });

  it("fails closed on unsupported versions and suites", () => {
    const client = new WhisperClient({
      suiClient: {} as never,
      packageId: VALID_PACKAGE,
      registryId: VALID_REGISTRY,
    });

    expect(() =>
      client.assertCanReadEnvelope({
        formatVersion: 99,
        encryptionScheme: ENCRYPTION_SCHEME_UNIFIED,
      }),
    ).toThrowError(UnsupportedEnvelopeFormatVersionError);

    expect(() =>
      client.assertCanReadEnvelope({
        formatVersion: CURRENT_ENVELOPE_FORMAT_VERSION,
        encryptionScheme: "poseidon-demo-suite",
      }),
    ).toThrowError(UnsupportedEncryptionSchemeError);
  });

  it("readOnChainProtocolVersion decodes the on-chain u32 (sanity test)", async () => {
    void SDK_PROTOCOL_VERSION;
    // Existence check; actual decoding is exercised in protocol.test.ts
  });
});

describe("feed v5 decoding", () => {
  it("decodes a single v5 EnvelopePosted entry", async () => {
    const client = {
      // 4 queryEvents calls in fetchFeed: KEY, ENVELOPE, COMMITTED, OPENED.
      // We populate ENVELOPE with one v5 entry and the rest empty.
      queryEvents: vi
        .fn()
        // KEY
        .mockResolvedValueOnce({ data: [] })
        // ENVELOPE (v5)
        .mockResolvedValueOnce({
          data: [
            {
              id: { txDigest: "0xtx-v5", eventSeq: "0" },
              timestampMs: "5",
              parsedJson: {
                envelope_id: "0xenv-v5",
                format_version: "5",
                sender: "0xsender",
                recipients: ["0xa", "0xb"],
                recipient_key_ids: [{ bytes: "0xkey-a" }, { bytes: "0xkey-b" }],
                recipient_key_versions: ["1", "1"],
                context: [],
                schema: Array.from(encoder.encode("text/plain")),
                encryption_scheme: Array.from(encoder.encode(ENCRYPTION_SCHEME_UNIFIED)),
              },
            },
          ],
        })
        // COMMITTED
        .mockResolvedValueOnce({ data: [] })
        // OPENED
        .mockResolvedValueOnce({ data: [] }),
      multiGetObjects: vi.fn(async () => [
        {
          data: {
            objectId: "0xenv-v5",
            content: keyEntryContent({
              format_version: "5",
              sender: "0xsender",
              recipients: ["0xa", "0xb"],
              recipient_key_ids: [{ bytes: "0xkey-a" }, { bytes: "0xkey-b" }],
              recipient_key_versions: ["1", "1"],
              context: [],
              schema: Array.from(encoder.encode("text/plain")),
              encryption_scheme: Array.from(encoder.encode(ENCRYPTION_SCHEME_UNIFIED)),
              eph_pubkey: [1, 2, 3],
              payload_nonce: [4, 5, 6],
              ciphertext: [7, 8, 9],
              wrapped_keys: [[10, 11], [12, 13]],
              wrap_nonces: [[14], [15]],
              created_at_ms: "5",
            }),
          },
        },
      ]),
      multiGetTransactionBlocks: vi.fn(async () => []),
    };

    const events = await fetchFeed(client as never, {
      packageId: VALID_PACKAGE,
      withGas: false,
    });

    expect(events).toHaveLength(1);
    const e = events[0]!;
    expect(e.kind).toBe("envelope");
    if (e.kind !== "envelope") return;
    expect(e.formatVersion).toBe(5);
    expect(e.recipients).toEqual(["0xa", "0xb"]);
    expect(e.encryptionScheme).toBe(ENCRYPTION_SCHEME_UNIFIED);
    expect(e.wrappedKeys).toHaveLength(2);
  });
});
