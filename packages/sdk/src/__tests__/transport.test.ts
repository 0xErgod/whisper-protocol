import { x25519 } from "@noble/curves/ed25519";
import { describe, expect, it, vi } from "vitest";
import {
  CURRENT_ENVELOPE_FORMAT_VERSION,
  ENCRYPTION_SCHEME,
  LEGACY_ENVELOPE_FORMAT_VERSION,
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

describe("WhisperClient transport integration", () => {
  it("prepares a V2 send against the recipient's current key entry", async () => {
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
      packageId: "0xpackage",
      registryId: "0xregistry",
    });

    const prepared = await client.prepareSend({
      senderAddress: VALID_SENDER,
      recipientAddress: VALID_RECIPIENT,
      plaintext: "secret",
    });

    expect(prepared.formatVersion).toBe(CURRENT_ENVELOPE_FORMAT_VERSION);
    expect(prepared.recipientKeyId).toBe(VALID_KEY_ID);
    expect(prepared.keyVersion).toBe(7);
    expect(prepared.payload.encryptionScheme).toBe(ENCRYPTION_SCHEME);
  });

  it("keeps an old V2 envelope decryptable after recipient key rotation via key resolver", async () => {
    const oldPriv = x25519.utils.randomPrivateKey();
    const oldPub = x25519.getPublicKey(oldPriv);
    const newPriv = x25519.utils.randomPrivateKey();

    const client = new WhisperClient({
      suiClient: {
        devInspectTransactionBlock: vi.fn(async () => ({
          results: [{ returnValues: [[[SDK_PROTOCOL_VERSION, 0, 0, 0], "u32"]] }],
        })),
      } as never,
      packageId: "0xpackage",
      registryId: "0xregistry",
    });

    const payload = WhisperClient.encrypt({
      senderAddress: "0xsender",
      recipientAddress: "0xrecipient",
      recipientPublicKey: oldPub,
      plaintext: "rotated secret",
      encryptionScheme: ENCRYPTION_SCHEME,
    });

    const envelope = {
      formatVersion: CURRENT_ENVELOPE_FORMAT_VERSION,
      sender: "0xsender",
      recipient: "0xrecipient",
      recipientKeyId: "0xkey-old",
      encryptionScheme: ENCRYPTION_SCHEME,
      keyVersion: 1,
      ephPubkey: payload.ephPubkey,
      nonce: payload.nonce,
      ciphertext: payload.ciphertext,
    };

    const plaintext = await client.decryptEnvelopeWithKeyResolver({
      envelope,
      recipientAddress: "0xrecipient",
      resolveRecipientPrivateKey: async ({ recipientKeyId }) => {
        if (recipientKeyId === "0xkey-old") return oldPriv;
        if (recipientKeyId === "0xkey-new") return newPriv;
        return null;
      },
    });

    expect(new TextDecoder().decode(plaintext!)).toBe("rotated secret");
  });

  it("does not fall back silently when the historical key anchor is wrong", async () => {
    const oldPriv = x25519.utils.randomPrivateKey();
    const oldPub = x25519.getPublicKey(oldPriv);
    const newPriv = x25519.utils.randomPrivateKey();
    const client = new WhisperClient({
      suiClient: {} as never,
      packageId: "0xpackage",
      registryId: "0xregistry",
    });
    const payload = WhisperClient.encrypt({
      senderAddress: "0xsender",
      recipientAddress: "0xrecipient",
      recipientPublicKey: oldPub,
      plaintext: "secret",
    });

    const plaintext = await client.decryptEnvelopeWithKeyResolver({
      envelope: {
        formatVersion: CURRENT_ENVELOPE_FORMAT_VERSION,
        sender: "0xsender",
        recipient: "0xrecipient",
        recipientKeyId: "0xunknown",
        encryptionScheme: ENCRYPTION_SCHEME,
        keyVersion: 1,
        ephPubkey: payload.ephPubkey,
        nonce: payload.nonce,
        ciphertext: payload.ciphertext,
      },
      recipientAddress: "0xrecipient",
      resolveRecipientPrivateKey: ({ recipientKeyId }) => {
        if (recipientKeyId === "0xkey-new") return newPriv;
        return null;
      },
    });

    expect(plaintext).toBeNull();
  });

  it("fails closed on unsupported versions and suites", () => {
    const client = new WhisperClient({
      suiClient: {} as never,
      packageId: "0xpackage",
      registryId: "0xregistry",
    });

    expect(() =>
      client.assertCanReadEnvelope({
        formatVersion: 99,
        encryptionScheme: ENCRYPTION_SCHEME,
      }),
    ).toThrowError(UnsupportedEnvelopeFormatVersionError);

    expect(() =>
      client.assertCanReadEnvelope({
        formatVersion: CURRENT_ENVELOPE_FORMAT_VERSION,
        encryptionScheme: "poseidon-demo-suite",
      }),
    ).toThrowError(UnsupportedEncryptionSchemeError);
  });
});

describe("feed compatibility decoding", () => {
  it("decodes mixed V1 and V2 feed entries in one pass", async () => {
    const client = {
      queryEvents: vi
        .fn()
        .mockResolvedValueOnce({
          data: [],
        })
        .mockResolvedValueOnce({
          data: [
            {
              id: { txDigest: "0xtx-v1", eventSeq: "0" },
              timestampMs: "1",
              parsedJson: {
                envelope_id: "0xenv-v1",
                sender: "0xsender",
                recipient: "0xrecipient",
                context: [],
                schema: Array.from(encoder.encode("text/plain")),
                key_version: "1",
              },
            },
            {
              id: { txDigest: "0xtx-v2", eventSeq: "1" },
              timestampMs: "2",
              parsedJson: {
                envelope_id: "0xenv-v2",
                format_version: "2",
                sender: "0xsender",
                recipient: "0xrecipient",
                recipient_key_id: { bytes: "0xkey-2" },
                context: [],
                schema: Array.from(encoder.encode("application/json")),
                encryption_scheme: Array.from(encoder.encode(ENCRYPTION_SCHEME)),
                key_version: "2",
              },
            },
          ],
        })
        .mockResolvedValueOnce({
          data: [],
        }),
      multiGetObjects: vi.fn(async () => [
        {
          data: {
            objectId: "0xenv-v1",
            content: keyEntryContent({
              sender: "0xsender",
              recipient: "0xrecipient",
              context: [],
              schema: Array.from(encoder.encode("text/plain")),
              key_version: "1",
              eph_pubkey: [1],
              nonce: [2],
              ciphertext: [3],
              created_at_ms: "1",
            }),
          },
        },
        {
          data: {
            objectId: "0xenv-v2",
            content: keyEntryContent({
              format_version: "2",
              sender: "0xsender",
              recipient: "0xrecipient",
              recipient_key_id: { bytes: "0xkey-2" },
              context: [],
              schema: Array.from(encoder.encode("application/json")),
              encryption_scheme: Array.from(encoder.encode(ENCRYPTION_SCHEME)),
              key_version: "2",
              eph_pubkey: [4],
              nonce: [5],
              ciphertext: [6],
              created_at_ms: "2",
            }),
          },
        },
      ]),
      multiGetTransactionBlocks: vi.fn(async () => []),
    };

    const events = await fetchFeed(client as never, {
      packageId: "0xpackage",
      withGas: false,
    });

    expect(events).toHaveLength(2);
    const [v2, v1] = events as Array<{ formatVersion: number; encryptionScheme: string }>;
    expect(v2).toBeDefined();
    expect(v1).toBeDefined();
    expect(v2!.formatVersion).toBe(CURRENT_ENVELOPE_FORMAT_VERSION);
    expect(v1!.formatVersion).toBe(LEGACY_ENVELOPE_FORMAT_VERSION);
    expect(v2!.encryptionScheme).toBe(ENCRYPTION_SCHEME);
    expect(v1!.encryptionScheme).toBe(ENCRYPTION_SCHEME);
  });
});
