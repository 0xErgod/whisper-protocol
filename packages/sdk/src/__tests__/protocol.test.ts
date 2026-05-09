import { describe, expect, it, vi } from "vitest";
import {
  CURRENT_ENVELOPE_FORMAT_VERSION,
  ENCRYPTION_SCHEME_UNIFIED,
  SDK_PROTOCOL_VERSION,
} from "../constants.js";
import {
  UnsupportedEncryptionSchemeError,
  WriteCompatibilityError,
} from "../errors.js";
import { assertWriteCompatible } from "../protocol.js";

function mockSuiClient(protocolVersion: number) {
  return {
    devInspectTransactionBlock: vi.fn(async () => ({
      results: [
        {
          returnValues: [
            [[protocolVersion & 0xff, (protocolVersion >> 8) & 0xff, 0, 0], "u32"],
          ],
        },
      ],
    })),
  };
}

describe("assertWriteCompatible", () => {
  it("passes for the current deployment protocol, format, and suite", async () => {
    const client = mockSuiClient(SDK_PROTOCOL_VERSION);
    await expect(
      assertWriteCompatible(client as never, "0xpackage", {
        expectedProtocolVersion: SDK_PROTOCOL_VERSION,
        formatVersion: CURRENT_ENVELOPE_FORMAT_VERSION,
        encryptionScheme: ENCRYPTION_SCHEME_UNIFIED,
      }),
    ).resolves.toBe(SDK_PROTOCOL_VERSION);
  });

  it("fails when the deployment protocol_version does not match write expectations", async () => {
    const client = mockSuiClient(99);
    await expect(
      assertWriteCompatible(client as never, "0xpackage", {
        expectedProtocolVersion: SDK_PROTOCOL_VERSION,
        formatVersion: CURRENT_ENVELOPE_FORMAT_VERSION,
        encryptionScheme: ENCRYPTION_SCHEME_UNIFIED,
      }),
    ).rejects.toThrowError(WriteCompatibilityError);
  });

  it("fails closed on unsupported suites before touching the network", async () => {
    const client = mockSuiClient(SDK_PROTOCOL_VERSION);
    await expect(
      assertWriteCompatible(client as never, "0xpackage", {
        expectedProtocolVersion: SDK_PROTOCOL_VERSION,
        formatVersion: CURRENT_ENVELOPE_FORMAT_VERSION,
        encryptionScheme: "babyjub-demo-suite",
      }),
    ).rejects.toThrowError(UnsupportedEncryptionSchemeError);
    expect(client.devInspectTransactionBlock).not.toHaveBeenCalled();
  });
});
