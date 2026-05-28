import { describe, expect, it, vi } from "vitest";
import { SDK_PROTOCOL_VERSION } from "../constants.js";
import { WriteCompatibilityError } from "../errors.js";
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
  it("passes when on-chain protocol_version matches the SDK's expected version", async () => {
    const client = mockSuiClient(SDK_PROTOCOL_VERSION);
    await expect(
      assertWriteCompatible(client as never, "0xpackage", {
        expectedProtocolVersion: SDK_PROTOCOL_VERSION,
      }),
    ).resolves.toBe(SDK_PROTOCOL_VERSION);
  });

  it("throws WriteCompatibilityError on a version mismatch", async () => {
    const client = mockSuiClient(99);
    await expect(
      assertWriteCompatible(client as never, "0xpackage", {
        expectedProtocolVersion: SDK_PROTOCOL_VERSION,
      }),
    ).rejects.toThrowError(WriteCompatibilityError);
  });
});
