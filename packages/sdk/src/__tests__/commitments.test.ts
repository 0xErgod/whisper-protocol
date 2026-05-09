import { describe, expect, it } from "vitest";
import { blake2b } from "@noble/hashes/blake2b";
import {
  COMMITMENT_DOMAIN_V1,
  CURRENT_COMMITMENT_FORMAT_VERSION,
  HASH_SCHEME_BLAKE2B_256,
} from "../constants.js";
import {
  commitmentHash,
  createCommitment,
  decodeCommitmentFields,
  encodeTextSecret,
  verifyOpening,
} from "../commitments.js";

describe("encodeTextSecret", () => {
  it("normalizes \\r\\n line endings to \\n so commitments stay stable across platforms", () => {
    const a = encodeTextSecret("hello\r\nworld");
    const b = encodeTextSecret("hello\nworld");
    expect(a).toEqual(b);
  });

  it("preserves arbitrary UTF-8 content otherwise", () => {
    const text = "fortress at x=42, y=9 — région 12";
    const bytes = encodeTextSecret(text);
    expect(new TextDecoder().decode(bytes)).toBe(text);
  });
});

describe("commitmentHash", () => {
  it("is deterministic for the same (secret, salt) pair", () => {
    const secret = encodeTextSecret("attack=north");
    const salt = new Uint8Array(32).fill(7);
    const a = commitmentHash(secret, salt);
    const b = commitmentHash(secret, salt);
    expect(a).toEqual(b);
    expect(a.length).toBe(32);
  });

  it("changes if the secret changes by even one byte", () => {
    const salt = new Uint8Array(32).fill(7);
    const a = commitmentHash(encodeTextSecret("attack=north"), salt);
    const b = commitmentHash(encodeTextSecret("attack=south"), salt);
    expect(a).not.toEqual(b);
  });

  it("changes if the salt changes", () => {
    const secret = encodeTextSecret("attack=north");
    const a = commitmentHash(secret, new Uint8Array(32).fill(7));
    const b = commitmentHash(secret, new Uint8Array(32).fill(8));
    expect(a).not.toEqual(b);
  });

  it("includes the domain prefix so plain Blake2b(secret||salt) does not match", () => {
    const secret = encodeTextSecret("attack=north");
    const salt = new Uint8Array(32).fill(7);
    // Domain-less hash of the same bytes via @noble/hashes directly.
    const naive = new Uint8Array(secret.length + salt.length);
    naive.set(secret, 0);
    naive.set(salt, secret.length);
    const naiveHash = blake2b(naive, { dkLen: 32 });
    expect(commitmentHash(secret, salt)).not.toEqual(naiveHash);
    expect(COMMITMENT_DOMAIN_V1).toBe("sui-secret-commitment-v1");
  });
});

describe("createCommitment + verifyOpening round-trip", () => {
  it("the original (secret, salt) verifies against the produced commitment", () => {
    const secret = encodeTextSecret("asset_id=fortress-001;x=42;y=9");
    const { commitment, salt } = createCommitment(secret);
    expect(salt.length).toBe(32);
    expect(commitment.length).toBe(32);
    expect(verifyOpening(secret, salt, commitment)).toBe(true);
  });

  it("a tampered secret fails to verify", () => {
    const secret = encodeTextSecret("asset_id=fortress-001;x=42;y=9");
    const { commitment, salt } = createCommitment(secret);
    const tampered = encodeTextSecret("asset_id=fortress-001;x=42;y=10");
    expect(verifyOpening(tampered, salt, commitment)).toBe(false);
  });

  it("a tampered salt fails to verify", () => {
    const secret = encodeTextSecret("asset_id=fortress-001");
    const { commitment, salt } = createCommitment(secret);
    const flippedSalt = new Uint8Array(salt);
    flippedSalt[0] = (flippedSalt[0]! ^ 0xff) & 0xff;
    expect(verifyOpening(secret, flippedSalt, commitment)).toBe(false);
  });

  it("a length-mismatched expected commitment fails fast without throwing", () => {
    const secret = encodeTextSecret("x");
    const { salt } = createCommitment(secret);
    expect(verifyOpening(secret, salt, new Uint8Array(0))).toBe(false);
    expect(verifyOpening(secret, salt, new Uint8Array(33))).toBe(false);
  });

  it("two separate calls produce different (commitment, salt) for the same secret", () => {
    const secret = encodeTextSecret("vote=yes");
    const a = createCommitment(secret);
    const b = createCommitment(secret);
    expect(a.salt).not.toEqual(b.salt);
    expect(a.commitment).not.toEqual(b.commitment);
  });
});

describe("decodeCommitmentFields", () => {
  it("decodes on-chain SecretCommitment fields into a typed object", () => {
    const decoded = decodeCommitmentFields("0xcommit-1", {
      format_version: "1",
      author: "0xa11ce",
      schema: Array.from(new TextEncoder().encode("asset_location_v1")),
      hash_scheme: Array.from(new TextEncoder().encode(HASH_SCHEME_BLAKE2B_256)),
      commitment: [1, 2, 3, 4],
      created_at_ms: "789",
      opened: false,
      opened_at_ms: "0",
    });

    expect(decoded.commitmentId).toBe("0xcommit-1");
    expect(decoded.formatVersion).toBe(CURRENT_COMMITMENT_FORMAT_VERSION);
    expect(decoded.schema).toBe("asset_location_v1");
    expect(decoded.hashScheme).toBe(HASH_SCHEME_BLAKE2B_256);
    expect(decoded.commitment).toEqual(Uint8Array.from([1, 2, 3, 4]));
    expect(decoded.opened).toBe(false);
    expect(decoded.openedAtMs).toBe(0);
  });

  it("decodes the opened state correctly", () => {
    const decoded = decodeCommitmentFields("0xcommit-2", {
      format_version: "1",
      author: "0xa11ce",
      schema: Array.from(new TextEncoder().encode("asset_location_v1")),
      hash_scheme: Array.from(new TextEncoder().encode(HASH_SCHEME_BLAKE2B_256)),
      commitment: [1, 2, 3, 4],
      created_at_ms: "789",
      opened: true,
      opened_at_ms: "1234",
    });

    expect(decoded.opened).toBe(true);
    expect(decoded.openedAtMs).toBe(1234);
  });
});
