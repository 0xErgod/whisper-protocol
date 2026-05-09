import { describe, expect, it, vi } from "vitest";
import { blake2b } from "@noble/hashes/blake2b";
import { x25519 } from "@noble/curves/ed25519";
import { bytesToHex } from "@noble/hashes/utils";
import {
  COMMITMENT_DOMAIN_V1,
  CURRENT_COMMITMENT_FORMAT_VERSION,
  ENCRYPTION_SCHEME,
  ENCRYPTION_SCHEME_UNIFIED,
  HASH_SCHEME_BLAKE2B_256,
  HASH_SCHEME_POSEIDON_BN254_CIRCOMLIB_V1,
  SCHEMA_COMMITMENT_OPENING_V1,
} from "../constants.js";
import {
  commitmentHash,
  createCommitment,
  decodeCommitmentFields,
  decodeOpeningPlaintext,
  encodeOpeningPlaintext,
  encodeTextSecret,
  loadOpeningForCommitment,
  prepareCommitWithSelfOpening,
  verifyOpening,
} from "../commitments.js";
import { UnsupportedHashSchemeError } from "../errors.js";
import { _poseidonInternals, MAX_POSEIDON_SECRET_BYTES, poseidonCommitmentHash } from "../hash-poseidon.js";
import { encryptForRecipientsV5 } from "../encrypt-unified.js";
import type { RegistryEntry } from "../registry.js";

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

describe("Poseidon-BN254 commitment hash (ZK-friendly)", () => {
  it("produces a deterministic 32-byte digest", () => {
    const secret = encodeTextSecret("attack=north");
    const salt = new Uint8Array(32).fill(0xff);
    const a = poseidonCommitmentHash(secret, salt);
    const b = poseidonCommitmentHash(secret, salt);
    expect(a).toEqual(b);
    expect(a.length).toBe(32);
  });

  it("matches the cross-language compatibility fixture (Rust prover MUST match this)", () => {
    // This fixture is the contract with the future arkworks-rs Rust
    // verifier. Any implementation that produces a different hash
    // for these exact inputs is using different Poseidon parameters,
    // a different chunking scheme, or a different field reduction,
    // and is incompatible with this SDK.
    //
    // See specs/poseidon-commitment-format.md for the full spec and
    // the inputs that produced this fixture.
    const secret = encodeTextSecret("attack=north");
    const salt = new Uint8Array(32).fill(0xff);
    const commitment = poseidonCommitmentHash(secret, salt);
    expect(bytesToHex(commitment)).toBe(
      "05f259557771fff79607b4e879588ab25c357c2da69acac697da93d9af2d1eb7",
    );
    // Domain tag derivation is also part of the contract.
    expect(_poseidonInternals.domainFieldHex()).toBe(
      "15acf9be01a30fd2b8298af5cab2f90c84e8fb388ae253ebb8911cf98f421306",
    );
  });

  it("changes when secret changes", () => {
    const salt = new Uint8Array(32).fill(0xff);
    const a = poseidonCommitmentHash(encodeTextSecret("attack=north"), salt);
    const b = poseidonCommitmentHash(encodeTextSecret("attack=south"), salt);
    expect(a).not.toEqual(b);
  });

  it("changes when salt changes", () => {
    const secret = encodeTextSecret("attack=north");
    const a = poseidonCommitmentHash(secret, new Uint8Array(32).fill(0xff));
    const b = poseidonCommitmentHash(secret, new Uint8Array(32).fill(0xfe));
    expect(a).not.toEqual(b);
  });

  it("rejects oversized secrets (cap is MAX_POSEIDON_SECRET_BYTES)", () => {
    const tooBig = new Uint8Array(MAX_POSEIDON_SECRET_BYTES + 1);
    const salt = new Uint8Array(32);
    expect(() => poseidonCommitmentHash(tooBig, salt)).toThrowError(/at most/);
  });

  it("rejects salts of the wrong length (must be 32 bytes)", () => {
    const secret = encodeTextSecret("x");
    expect(() => poseidonCommitmentHash(secret, new Uint8Array(31))).toThrowError(
      /must be 32 bytes/,
    );
    expect(() => poseidonCommitmentHash(secret, new Uint8Array(33))).toThrowError(
      /must be 32 bytes/,
    );
  });
});

describe("hash scheme dispatch", () => {
  it("commitmentHash defaults to Blake2b for back-compat", () => {
    const secret = encodeTextSecret("x");
    const salt = new Uint8Array(32).fill(7);
    const defaulted = commitmentHash(secret, salt);
    const explicit = commitmentHash(secret, salt, HASH_SCHEME_BLAKE2B_256);
    expect(defaulted).toEqual(explicit);
  });

  it("commitmentHash routes Poseidon and Blake2b to different outputs for the same inputs", () => {
    const secret = encodeTextSecret("attack=north");
    const salt = new Uint8Array(32).fill(0xff);
    const blake = commitmentHash(secret, salt, HASH_SCHEME_BLAKE2B_256);
    const poseidon = commitmentHash(secret, salt, HASH_SCHEME_POSEIDON_BN254_CIRCOMLIB_V1);
    expect(blake).not.toEqual(poseidon);
  });

  it("commitmentHash throws UnsupportedHashSchemeError on unknown schemes", () => {
    expect(() =>
      commitmentHash(new Uint8Array(0), new Uint8Array(32), "fnv-mvp-v1"),
    ).toThrowError(UnsupportedHashSchemeError);
  });

  it("verifyOpening fails closed when given the wrong hash scheme", () => {
    // A Poseidon commitment verified under Blake2b must fail.
    const secret = encodeTextSecret("attack=north");
    const { commitment, salt } = createCommitment(secret, HASH_SCHEME_POSEIDON_BN254_CIRCOMLIB_V1);
    expect(verifyOpening(secret, salt, commitment, HASH_SCHEME_BLAKE2B_256)).toBe(false);
    expect(verifyOpening(secret, salt, commitment, HASH_SCHEME_POSEIDON_BN254_CIRCOMLIB_V1)).toBe(true);
  });

  it("verifyOpening returns false (not throws) for unknown scheme strings", () => {
    const secret = encodeTextSecret("x");
    const salt = new Uint8Array(32);
    const commitment = new Uint8Array(32);
    expect(verifyOpening(secret, salt, commitment, "made-up-scheme-v1")).toBe(false);
  });

  it("createCommitment + verifyOpening round-trip works for Poseidon", () => {
    const secret = encodeTextSecret("asset_id=fortress;x=42;y=9");
    const { commitment, salt, hashScheme } = createCommitment(
      secret,
      HASH_SCHEME_POSEIDON_BN254_CIRCOMLIB_V1,
    );
    expect(hashScheme).toBe(HASH_SCHEME_POSEIDON_BN254_CIRCOMLIB_V1);
    expect(salt.length).toBe(32);
    expect(commitment.length).toBe(32);
    expect(verifyOpening(secret, salt, commitment, hashScheme)).toBe(true);
  });
});

describe("commitment_opening_v1 plaintext codec", () => {
  it("round-trips encoded_secret and salt through JSON+UTF-8", () => {
    const encodedSecret = encodeTextSecret("attack=north");
    const salt = new Uint8Array(32).fill(7);
    const bytes = encodeOpeningPlaintext({ encodedSecret, salt });
    const decoded = decodeOpeningPlaintext(bytes);
    expect(decoded).not.toBeNull();
    expect(decoded!.kind).toBe("commitment_opening_v1");
    expect(decoded!.encodedSecretHex).toBe(bytesToHex(encodedSecret));
    expect(decoded!.saltHex).toBe(bytesToHex(salt));
  });

  it("returns null for malformed JSON", () => {
    expect(decodeOpeningPlaintext(new TextEncoder().encode("not json"))).toBeNull();
    expect(decodeOpeningPlaintext(new TextEncoder().encode("{}"))).toBeNull();
  });

  it("returns null for the wrong kind tag (fail closed on schema drift)", () => {
    const bad = new TextEncoder().encode(
      JSON.stringify({ kind: "text_secret_v1", encodedSecretHex: "00", saltHex: "00" }),
    );
    expect(decodeOpeningPlaintext(bad)).toBeNull();
  });

  it("returns null when required hex fields are missing", () => {
    const missingSalt = new TextEncoder().encode(
      JSON.stringify({ kind: "commitment_opening_v1", encodedSecretHex: "00" }),
    );
    expect(decodeOpeningPlaintext(missingSalt)).toBeNull();
  });
});

describe("prepareCommitWithSelfOpening", () => {
  it("returns a Transaction with both commit_secret and post_envelope move calls", () => {
    const author = "0x" + "a".repeat(64);
    const authorPriv = x25519.utils.randomPrivateKey();
    const authorPub = x25519.getPublicKey(authorPriv);
    const registryEntry: RegistryEntry = {
      account: author,
      encryptionScheme: ENCRYPTION_SCHEME,
      encryptionPubkey: authorPub,
      currentKeyId: "0x" + "b".repeat(64),
      keyVersion: 1,
      rotatedAtMs: 0,
    };

    const prepared = prepareCommitWithSelfOpening({
      packageId: "0x" + "c".repeat(64),
      registryId: "0x" + "d".repeat(64),
      authorAddress: author,
      authorRegistryEntry: registryEntry,
      schema: "asset_location_v1",
      plaintextSecret: "fortress at x=42 y=9",
    });

    // Transaction shape: two move calls in one PTB.
    const txData = prepared.tx.getData();
    const moveCalls = txData.commands.filter((c) => "MoveCall" in c);
    expect(moveCalls).toHaveLength(2);
    const targets = moveCalls.map((c) => {
      const mc = (c as { MoveCall: { module: string; function: string } }).MoveCall;
      return `${mc.module}::${mc.function}`;
    });
    expect(targets).toContain("commitments::commit_secret");
    expect(targets).toContain("envelopes::post_envelope");
    expect(prepared.commitment.length).toBe(32);
    expect(prepared.salt.length).toBe(32);
    expect(verifyOpening(prepared.encodedSecret, prepared.salt, prepared.commitment)).toBe(true);
    expect(prepared.openingSchema).toBe(SCHEMA_COMMITMENT_OPENING_V1);
  });

  it("rejects an authorAddress that doesn't match the registry entry", () => {
    const authorPub = x25519.getPublicKey(x25519.utils.randomPrivateKey());
    const registryEntry: RegistryEntry = {
      account: "0xb0b",
      encryptionScheme: ENCRYPTION_SCHEME,
      encryptionPubkey: authorPub,
      currentKeyId: "0x" + "a".repeat(64),
      keyVersion: 1,
      rotatedAtMs: 0,
    };
    expect(() =>
      prepareCommitWithSelfOpening({
        packageId: "0xpkg",
        registryId: "0xregistry",
        authorAddress: "0xa11ce",
        authorRegistryEntry: registryEntry,
        schema: "x",
        plaintextSecret: "y",
      }),
    ).toThrowError(/does not match/);
  });
});

describe("loadOpeningForCommitment", () => {
  it("decrypts the matching v5 self-envelope and ignores wrong-schema and wrong-commitment candidates", async () => {
    const authorPriv = x25519.utils.randomPrivateKey();
    const authorPub = x25519.getPublicKey(authorPriv);
    const author = "0xa11ce";
    const PKG = "0x" + "p".padEnd(64, "0").slice(0, 64);

    // Three candidates in the inbox:
    //   (a) wrong schema — text_secret_v1 — should be ignored
    //   (b) right schema but opens a DIFFERENT commitment — should be ignored
    //   (c) right schema, right commitment — should be returned

    // (a) text envelope from a friend (v5, schema = text_secret_v1)
    const envelopeA = encryptForRecipientsV5({
      senderAddress: "0xfriend",
      recipients: [{ address: author, publicKey: authorPub }],
      plaintext: "hello",
    });

    // (b) a self-opening for a different secret
    const otherSecret = encodeTextSecret("different");
    const otherSalt = new Uint8Array(32).fill(1);
    const otherCommitment = commitmentHash(otherSecret, otherSalt);
    const envelopeB = encryptForRecipientsV5({
      senderAddress: author,
      recipients: [{ address: author, publicKey: authorPub }],
      plaintext: encodeOpeningPlaintext({ encodedSecret: otherSecret, salt: otherSalt }),
    });

    // (c) the target — a self-opening for the secret we want to find
    const targetSecret = encodeTextSecret("attack=north");
    const targetSalt = new Uint8Array(32).fill(7);
    const targetCommitment = commitmentHash(targetSecret, targetSalt);
    const envelopeC = encryptForRecipientsV5({
      senderAddress: author,
      recipients: [{ address: author, publicKey: authorPub }],
      plaintext: encodeOpeningPlaintext({ encodedSecret: targetSecret, salt: targetSalt }),
    });

    function v5EventFor(envId: string, schema: string, sender: string, recipient: string) {
      return {
        id: { txDigest: `0xtx-${envId}`, eventSeq: "0" },
        timestampMs: "0",
        parsedJson: {
          envelope_id: envId,
          format_version: "5",
          sender,
          recipients: [recipient],
          recipient_key_ids: [{ bytes: "0xkey-1" }],
          recipient_key_versions: ["1"],
          context: [],
          schema: Array.from(new TextEncoder().encode(schema)),
          encryption_scheme: Array.from(new TextEncoder().encode(ENCRYPTION_SCHEME_UNIFIED)),
        },
      };
    }

    function v5ObjectFor(envId: string, schema: string, sender: string, recipient: string, payload: typeof envelopeA) {
      return {
        data: {
          objectId: envId,
          content: {
            dataType: "moveObject",
            fields: {
              format_version: "5",
              sender,
              recipients: [recipient],
              recipient_key_ids: [{ bytes: "0xkey-1" }],
              recipient_key_versions: ["1"],
              context: [],
              schema: Array.from(new TextEncoder().encode(schema)),
              encryption_scheme: Array.from(new TextEncoder().encode(payload.encryptionScheme)),
              eph_pubkey: Array.from(payload.ephPubkey),
              payload_nonce: Array.from(payload.payloadNonce),
              ciphertext: Array.from(payload.ciphertext),
              wrapped_keys: payload.wrappedKeys.map((w) => Array.from(w)),
              wrap_nonces: payload.wrapNonces.map((n) => Array.from(n)),
              created_at_ms: "0",
            },
          },
        },
      };
    }

    const client = {
      queryEvents: vi.fn(async () => ({
        data: [
          v5EventFor("0xenvA", "text_secret_v1", "0xfriend", author),
          v5EventFor("0xenvB", SCHEMA_COMMITMENT_OPENING_V1, author, author),
          v5EventFor("0xenvC", SCHEMA_COMMITMENT_OPENING_V1, author, author),
        ],
      })),
      multiGetObjects: vi.fn(async () => [
        v5ObjectFor("0xenvA", "text_secret_v1", "0xfriend", author, envelopeA),
        v5ObjectFor("0xenvB", SCHEMA_COMMITMENT_OPENING_V1, author, author, envelopeB),
        v5ObjectFor("0xenvC", SCHEMA_COMMITMENT_OPENING_V1, author, author, envelopeC),
      ]),
    };

    const found = await loadOpeningForCommitment(
      client as never,
      PKG,
      author,
      authorPriv,
      targetCommitment,
    );
    expect(found).not.toBeNull();
    expect(bytesToHex(found!.encodedSecret)).toBe(bytesToHex(targetSecret));
    expect(bytesToHex(found!.salt)).toBe(bytesToHex(targetSalt));
    expect(found!.envelope.envelopeId).toBe("0xenvC");

    // Asking for the OTHER commitment also resolves correctly.
    const otherFound = await loadOpeningForCommitment(
      client as never,
      PKG,
      author,
      authorPriv,
      otherCommitment,
    );
    expect(otherFound!.envelope.envelopeId).toBe("0xenvB");
  });

  it("returns null when no envelope matches the target commitment", async () => {
    const authorPriv = x25519.utils.randomPrivateKey();
    const author = "0xa11ce";
    const client = {
      queryEvents: vi.fn(async () => ({ data: [] })),
      multiGetObjects: vi.fn(async () => []),
    };
    const targetCommitment = new Uint8Array(32).fill(0xff);
    const result = await loadOpeningForCommitment(
      client as never,
      "0xpkg",
      author,
      authorPriv,
      targetCommitment,
    );
    expect(result).toBeNull();
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
