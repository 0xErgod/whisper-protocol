// Cross-language envelope round-trip parity test.
//
// Mirrors `crates/protocol/tests/envelope_fixture.rs` against the
// same pinned Alice/Bob/envelope-42 fixture. The Rust test pins the
// envelope's `ciphertext`, `mac_tag`, and `encoding_id`; this TS
// test re-runs `seal` over crypto-wasm and asserts byte-for-byte
// agreement on each pinned vector. Anything drifting between Rust
// and TS — a domain tag change, a KDF order swap, a different MAC
// input encoding — surfaces here as a fixture failure.
//
// The fixture chains through every underlying primitive's pinned
// vectors (ECDH shared point, KDF keys, cipher output, MAC tag),
// so a passing round trip here pins the entire composition.

import { describe, expect, it } from "vitest";
import { cryptoWasm } from "../wasm.js";
import { open, seal } from "../suite.js";

// Pinned in `specs/encodings/text-utf8-v1.md` and reused across
// `crates/protocol/tests/envelope_fixture.rs` (line 30).
const TEXT_UTF8_V1_ID =
  "10251905648233427808659162032937842155138269080868533503078341140126603942221";

/** Build a 64-byte seed whose first byte is `first` and rest is zero. */
function seed(first: number): Uint8Array {
  const s = new Uint8Array(64);
  s[0] = first;
  return s;
}

function aliceBobEnvelope42() {
  const seedA = seed(1);
  const seedB = seed(2);
  const kpA = cryptoWasm.keypair_from_seed(seedA);
  const kpB = cryptoWasm.keypair_from_seed(seedB);

  const payload = {
    encodingId: TEXT_UTF8_V1_ID,
    stream: ["1", "2", "3", "4"],
  };

  const envelope = seal({
    senderSeed: seedA,
    senderPkX: kpA.pk_x,
    senderPkY: kpA.pk_y,
    recipientPkX: kpB.pk_x,
    recipientPkY: kpB.pk_y,
    envelopeId: "42",
    payload,
  });

  return { envelope, seedA, seedB, kpA, kpB };
}

describe("envelope fixture parity", () => {
  it("matches the babyjub-cipher spec's Vector 3 ciphertext", () => {
    // Pinned in `specs/babyjub-cipher.md § Vector 3` and asserted in
    // `crates/protocol/tests/envelope_fixture.rs::envelope_ciphertext_matches_cipher_spec_vector_3`.
    const { envelope } = aliceBobEnvelope42();
    expect(envelope.ciphertext).toEqual([
      "10787321779190226554676337514347691875659477298610453494316095697639731105525",
      "11005131623232030623906867189653141067415173065234117331769608574160093139922",
      "11791314040563090199526129580738560103220176213914809365331933459954108858858",
      "7865039964291077852173468667319105421171640084683400461629880408575490986497",
    ]);
  });

  it("matches the MAC tag over [encoding_id, ...ciphertext]", () => {
    // Pinned in `crates/protocol/tests/envelope_fixture.rs::envelope_mac_tag_matches_augmented_input`.
    // Folding encoding_id into the MAC input is the Option-A binding
    // from `specs/encodings/payload.md`; the tag is over the augmented
    // input, not the bare ciphertext.
    const { envelope } = aliceBobEnvelope42();
    expect(envelope.macTag).toBe(
      "10617735897557692178614481311515068866203189059565568446474293383244412682151",
    );
  });

  it("carries the text-utf8-v1 encoding_id as a public envelope field", () => {
    const { envelope } = aliceBobEnvelope42();
    expect(envelope.encodingId).toBe(TEXT_UTF8_V1_ID);
  });

  it("preserves the caller-supplied envelope_id", () => {
    const { envelope } = aliceBobEnvelope42();
    expect(envelope.envelopeId).toBe("42");
  });

  it("identifies Alice as sender and Bob as recipient by pubkey", () => {
    const { envelope, kpA, kpB } = aliceBobEnvelope42();
    expect(envelope.senderPkX).toBe(kpA.pk_x);
    expect(envelope.senderPkY).toBe(kpA.pk_y);
    expect(envelope.recipientPkX).toBe(kpB.pk_x);
    expect(envelope.recipientPkY).toBe(kpB.pk_y);
  });

  it("round-trips: Bob's open recovers the pinned payload", () => {
    const { envelope, seedB, kpB } = aliceBobEnvelope42();
    const recovered = open({
      recipientSeed: seedB,
      recipientPkX: kpB.pk_x,
      recipientPkY: kpB.pk_y,
      envelope,
    });
    expect(recovered.stream).toEqual(["1", "2", "3", "4"]);
    expect(recovered.encodingId).toBe(TEXT_UTF8_V1_ID);
  });

  it("rejects opening with the wrong recipient seed", () => {
    const { envelope, kpB } = aliceBobEnvelope42();
    const wrongSeed = seed(99);
    expect(() =>
      open({
        recipientSeed: wrongSeed,
        recipientPkX: kpB.pk_x,
        recipientPkY: kpB.pk_y,
        envelope,
      }),
    ).toThrow(/MAC verification failed|corrupt/);
  });

  it("rejects opening when the routing recipient pubkey does not match", () => {
    const { envelope, seedB } = aliceBobEnvelope42();
    expect(() =>
      open({
        recipientSeed: seedB,
        recipientPkX: "1",
        recipientPkY: "2",
        envelope,
      }),
    ).toThrow(/recipient_pk does not match|wrong recipient/i);
  });

  it("rejects opening when the ciphertext has been tampered with", () => {
    const { envelope, seedB, kpB } = aliceBobEnvelope42();
    const tampered = {
      ...envelope,
      ciphertext: [
        envelope.ciphertext[0]!,
        envelope.ciphertext[1]!,
        envelope.ciphertext[2]!,
        "0", // flipped
      ],
    };
    expect(() =>
      open({
        recipientSeed: seedB,
        recipientPkX: kpB.pk_x,
        recipientPkY: kpB.pk_y,
        envelope: tampered,
      }),
    ).toThrow(/MAC verification failed|corrupt/);
  });
});
