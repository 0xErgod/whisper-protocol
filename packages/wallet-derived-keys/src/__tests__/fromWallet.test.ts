import { describe, expect, it, vi } from "vitest";
import { ed25519 } from "@noble/curves/ed25519";
import { deriveEncryptionKeypairFromWallet } from "../fromWallet.js";
import {
  CURRENT_DERIVATION_VERSION,
  DERIVE_SIGNATURE_FEATURE_SCOPE,
  ROOT_SCOPE,
} from "../constants.js";
import { canonicalMessageBytes } from "../message.js";
import { suiAddressFromPublicKey, SUI_SIGNATURE_FLAGS } from "../scheme.js";

/**
 * Tests the wallet-aware dispatch layer. We build minimal Wallet-Standard-
 * shaped fakes with the features under test and assert:
 *
 *   - Path A (`sui:signPersonalMessage`): runs the Ed25519 gate; the
 *     fake wallet's signer is invoked with the canonical message bytes.
 *   - Path B (`misc:deriveSignature`): bypasses the Ed25519 gate; the
 *     fake wallet's deriver is invoked with the Whisper scope tag.
 *   - When both are present, B wins (preference rule from the spec).
 *   - When neither is present, the function throws with a clear error.
 *   - Personal-message path refuses non-Ed25519 accounts.
 *
 * The fakes return canned signatures; we only check call shape, not
 * derived-keypair correctness — that's the golden-vector test's job.
 */

const ED25519_PRIVATE_KEY = Uint8Array.from(
  Array.from({ length: 32 }, (_, i) => i + 1),
);
const ED25519_PUBLIC_KEY = ed25519.getPublicKey(ED25519_PRIVATE_KEY);
const ED25519_ADDRESS = suiAddressFromPublicKey(
  SUI_SIGNATURE_FLAGS.ED25519,
  ED25519_PUBLIC_KEY,
);

const CANNED_SIGNATURE = new Uint8Array(64);
for (let i = 0; i < 64; i++) CANNED_SIGNATURE[i] = i;

function toBase64(bytes: Uint8Array): string {
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]!);
  // btoa is available in Node 16+.
  return btoa(bin);
}

const ed25519Account = {
  address: ED25519_ADDRESS,
  publicKey: ED25519_PUBLIC_KEY,
};

const message = {
  address: ED25519_ADDRESS,
  version: CURRENT_DERIVATION_VERSION,
  scope: ROOT_SCOPE,
};

function makePersonalMessageWallet(
  signer = vi.fn(async ({ message: bytes }: { message: Uint8Array }) => {
    expect(bytes).toBeInstanceOf(Uint8Array);
    return { bytes: toBase64(bytes), signature: toBase64(CANNED_SIGNATURE) };
  }),
) {
  return {
    wallet: {
      name: "Fake Personal-Message Wallet",
      features: {
        "sui:signPersonalMessage": { signPersonalMessage: signer },
      },
    },
    signer,
  };
}

function makeDeriveSignatureWallet(
  deriver = vi.fn(
    async ({ scope, message: bytes }: { scope: string; message: Uint8Array }) => {
      expect(typeof scope).toBe("string");
      expect(bytes).toBeInstanceOf(Uint8Array);
      return {
        bytes: toBase64(bytes),
        signature: toBase64(CANNED_SIGNATURE),
        publicKey: toBase64(ED25519_PUBLIC_KEY),
      };
    },
  ),
) {
  return {
    wallet: {
      name: "Fake Derive-Signature Wallet",
      features: {
        "misc:deriveSignature": { deriveSignature: deriver },
      },
    },
    deriver,
  };
}

describe("deriveEncryptionKeypairFromWallet — path dispatch", () => {
  it("uses sui:signPersonalMessage when only that feature is exposed", async () => {
    const { wallet, signer } = makePersonalMessageWallet();
    const result = await deriveEncryptionKeypairFromWallet(
      wallet,
      ed25519Account,
      message,
      { chain: "sui:testnet" },
    );

    expect(result.path).toBe("personal-message");
    expect(signer).toHaveBeenCalledTimes(1);

    const call = signer.mock.calls[0]![0];
    expect(call.message).toEqual(canonicalMessageBytes(message));
    expect(call.account).toBe(ed25519Account);
    expect(call.chain).toBe("sui:testnet");
  });

  it("uses misc:deriveSignature when only that feature is exposed", async () => {
    const { wallet, deriver } = makeDeriveSignatureWallet();
    const result = await deriveEncryptionKeypairFromWallet(
      wallet,
      ed25519Account,
      message,
    );

    expect(result.path).toBe("derive-signature");
    expect(deriver).toHaveBeenCalledTimes(1);

    const call = deriver.mock.calls[0]![0];
    expect(call.scope).toBe(DERIVE_SIGNATURE_FEATURE_SCOPE);
    expect(call.message).toEqual(canonicalMessageBytes(message));
  });

  it("prefers misc:deriveSignature when both features are present", async () => {
    const pm = makePersonalMessageWallet();
    const ds = makeDeriveSignatureWallet();
    const wallet = {
      name: "Both",
      features: {
        ...pm.wallet.features,
        ...ds.wallet.features,
      },
    };

    const result = await deriveEncryptionKeypairFromWallet(
      wallet,
      ed25519Account,
      message,
    );

    expect(result.path).toBe("derive-signature");
    expect(ds.deriver).toHaveBeenCalledTimes(1);
    expect(pm.signer).not.toHaveBeenCalled();
  });

  it("forwards a custom scope override to misc:deriveSignature", async () => {
    const { wallet, deriver } = makeDeriveSignatureWallet();
    await deriveEncryptionKeypairFromWallet(wallet, ed25519Account, message, {
      scope: "whisper-protocol/v2",
    });
    expect(deriver.mock.calls[0]![0].scope).toBe("whisper-protocol/v2");
  });

  it("throws when the wallet exposes neither known feature", async () => {
    const wallet = {
      name: "Empty",
      features: {
        "standard:connect": {},
      },
    };
    await expect(
      deriveEncryptionKeypairFromWallet(wallet, ed25519Account, message),
    ).rejects.toThrow(/does not implement/i);
  });

  it("throws when no account is connected", async () => {
    const { wallet } = makePersonalMessageWallet();
    await expect(
      deriveEncryptionKeypairFromWallet(wallet, null, message),
    ).rejects.toThrow(/account/i);
  });

  it("throws when no wallet is connected", async () => {
    await expect(
      deriveEncryptionKeypairFromWallet(null, ed25519Account, message),
    ).rejects.toThrow(/wallet/i);
  });
});

describe("deriveEncryptionKeypairFromWallet — Ed25519 gate", () => {
  it("personal-message path refuses a non-Ed25519 account", async () => {
    const fakeSecp256k1 = new Uint8Array(33);
    for (let i = 0; i < 33; i++) fakeSecp256k1[i] = (i * 7) & 0xff;
    const secpAddress = suiAddressFromPublicKey(
      SUI_SIGNATURE_FLAGS.Secp256k1,
      fakeSecp256k1,
    );
    const account = { address: secpAddress, publicKey: fakeSecp256k1 };

    const { wallet, signer } = makePersonalMessageWallet();
    await expect(
      deriveEncryptionKeypairFromWallet(wallet, account, {
        ...message,
        address: secpAddress,
      }),
    ).rejects.toThrow(/Whisper requires an Ed25519 wallet/i);
    // We must throw BEFORE prompting the user; the signer must not be invoked.
    expect(signer).not.toHaveBeenCalled();
  });

  it("derive-signature path skips the Ed25519 gate (zkLogin-style)", async () => {
    // A zkLogin-style account: address derived under the ZkLogin flag,
    // pubkey shape we wouldn't otherwise accept for personal-message.
    // The deterministic-sign feature does its own internal derivation,
    // so we don't run our gate here.
    const zkPubkey = new Uint8Array(33);
    for (let i = 0; i < 33; i++) zkPubkey[i] = (i * 11) & 0xff;
    const zkAddress = suiAddressFromPublicKey(
      SUI_SIGNATURE_FLAGS.ZkLogin,
      zkPubkey,
    );

    const { wallet, deriver } = makeDeriveSignatureWallet();
    const result = await deriveEncryptionKeypairFromWallet(
      wallet,
      { address: zkAddress, publicKey: zkPubkey },
      { ...message, address: zkAddress },
    );

    expect(result.path).toBe("derive-signature");
    expect(deriver).toHaveBeenCalledTimes(1);
  });
});
