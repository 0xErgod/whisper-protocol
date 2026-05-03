/**
 * Wallet-Standard-aware entry point. Inspects the connected wallet's
 * features map, picks the right signing path, and runs the derivation.
 *
 * This is the layer consumers should integrate against — it hides the
 * choice between the classic personal-message path and newer
 * deterministic-sign features (currently `misc:deriveSignature`) so
 * that adding more paths in the future is non-breaking.
 *
 * The function is React-agnostic and depends only on the Wallet-Standard
 * shape: `{ features: { [id]: { ...method } } }` and an account with an
 * `address` + `publicKey`. Pass these in from your framework's wallet
 * adapter (e.g. `useCurrentWallet()` and `useCurrentAccount()` from
 * `@mysten/dapp-kit`).
 */

import { DERIVE_SIGNATURE_FEATURE_SCOPE } from "./constants.js";
import {
  deriveFromDeterministicSigner,
  deriveFromWalletSigner,
  type DerivedEncryptionKeypair,
} from "./derive.js";
import type { CanonicalMessageInput } from "./message.js";
import { requireEd25519 } from "./scheme.js";

/**
 * Which path produced the derivation. Surfaced for UI display.
 */
export type DerivationPath = "personal-message" | "derive-signature";

/**
 * Minimal Wallet-Standard wallet shape we depend on.
 *
 * We intentionally avoid importing the full `@wallet-standard/core`
 * types here so this package remains framework-agnostic and dependency-
 * light; the Wallet-Standard contract for `features` is stable enough
 * that a structural type is sufficient.
 */
export interface WalletStandardWalletLike {
  name?: string;
  features?: Record<string, unknown>;
}

/**
 * Minimal account shape we depend on. Same structural-typing reasoning
 * as above.
 */
export interface WalletStandardAccountLike {
  address: string;
  publicKey: ArrayLike<number>;
}

const SIGN_PERSONAL_MESSAGE_FEATURE = "sui:signPersonalMessage";
const DERIVE_SIGNATURE_FEATURE = "misc:deriveSignature";

type SignPersonalMessageFeature = {
  signPersonalMessage: (input: {
    message: Uint8Array;
    account: WalletStandardAccountLike;
    chain?: string;
  }) => Promise<{ bytes: string; signature: string }>;
};

type DeriveSignatureFeature = {
  deriveSignature: (input: {
    scope: string;
    message: Uint8Array;
  }) => Promise<{ bytes: string; signature: string; publicKey: string }>;
};

function getFeature<T>(
  wallet: WalletStandardWalletLike | null | undefined,
  id: string,
  methodName: string,
): T | null {
  const feature = wallet?.features?.[id];
  if (
    feature &&
    typeof feature === "object" &&
    methodName in feature &&
    typeof (feature as Record<string, unknown>)[methodName] === "function"
  ) {
    return feature as T;
  }
  return null;
}

function fromBase64(b64: string): Uint8Array {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export interface DeriveFromWalletOptions {
  /**
   * Optional Sui chain identifier (e.g. `"sui:testnet"`) forwarded to
   * `sui:signPersonalMessage` when that path is taken. Required by some
   * wallets (notably Slush) but ignored by others. The deterministic-sign
   * path does not consume it.
   */
  chain?: string;
  /**
   * Domain-separation tag forwarded to `misc:deriveSignature` when that
   * path is taken. Defaults to `"whisper-protocol/v1"`. Different scopes
   * produce unrelated keys for the same wallet, so changing this is a
   * key rotation.
   */
  scope?: string;
}

export interface DeriveFromWalletResult {
  keypair: DerivedEncryptionKeypair;
  /** Which signing path was used. Exposed so dApps can surface it in UI. */
  path: DerivationPath;
}

/**
 * Pick the right signing path for the connected wallet and derive the
 * encryption keypair.
 *
 * Path selection (in order):
 *  1. If the wallet exposes `misc:deriveSignature`, use it. The
 *     Ed25519 scheme gate is skipped because the wallet derives its own
 *     deterministic Ed25519 sub-key internally regardless of its outer
 *     signing scheme. This is what unblocks zkLogin wallets.
 *  2. Otherwise require Ed25519 on the account and use
 *     `sui:signPersonalMessage`.
 *
 * Throws on missing features, missing accounts, or non-Ed25519 wallets
 * that don't implement the deterministic-sign feature.
 */
export async function deriveEncryptionKeypairFromWallet(
  wallet: WalletStandardWalletLike | null | undefined,
  account: WalletStandardAccountLike | null | undefined,
  message: CanonicalMessageInput,
  options: DeriveFromWalletOptions = {},
): Promise<DeriveFromWalletResult> {
  if (!account) {
    throw new Error("No wallet account connected");
  }
  if (!wallet) {
    throw new Error("No wallet connected");
  }

  const detFeature = getFeature<DeriveSignatureFeature>(
    wallet,
    DERIVE_SIGNATURE_FEATURE,
    "deriveSignature",
  );

  if (detFeature) {
    const scope = options.scope ?? DERIVE_SIGNATURE_FEATURE_SCOPE;
    const keypair = await deriveFromDeterministicSigner(
      async (sc, msg) => {
        const result = await detFeature.deriveSignature({
          scope: sc,
          message: msg,
        });
        return { signature: fromBase64(result.signature) };
      },
      message,
      scope,
    );
    return { keypair, path: "derive-signature" };
  }

  // Personal-message path. Determinism is only guaranteed for Ed25519
  // here, so gate explicitly before we ever pop a wallet prompt.
  requireEd25519(account);

  const pmFeature = getFeature<SignPersonalMessageFeature>(
    wallet,
    SIGN_PERSONAL_MESSAGE_FEATURE,
    "signPersonalMessage",
  );
  if (!pmFeature) {
    throw new Error(
      `Wallet "${wallet.name ?? "unknown"}" does not implement ${SIGN_PERSONAL_MESSAGE_FEATURE} or ${DERIVE_SIGNATURE_FEATURE}; cannot derive encryption keypair`,
    );
  }

  const keypair = await deriveFromWalletSigner(async (bytes) => {
    const { signature } = await pmFeature.signPersonalMessage({
      message: bytes,
      account,
      chain: options.chain,
    });
    return { signature: fromBase64(signature) };
  }, message);
  return { keypair, path: "personal-message" };
}
