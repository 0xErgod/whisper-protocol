import { useCallback, useEffect, useState } from "react";
import { useCurrentAccount, useCurrentWallet } from "@mysten/dapp-kit";
import {
  canonicalMessageBytes,
  clearCachedKeypair,
  CURRENT_DERIVATION_VERSION,
  deriveEncryptionKeypairFromWallet,
  readCachedKeypair,
  requireEd25519,
  ROOT_SCOPE,
  writeCachedKeypair,
} from "@whisper-protocol/wallet-derived-keys";
import type {
  CanonicalMessageInput,
  DerivationPath,
  DerivedEncryptionKeypair,
} from "@whisper-protocol/wallet-derived-keys";
import { sha256 } from "@noble/hashes/sha256";
import { ACTIVE_CHAIN } from "./client";

export interface WhisperKeysState {
  /** Derived encryption keypair, or null until the user signs. */
  keys: DerivedEncryptionKeypair | null;
  /** Whether we already have a cached keypair on this device. */
  hasCached: boolean | null;
  /** True while waiting on the wallet prompt. */
  deriving: boolean;
  /** Last error from the derivation flow, if any. */
  error: string | null;
  /**
   * Set when the connected wallet uses an unsupported signature scheme
   * (anything other than Ed25519) AND does not expose a deterministic
   * signing feature like `misc:deriveSignature`. Whisper's derivation
   * requires deterministic signing; non-Ed25519 wallets without an
   * alternative path would silently produce a different encryption key
   * on each session and lose access to past envelopes. When this is
   * non-null, `derive()` is a no-op.
   *
   * The Wallet-Standard feature inspection happens inside the SDK; this
   * hook only runs the *gate* eagerly so the UI can refuse "derive" up
   * front instead of letting the user click and see the prompt rejected.
   */
  schemeError: string | null;
  /**
   * Which signing path the SDK chose for the active wallet. `null`
   * before the first derivation. Surfaced for UI display only — clients
   * don't need to branch on this.
   */
  signPath: DerivationPath | null;
  /** Trigger derivation. Will pop the wallet prompt if not cached. */
  derive: () => Promise<DerivedEncryptionKeypair | null>;
  /** Forget the cached keypair on this device. */
  clear: () => Promise<void>;
}

/**
 * Eager scheme check: returns true if we should let the user attempt
 * derivation without expecting a guaranteed-failure prompt.
 *
 * The SDK does the same check internally (and is the source of truth);
 * this is just so the bar can show "unsupported wallet" eagerly.
 */
function eagerSchemeOk(
  wallet: { features?: Record<string, unknown> } | null | undefined,
  account: { address: string; publicKey: ArrayLike<number> } | null,
): { ok: true } | { ok: false; reason: string } {
  if (!account) return { ok: true };
  // Wallet exposes a deterministic-sign feature → bypass the Ed25519 gate.
  // The SDK will pick that path internally.
  const features = wallet?.features;
  if (
    features &&
    typeof features === "object" &&
    "misc:deriveSignature" in features
  ) {
    return { ok: true };
  }
  try {
    requireEd25519(account);
    return { ok: true };
  } catch (e) {
    return { ok: false, reason: e instanceof Error ? e.message : String(e) };
  }
}

export function useWhisperKeys(): WhisperKeysState {
  const account = useCurrentAccount();
  const { currentWallet } = useCurrentWallet();

  const [keys, setKeys] = useState<DerivedEncryptionKeypair | null>(null);
  const [hasCached, setHasCached] = useState<boolean | null>(null);
  const [deriving, setDeriving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [schemeError, setSchemeError] = useState<string | null>(null);
  const [signPath, setSignPath] = useState<DerivationPath | null>(null);

  // Reset state and run the eager scheme gate when the connected wallet
  // changes. We don't pre-pick a sign path here — the SDK does that at
  // derive() time so wallets that lazily register features still work.
  useEffect(() => {
    setKeys(null);
    setHasCached(null);
    setError(null);
    setSchemeError(null);
    setSignPath(null);
    if (!account) return;

    const gate = eagerSchemeOk(currentWallet, account);
    if (!gate.ok) {
      setSchemeError(gate.reason);
      return;
    }

    let cancelled = false;
    (async () => {
      try {
        const message: CanonicalMessageInput = {
          address: account.address,
          version: CURRENT_DERIVATION_VERSION,
          scope: ROOT_SCOPE,
        };
        const cacheKey = {
          address: account.address,
          version: CURRENT_DERIVATION_VERSION,
          scope: ROOT_SCOPE,
          canonicalMessageDigest: sha256(canonicalMessageBytes(message)),
        };
        const cached = await readCachedKeypair(cacheKey);
        if (cancelled) return;
        if (cached) {
          setKeys(cached);
          setHasCached(true);
        } else {
          setHasCached(false);
        }
      } catch (e) {
        if (cancelled) return;
        setError(e instanceof Error ? e.message : String(e));
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [account?.address, currentWallet?.name]);

  const derive = useCallback(async (): Promise<DerivedEncryptionKeypair | null> => {
    if (!account) {
      setError("No wallet connected");
      return null;
    }
    setDeriving(true);
    setError(null);
    try {
      const message: CanonicalMessageInput = {
        address: account.address,
        version: CURRENT_DERIVATION_VERSION,
        scope: ROOT_SCOPE,
      };
      const cacheKey = {
        address: account.address,
        version: CURRENT_DERIVATION_VERSION,
        scope: ROOT_SCOPE,
        canonicalMessageDigest: sha256(canonicalMessageBytes(message)),
      };
      const cached = await readCachedKeypair(cacheKey);
      if (cached) {
        setKeys(cached);
        setHasCached(true);
        return cached;
      }

      const { keypair, path } = await deriveEncryptionKeypairFromWallet(
        currentWallet,
        account,
        message,
        { chain: ACTIVE_CHAIN },
      );

      await writeCachedKeypair(cacheKey, keypair);
      setKeys(keypair);
      setHasCached(true);
      setSignPath(path);
      return keypair;
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      setError(msg);
      return null;
    } finally {
      setDeriving(false);
    }
  }, [account, currentWallet]);

  const clear = useCallback(async () => {
    if (!account) return;
    const message: CanonicalMessageInput = {
      address: account.address,
      version: CURRENT_DERIVATION_VERSION,
      scope: ROOT_SCOPE,
    };
    const cacheKey = {
      address: account.address,
      version: CURRENT_DERIVATION_VERSION,
      scope: ROOT_SCOPE,
      canonicalMessageDigest: sha256(canonicalMessageBytes(message)),
    };
    await clearCachedKeypair(cacheKey);
    setKeys(null);
    setHasCached(false);
    setSignPath(null);
  }, [account?.address]);

  return { keys, hasCached, deriving, error, schemeError, signPath, derive, clear };
}
