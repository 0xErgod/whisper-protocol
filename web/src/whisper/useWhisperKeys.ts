import { useCallback, useEffect, useState } from "react";
import { useCurrentAccount, useSignPersonalMessage } from "@mysten/dapp-kit";
import {
  canonicalMessageBytes,
  clearCachedKeypair,
  deriveFromWalletSigner,
  readCachedKeypair,
  requireEd25519,
  writeCachedKeypair,
} from "@whisper-protocol/wallet-derived-keys";
import type {
  CanonicalMessageInput,
  DerivedEncryptionKeypair,
} from "@whisper-protocol/wallet-derived-keys";
import { sha256 } from "@noble/hashes/sha256";
import { ACTIVE_CHAIN } from "./client";

const SCOPE = "root";
const VERSION = 1;

function fromBase64(b64: string): Uint8Array {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

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
   * (anything other than Ed25519). Whisper's derivation requires
   * deterministic signing; non-Ed25519 wallets would silently produce a
   * different encryption key on each session and lose access to past
   * envelopes. When this is non-null, `derive()` is a no-op.
   */
  schemeError: string | null;
  /** Trigger derivation. Will pop the wallet prompt if not cached. */
  derive: () => Promise<DerivedEncryptionKeypair | null>;
  /** Forget the cached keypair on this device. */
  clear: () => Promise<void>;
}

export function useWhisperKeys(): WhisperKeysState {
  const account = useCurrentAccount();
  const { mutateAsync: signPersonalMessage } = useSignPersonalMessage();

  const [keys, setKeys] = useState<DerivedEncryptionKeypair | null>(null);
  const [hasCached, setHasCached] = useState<boolean | null>(null);
  const [deriving, setDeriving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [schemeError, setSchemeError] = useState<string | null>(null);

  // Reset state when the connected wallet changes. Run the Ed25519 gate
  // immediately so the bar can refuse to show "derive" for unsupported
  // wallets — better UX than letting the user click and seeing the prompt
  // be rejected after the fact.
  useEffect(() => {
    setKeys(null);
    setHasCached(null);
    setError(null);
    setSchemeError(null);
    if (!account) return;
    try {
      requireEd25519(account);
    } catch (e) {
      setSchemeError(e instanceof Error ? e.message : String(e));
      return;
    }
    let cancelled = false;
    (async () => {
      try {
        const message: CanonicalMessageInput = {
          address: account.address,
          version: VERSION,
          scope: SCOPE,
        };
        const cacheKey = {
          address: account.address,
          version: VERSION,
          scope: SCOPE,
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
  }, [account?.address]);

  const derive = useCallback(async (): Promise<DerivedEncryptionKeypair | null> => {
    if (!account) {
      setError("No wallet connected");
      return null;
    }
    setDeriving(true);
    setError(null);
    try {
      // Belt-and-braces: the connect-effect already runs this, but
      // catching it here too means the gate can't be bypassed by a
      // direct caller.
      requireEd25519(account);
      const message: CanonicalMessageInput = {
        address: account.address,
        version: VERSION,
        scope: SCOPE,
      };
      const cacheKey = {
        address: account.address,
        version: VERSION,
        scope: SCOPE,
        canonicalMessageDigest: sha256(canonicalMessageBytes(message)),
      };
      const cached = await readCachedKeypair(cacheKey);
      if (cached) {
        setKeys(cached);
        setHasCached(true);
        return cached;
      }
      const derived = await deriveFromWalletSigner(async (bytes) => {
        const { signature } = await signPersonalMessage({
          message: bytes,
          chain: ACTIVE_CHAIN,
        });
        return { signature: fromBase64(signature) };
      }, message);
      await writeCachedKeypair(cacheKey, derived);
      setKeys(derived);
      setHasCached(true);
      return derived;
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      setError(msg);
      return null;
    } finally {
      setDeriving(false);
    }
  }, [account?.address, signPersonalMessage]);

  const clear = useCallback(async () => {
    if (!account) return;
    const message: CanonicalMessageInput = {
      address: account.address,
      version: VERSION,
      scope: SCOPE,
    };
    const cacheKey = {
      address: account.address,
      version: VERSION,
      scope: SCOPE,
      canonicalMessageDigest: sha256(canonicalMessageBytes(message)),
    };
    await clearCachedKeypair(cacheKey);
    setKeys(null);
    setHasCached(false);
  }, [account?.address]);

  return { keys, hasCached, deriving, error, schemeError, derive, clear };
}
