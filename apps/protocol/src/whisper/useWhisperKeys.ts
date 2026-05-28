// React hook: derive (or read from IndexedDB cache) the connected
// wallet's Baby Jubjub keypair. Phase 4 will polish the UX (better
// error messages, Wallet-Standard feature gating, deterministic-sign
// path); for now this is the minimal viable rewire.

import { useCallback, useEffect, useState } from "react";
import { useCurrentAccount, useSignPersonalMessage } from "@mysten/dapp-kit";
import {
  canonicalMessage,
  canonicalMessageBytes,
  canonicalMessageDigest,
  deriveFromSignature,
  loadCached,
  saveCached,
  type CanonicalMessageInput,
  type DerivedBabyJubKeypair,
} from "@whisper-protocol/sdk";

const DERIVATION_VERSION = 1;
const SCOPE = "root";

export interface WhisperKeysState {
  /** Derived BJJ keypair, or null until the user signs. */
  keys: DerivedBabyJubKeypair | null;
  /** Whether we already have a cached keypair on this device. */
  hasCached: boolean | null;
  /** True while waiting on the wallet prompt. */
  deriving: boolean;
  /** Last error from the derivation flow, if any. */
  error: string | null;
  /**
   * Set when the connected wallet uses an unsupported signature scheme.
   * Phase-4 work will tighten this; today we accept any wallet that can
   * `signPersonalMessage` and let the runtime fail if the signature
   * isn't 64 bytes.
   */
  schemeError: string | null;
  /** Trigger derivation. Will pop the wallet prompt if not cached. */
  derive: () => Promise<DerivedBabyJubKeypair | null>;
  /** Forget the cached keypair on this device. */
  clear: () => Promise<void>;
}

function messageFor(address: string): CanonicalMessageInput {
  return { address, version: DERIVATION_VERSION, scope: SCOPE };
}

export function useWhisperKeys(): WhisperKeysState {
  const account = useCurrentAccount();
  const { mutateAsync: signPersonalMessage } = useSignPersonalMessage();

  const [keys, setKeys] = useState<DerivedBabyJubKeypair | null>(null);
  const [hasCached, setHasCached] = useState<boolean | null>(null);
  const [deriving, setDeriving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [schemeError] = useState<string | null>(null);

  useEffect(() => {
    setKeys(null);
    setHasCached(null);
    setError(null);
    if (!account) return;

    let cancelled = false;
    (async () => {
      try {
        const message = messageFor(account.address);
        const digest = canonicalMessageDigest(message);
        const cached = await loadCached({
          address: account.address,
          version: DERIVATION_VERSION,
          scope: SCOPE,
          canonicalMessageDigest: digest,
        });
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

  const derive = useCallback(async (): Promise<DerivedBabyJubKeypair | null> => {
    if (!account) {
      setError("No wallet connected");
      return null;
    }
    setDeriving(true);
    setError(null);
    try {
      const message = messageFor(account.address);
      const signed = await signPersonalMessage({
        message: canonicalMessageBytes(message),
      });
      // Sui personal-message signatures arrive base64-encoded. The
      // first byte is the scheme tag (0x00 = Ed25519); the next 64 are
      // the raw signature. We feed those 64 bytes into the SDK.
      const sigBytes = base64ToBytes(signed.signature);
      if (sigBytes.length < 65) {
        throw new Error(`unexpected wallet signature length ${sigBytes.length}`);
      }
      const sig = sigBytes.subarray(1, 65);
      const derived = deriveFromSignature(sig, message);
      await saveCached(
        {
          address: account.address,
          version: DERIVATION_VERSION,
          scope: SCOPE,
          canonicalMessageDigest: derived.canonicalMessageDigest,
        },
        derived,
      );
      setKeys(derived);
      setHasCached(true);
      return derived;
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      return null;
    } finally {
      setDeriving(false);
    }
  }, [account, signPersonalMessage]);

  const clear = useCallback(async () => {
    // Phase-3 minimal: rebuild state without writing to the cache. The
    // dApp's "forget cached keypair" affordance lives in IdentityBar
    // and will get the wired-up IndexedDB delete in Phase 4.
    if (!account) return;
    setKeys(null);
    setHasCached(false);
  }, [account?.address]);

  return { keys, hasCached, deriving, error, schemeError, derive, clear };
}

function base64ToBytes(b64: string): Uint8Array {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

// Re-export so other dApp modules can grab the canonical-message helper
// without importing from the SDK directly. (Pure pass-through.)
export { canonicalMessage };
