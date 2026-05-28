// Optional in-browser signer for testing flows without a wallet that
// can target the dev devnet. Mirrors useWhisperKeys' BJJ derivation:
// signs the canonical message with an Ed25519 keypair from env, feeds
// the resulting 64-byte signature into deriveFromSignature.
//
// Phase-3 minimal rewire — Phase 4 will polish UX (better error
// messages, env-validation diagnostics, etc.).

import { useCallback, useEffect, useMemo, useState } from "react";
import { Ed25519Keypair } from "@mysten/sui/keypairs/ed25519";
import { parseSerializedSignature } from "@mysten/sui/cryptography";
import { fromHex } from "@mysten/sui/utils";
import type { Transaction } from "@mysten/sui/transactions";
import {
  canonicalMessageBytes,
  deriveFromSignature,
  type DerivedBabyJubKeypair,
} from "@whisper-protocol/sdk";
import { ACTIVE_CHAIN, suiClient } from "./client";
import type { ActiveAccount, TxExecutionResult } from "./session";
import type { WhisperKeysState } from "./useWhisperKeys";

const DERIVATION_VERSION = 1;
const SCOPE = "root";

const env = import.meta.env;

export const DEV_SIGNER_ENABLED = env.VITE_ENABLE_DEV_SIGNER === "true";
const DEV_SIGNER_KEYS_JSON = env.VITE_DEV_SIGNER_KEYS;
const DEV_SIGNER_LABEL = env.VITE_DEV_SIGNER_LABEL ?? "dev signer";
const DEV_SIGNER_SECRET_KEY = env.VITE_DEV_SIGNER_SECRET_KEY;
const ACTIVE_LABEL_STORAGE_KEY = "whisper:dev-signer:active-label";

function decodeSecretKey(secret: string): Uint8Array | string {
  const trimmed = secret.trim();
  if (trimmed.startsWith("suiprivkey")) return trimmed;
  const hex = trimmed.startsWith("0x") ? trimmed.slice(2) : trimmed;
  if (!/^[0-9a-fA-F]+$/.test(hex)) {
    throw new Error(
      "dev signer secret must be a suiprivkey string or 32-byte hex private key",
    );
  }
  const bytes = fromHex(hex);
  if (bytes.length !== 32) {
    throw new Error(`dev signer secret must decode to 32 bytes, got ${bytes.length}`);
  }
  return bytes;
}

interface ConfiguredSigner {
  label: string;
  signer: Ed25519Keypair;
  address: string;
}

interface ParsedConfig {
  signers: ConfiguredSigner[];
  configError: string | null;
}

function parseConfig(): ParsedConfig {
  if (!DEV_SIGNER_ENABLED) return { signers: [], configError: null };

  const entries: Array<{ label: string; secret: string }> = [];

  if (DEV_SIGNER_KEYS_JSON && DEV_SIGNER_KEYS_JSON.trim() !== "") {
    let parsed: unknown;
    try {
      parsed = JSON.parse(DEV_SIGNER_KEYS_JSON);
    } catch (e) {
      return {
        signers: [],
        configError: `VITE_DEV_SIGNER_KEYS is not valid JSON: ${
          e instanceof Error ? e.message : String(e)
        }`,
      };
    }
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      return {
        signers: [],
        configError: "VITE_DEV_SIGNER_KEYS must be a JSON object of { label: secret }",
      };
    }
    for (const [label, secret] of Object.entries(parsed as Record<string, unknown>)) {
      if (typeof secret !== "string" || secret.trim() === "") continue;
      entries.push({ label, secret });
    }
  } else if (DEV_SIGNER_SECRET_KEY && DEV_SIGNER_SECRET_KEY.trim() !== "") {
    entries.push({ label: DEV_SIGNER_LABEL, secret: DEV_SIGNER_SECRET_KEY });
  }

  if (entries.length === 0) {
    return {
      signers: [],
      configError:
        "VITE_ENABLE_DEV_SIGNER is true, but neither VITE_DEV_SIGNER_KEYS nor VITE_DEV_SIGNER_SECRET_KEY is set",
    };
  }

  const signers: ConfiguredSigner[] = [];
  for (const { label, secret } of entries) {
    try {
      const keypair = Ed25519Keypair.fromSecretKey(decodeSecretKey(secret));
      signers.push({ label, signer: keypair, address: keypair.toSuiAddress() });
    } catch (e) {
      return {
        signers: [],
        configError: `dev signer "${label}" is invalid: ${
          e instanceof Error ? e.message : String(e)
        }`,
      };
    }
  }
  return { signers, configError: null };
}

export interface DevAccountSummary {
  label: string;
  address: string;
}

interface DevSession {
  enabled: boolean;
  chain: string;
  account: ActiveAccount | null;
  keysState: WhisperKeysState;
  executeTransaction: ((transaction: Transaction) => Promise<TxExecutionResult>) | null;
  error: string | null;
  accounts: DevAccountSummary[];
  setActiveLabel: (label: string) => void;
}

function readStoredLabel(): string | null {
  try {
    return localStorage.getItem(ACTIVE_LABEL_STORAGE_KEY);
  } catch {
    return null;
  }
}

function writeStoredLabel(label: string) {
  try {
    localStorage.setItem(ACTIVE_LABEL_STORAGE_KEY, label);
  } catch {
    // best-effort
  }
}

export function useDevSession(): DevSession {
  const config = useMemo(parseConfig, []);

  const [activeLabel, setActiveLabelState] = useState<string | null>(() => {
    if (config.signers.length === 0) return null;
    const stored = readStoredLabel();
    if (stored && config.signers.some((s) => s.label === stored)) return stored;
    return config.signers[0]!.label;
  });

  const [account, setAccount] = useState<ActiveAccount | null>(null);
  const [keys, setKeys] = useState<DerivedBabyJubKeypair | null>(null);
  const [error, setError] = useState<string | null>(config.configError);

  const activeSigner = useMemo<ConfiguredSigner | null>(() => {
    if (!activeLabel) return null;
    return config.signers.find((s) => s.label === activeLabel) ?? null;
  }, [activeLabel, config.signers]);

  useEffect(() => {
    if (!DEV_SIGNER_ENABLED) {
      setAccount(null);
      setKeys(null);
      setError(null);
      return;
    }
    if (config.configError) {
      setError(config.configError);
      setAccount(null);
      setKeys(null);
      return;
    }
    if (!activeSigner) {
      setAccount(null);
      setKeys(null);
      return;
    }

    let cancelled = false;
    setKeys(null);
    (async () => {
      try {
        const { signer, label, address } = activeSigner;
        const message = { address, version: DERIVATION_VERSION, scope: SCOPE };
        const signed = await signer.signPersonalMessage(canonicalMessageBytes(message));
        const parsed = parseSerializedSignature(signed.signature);
        if (parsed.signatureScheme !== "ED25519") {
          throw new Error(`dev signer must be Ed25519, got ${parsed.signatureScheme}`);
        }
        const derived = deriveFromSignature(parsed.signature, message);
        if (cancelled) return;
        setAccount({ address, source: "dev", label });
        setKeys(derived);
        setError(null);
      } catch (e) {
        if (cancelled) return;
        setError(e instanceof Error ? e.message : String(e));
        setAccount(null);
        setKeys(null);
      }
    })();

    return () => {
      cancelled = true;
    };
  }, [activeSigner, config.configError]);

  const executeTransaction = useCallback(
    async (transaction: Transaction): Promise<TxExecutionResult> => {
      if (!activeSigner) throw new Error("dev signer is not configured");
      const result = await suiClient.signAndExecuteTransaction({
        transaction,
        signer: activeSigner.signer,
      });
      return { digest: result.digest };
    },
    [activeSigner],
  );

  const setActiveLabel = useCallback(
    (label: string) => {
      if (!config.signers.some((s) => s.label === label)) return;
      writeStoredLabel(label);
      setActiveLabelState(label);
    },
    [config.signers],
  );

  const accounts = useMemo<DevAccountSummary[]>(
    () => config.signers.map(({ label, address }) => ({ label, address })),
    [config.signers],
  );

  return {
    enabled: DEV_SIGNER_ENABLED,
    chain: ACTIVE_CHAIN,
    account,
    keysState: {
      keys,
      hasCached: DEV_SIGNER_ENABLED ? true : null,
      deriving: false,
      error,
      schemeError: null,
      derive: async () => keys,
      clear: async () => {},
    },
    executeTransaction: activeSigner ? executeTransaction : null,
    error,
    accounts,
    setActiveLabel,
  };
}
