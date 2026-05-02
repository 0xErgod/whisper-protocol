import { useEffect, useMemo, useState } from "react";
import {
  ConnectButton,
  useCurrentAccount,
  useSignAndExecuteTransaction,
} from "@mysten/dapp-kit";
import { bytesToHex } from "@noble/hashes/utils";
import type { SuiTransactionBlockResponse } from "@mysten/sui/client";
import {
  ENCRYPTION_SCHEME,
  normalizeAddress,
  type RegistryEntry,
} from "@whisper-protocol/sdk";
import type { DerivedEncryptionKeypair } from "@whisper-protocol/wallet-derived-keys";
import type { WhisperKeysState } from "../whisper/useWhisperKeys";
import { whisper, suiClient, ACTIVE_CHAIN } from "../whisper/client";
import { RawId } from "./RawId";

interface Props {
  registry: RegistryEntry[];
  keysState: WhisperKeysState;
}

export function IdentityBar({ registry, keysState }: Props) {
  const account = useCurrentAccount();
  const { mutateAsync: signAndExecute } = useSignAndExecuteTransaction();
  const [registering, setRegistering] = useState(false);
  const [regError, setRegError] = useState<string | null>(null);
  const [regSuccess, setRegSuccess] = useState<string | null>(null);

  const myEntry = useMemo<RegistryEntry | null>(() => {
    if (!account) return null;
    const norm = normalizeAddress(account.address);
    return registry.find((e) => e.account === norm) ?? null;
  }, [account, registry]);

  const registeredKeyMatches = useMemo(() => {
    if (!myEntry || !keysState.keys) return null;
    const onChain = bytesToHex(myEntry.encryptionPubkey);
    const local = bytesToHex(keysState.keys.encryptionPublicKey);
    return onChain === local;
  }, [myEntry, keysState.keys]);

  // Fade the success toast out a few seconds after the registry entry
  // has caught up. We watch myEntry to know the chain confirmed.
  useEffect(() => {
    if (!regSuccess) return;
    const t = setTimeout(() => setRegSuccess(null), 8000);
    return () => clearTimeout(t);
  }, [regSuccess]);

  async function registerKey(keys: DerivedEncryptionKeypair) {
    setRegistering(true);
    setRegError(null);
    setRegSuccess(null);
    try {
      const tx = whisper.buildRegisterKeyTx(keys.encryptionPublicKey);
      const result = await signAndExecute({ transaction: tx, chain: ACTIVE_CHAIN });
      const full: SuiTransactionBlockResponse = await suiClient.waitForTransaction({
        digest: result.digest,
        options: { showEffects: true },
      });
      const execStatus = full.effects?.status;
      if (!execStatus || execStatus.status !== "success") {
        const code = execStatus?.status ?? "unknown";
        const errText = execStatus?.error;
        throw new Error(`tx failed (${code})${errText ? `: ${errText}` : ""}`);
      }
      setRegSuccess(full.digest);
    } catch (e) {
      setRegError(e instanceof Error ? e.message : String(e));
    } finally {
      setRegistering(false);
    }
  }

  return (
    <div className="identity-bar">
      <div className="identity-cell">
        <span className="identity-label">WALLET</span>
        <span className="identity-cell-value">
          <ConnectButton connectText="connect wallet" />
        </span>
      </div>

      <div className="identity-cell">
        <span className="identity-label">ADDRESS</span>
        <span className="identity-cell-value">
          {account ? (
            <RawId value={account.address} kind="address" />
          ) : (
            <span style={{ color: "var(--text-faint)" }}>—</span>
          )}
        </span>
      </div>

      <div className="identity-cell">
        <span className="identity-label">ENCRYPTION KEYS</span>
        <span className="identity-cell-value">
          {!account ? (
            <span style={{ color: "var(--text-faint)" }}>—</span>
          ) : keysState.schemeError ? (
            <span className="identity-status error">unsupported wallet</span>
          ) : keysState.keys ? (
            <span className="identity-status ok">
              derived
              {keysState.hasCached === true && (
                <>
                  <span className="identity-sep">·</span>cached
                </>
              )}
            </span>
          ) : keysState.deriving ? (
            <span className="identity-status">
              <span className="spinner" /> awaiting wallet…
            </span>
          ) : keysState.hasCached === false ? (
            <button
              type="button"
              className="identity-action"
              onClick={() => keysState.derive()}
              disabled={keysState.deriving}
            >
              derive (sign once)
            </button>
          ) : (
            <span className="identity-status">checking cache…</span>
          )}
        </span>
      </div>

      <div className="identity-cell">
        <span className="identity-label">REGISTRATION</span>
        <span className="identity-cell-value">
          {!account || !keysState.keys ? (
            <span style={{ color: "var(--text-faint)" }}>—</span>
          ) : myEntry === null ? (
            <button
              type="button"
              className="identity-action"
              onClick={() => registerKey(keysState.keys!)}
              disabled={registering}
            >
              {registering ? "registering…" : "register on-chain"}
            </button>
          ) : registeredKeyMatches ? (
            <span className="identity-status ok">
              v{myEntry.keyVersion}
              <span className="identity-sep">·</span>matches local
            </span>
          ) : (
            <button
              type="button"
              className="identity-action"
              onClick={() => registerKey(keysState.keys!)}
              disabled={registering}
              title="on-chain key does not match local — re-register to rotate"
            >
              {registering ? "rotating…" : `rotate (was v${myEntry.keyVersion})`}
            </button>
          )}
        </span>
      </div>

      {keysState.schemeError && (
        <div className="identity-toast error">
          <strong>UNSUPPORTED WALLET</strong>
          <span>·</span>
          <span style={{ color: "var(--bad)" }}>{keysState.schemeError}</span>
        </div>
      )}

      {(keysState.error || regError) && (
        <div className="identity-toast error">
          <strong>{keysState.error ? "DERIVE ERROR" : "REGISTER ERROR"}</strong>
          <span>·</span>
          <span style={{ color: "var(--bad)" }}>
            {keysState.error ?? regError}
          </span>
        </div>
      )}

      {regSuccess && (
        <div className="identity-toast">
          <strong>REGISTERED</strong>
          <span>·</span>
          <span>tx</span>
          <RawId value={regSuccess} kind="tx" />
        </div>
      )}

      {account && keysState.keys && (
        <div className="identity-bar-foot">
          <span style={{ color: "var(--text-faint)" }}>local pubkey</span>
          <RawId
            value={`0x${bytesToHex(keysState.keys.encryptionPublicKey)}`}
            kind="bytes"
          />
          <span className="identity-foot-spacer" />
          <span className="identity-foot-scheme">scheme {ENCRYPTION_SCHEME}</span>
        </div>
      )}
    </div>
  );
}
