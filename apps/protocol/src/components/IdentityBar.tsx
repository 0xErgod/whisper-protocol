import { useEffect, useMemo, useState } from "react";
import {
  ConnectButton,
} from "@mysten/dapp-kit";
import type { SuiTransactionBlockResponse } from "@mysten/sui/client";
import {
  normalizeAddress,
  type DerivedBabyJubKeypair,
  type RegistryEntry,
} from "@whisper-protocol/sdk";
import type { WhisperKeysState } from "../whisper/useWhisperKeys";
import { whisper, suiClient } from "../whisper/client";
import type { ActiveAccount, DemoMode, TxExecutor } from "../whisper/session";
import type { DevAccountSummary } from "../whisper/useDevSession";
import { RawId } from "./RawId";

interface Props {
  registry: RegistryEntry[];
  keysState: WhisperKeysState;
  account: ActiveAccount | null;
  mode: DemoMode;
  txExecutor: TxExecutor | null;
  devEnabled: boolean;
  devAccounts: DevAccountSummary[];
  onSelectDevAccount: (label: string) => void;
}

function shortCoord(s: string): string {
  if (s.length <= 14) return s;
  return `${s.slice(0, 6)}…${s.slice(-6)}`;
}

export function IdentityBar({
  registry,
  keysState,
  account,
  mode,
  txExecutor,
  devEnabled,
  devAccounts,
  onSelectDevAccount,
}: Props) {
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
    return (
      myEntry.pubkeyX === keysState.keys.pubkeyX &&
      myEntry.pubkeyY === keysState.keys.pubkeyY
    );
  }, [myEntry, keysState.keys]);

  useEffect(() => {
    if (!regSuccess) return;
    const t = setTimeout(() => setRegSuccess(null), 8000);
    return () => clearTimeout(t);
  }, [regSuccess]);

  async function registerKey(keys: DerivedBabyJubKeypair) {
    setRegistering(true);
    setRegError(null);
    setRegSuccess(null);
    try {
      const tx = whisper.buildRegisterKeyTx({
        pubkeyX: keys.pubkeyX,
        pubkeyY: keys.pubkeyY,
      });
      if (!txExecutor) throw new Error("no transaction signer available");
      const result = await txExecutor(tx);
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
        <span className="identity-label">MODE</span>
        <span className="identity-cell-value">
          {mode === "wallet" ? (
            <ConnectButton connectText="connect wallet" />
          ) : (
            <span className="identity-status ok">
              dev signer
              {devAccounts.length > 1 ? (
                <>
                  <span className="identity-sep">·</span>
                  <select
                    className="dev-account-select"
                    value={account?.label ?? ""}
                    onChange={(e) => onSelectDevAccount(e.target.value)}
                    aria-label="active dev account"
                  >
                    {devAccounts.map((a) => (
                      <option key={a.label} value={a.label}>
                        {a.label}
                      </option>
                    ))}
                  </select>
                </>
              ) : account?.label ? (
                <>
                  <span className="identity-sep">·</span>
                  {account.label}
                </>
              ) : null}
            </span>
          )}
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
              {mode === "dev" ? (
                <>
                  <span className="identity-sep">·</span>local
                </>
              ) : keysState.hasCached === true && (
                <>
                  <span className="identity-sep">·</span>cached
                </>
              )}
            </span>
          ) : keysState.deriving ? (
            <span className="identity-status">
              <span className="spinner" /> awaiting wallet…
            </span>
          ) : mode === "dev" ? (
            <span className="identity-status error">missing dev signer</span>
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

      {mode === "dev" && devEnabled && (
        <div className="identity-toast">
          <strong>DEV MODE</strong>
          <span>·</span>
          <span>transactions signed locally for</span>
          {account ? (
            <RawId value={account.address} kind="address" />
          ) : (
            <span style={{ color: "var(--text-faint)" }}>signer unavailable</span>
          )}
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
          <span className="mono-trunc" style={{ color: "var(--text-dim)" }}>
            ({shortCoord(keysState.keys.pubkeyX)}, {shortCoord(keysState.keys.pubkeyY)})
          </span>
          <span className="identity-foot-spacer" />
          <span className="identity-foot-scheme">suite babyjub+poseidon</span>
        </div>
      )}
    </div>
  );
}
