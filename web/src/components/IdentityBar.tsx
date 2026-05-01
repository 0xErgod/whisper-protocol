import { useMemo, useState } from "react";
import {
  ConnectButton,
  useCurrentAccount,
  useSignAndExecuteTransaction,
} from "@mysten/dapp-kit";
import { bytesToHex } from "@noble/hashes/utils";
import {
  ENCRYPTION_SCHEME,
  normalizeAddress,
  type RegistryEntry,
} from "@whisper-protocol/sdk";
import type { DerivedEncryptionKeypair } from "@whisper-protocol/wallet-derived-keys";
import type { WhisperKeysState } from "../whisper/useWhisperKeys";
import { whisper, suiClient } from "../whisper/client";
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

  async function registerKey(keys: DerivedEncryptionKeypair) {
    setRegistering(true);
    setRegError(null);
    setRegSuccess(null);
    try {
      const tx = whisper.buildRegisterKeyTx(keys.encryptionPublicKey);
      const result = await signAndExecute({ transaction: tx });
      const full = await suiClient.waitForTransaction({
        digest: result.digest,
        options: { showEffects: true },
      });
      const status = (full.effects?.status as { status?: string; error?: string } | undefined)
        ?.status ?? "unknown";
      if (status !== "success") {
        const errText = (full.effects?.status as { error?: string } | undefined)?.error;
        throw new Error(`tx failed (${status})${errText ? `: ${errText}` : ""}`);
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
      <div className="identity-bar-row">
        <div className="identity-bar-section">
          <span className="identity-label">WALLET</span>
          <ConnectButton connectText="connect wallet" />
        </div>

        {account && (
          <div className="identity-bar-section">
            <span className="identity-label">ADDRESS</span>
            <RawId value={account.address} kind="address" />
          </div>
        )}

        {account && (
          <div className="identity-bar-section">
            <span className="identity-label">ENCRYPTION KEYS</span>
            {keysState.keys ? (
              <span className="identity-status ok">
                derived
                {keysState.hasCached === true && " · cached"}
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
          </div>
        )}

        {account && keysState.keys && (
          <div className="identity-bar-section">
            <span className="identity-label">REGISTRATION</span>
            {myEntry === null ? (
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
                v{myEntry.keyVersion} · matches local
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
          </div>
        )}
      </div>

      {keysState.error && (
        <div className="identity-bar-row">
          <span className="identity-status error">DERIVE ERROR · {keysState.error}</span>
        </div>
      )}
      {regError && (
        <div className="identity-bar-row">
          <span className="identity-status error">REGISTER ERROR · {regError}</span>
        </div>
      )}
      {regSuccess && (
        <div className="identity-bar-row">
          <span className="identity-status ok">
            registered · tx <RawId value={regSuccess} kind="tx" />
          </span>
        </div>
      )}

      {account && keysState.keys && (
        <div className="identity-bar-row identity-bar-detail">
          <span style={{ color: "var(--text-faint)" }}>
            local pubkey
          </span>
          <RawId value={`0x${bytesToHex(keysState.keys.encryptionPublicKey)}`} kind="bytes" />
          <span style={{ color: "var(--text-faint)", marginLeft: "auto" }}>
            scheme {ENCRYPTION_SCHEME}
          </span>
        </div>
      )}
    </div>
  );
}
