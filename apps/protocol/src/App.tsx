import { useEffect, useRef, useState } from "react";
import { useCurrentAccount, useSignAndExecuteTransaction } from "@mysten/dapp-kit";
import type { FeedEvent } from "@whisper-protocol/sdk/feed";
import { fetchFeed } from "@whisper-protocol/sdk/feed";
import type { RegistryEntry } from "@whisper-protocol/sdk";
import { ACTIVE_CHAIN, suiClient, whisper, PACKAGE_ID, REGISTRY_ID } from "./whisper/client";
import { useWhisperKeys } from "./whisper/useWhisperKeys";
import { useDevSession } from "./whisper/useDevSession";
import type { ActiveAccount, DemoMode, TxExecutor } from "./whisper/session";
import { RegistryView } from "./components/RegistryView";
import { Feed } from "./components/Feed";
import { ComposeTabs } from "./components/ComposeTabs";
import { AuditToggle } from "./components/AuditToggle";
import { IdentityBar } from "./components/IdentityBar";
import { RawId } from "./components/RawId";

const POLL_INTERVAL_MS = 3000;

export function App() {
  const walletAccount = useCurrentAccount();
  const { mutateAsync: walletSignAndExecute } = useSignAndExecuteTransaction();
  const walletKeysState = useWhisperKeys();
  const devSession = useDevSession();
  const [mode, setMode] = useState<DemoMode>(devSession.enabled ? "dev" : "wallet");
  const [registry, setRegistry] = useState<RegistryEntry[]>([]);
  const [feed, setFeed] = useState<FeedEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [err, setErr] = useState<string | null>(null);
  const [protocolError, setProtocolError] = useState<string | null>(null);
  const cancelled = useRef(false);

  useEffect(() => {
    if (!devSession.enabled && mode === "dev") {
      setMode("wallet");
    }
  }, [devSession.enabled, mode]);

  const account: ActiveAccount | null =
    mode === "dev"
      ? devSession.account
      : walletAccount
        ? { address: walletAccount.address, source: "wallet" }
        : null;

  const keysState = mode === "dev" ? devSession.keysState : walletKeysState;

  const txExecutor: TxExecutor | null =
    mode === "dev"
      ? devSession.executeTransaction
      : async (transaction) => {
          const result = await walletSignAndExecute({
            transaction,
            chain: ACTIVE_CHAIN,
          });
          return { digest: result.digest };
        };

  // Run the write-compatibility check once at mount. Read paths stay
  // versioned per envelope, but writing the current V2 format still
  // requires the deployment to expose the expected protocol_version.
  useEffect(() => {
    let cancelledLocal = false;
    whisper
      .assertWriteCompatible()
      .catch((e: unknown) => {
        if (cancelledLocal) return;
        setProtocolError(e instanceof Error ? e.message : String(e));
      });
    return () => {
      cancelledLocal = true;
    };
  }, []);

  useEffect(() => {
    cancelled.current = false;
    let timer: ReturnType<typeof setTimeout> | null = null;
    const tick = async () => {
      try {
        const [r, f] = await Promise.all([
          whisper.fetchRegistry(),
          fetchFeed(suiClient, { packageId: PACKAGE_ID, withGas: true }),
        ]);
        if (cancelled.current) return;
        setRegistry(r);
        setFeed(f);
        setErr(null);
      } catch (e) {
        if (cancelled.current) return;
        setErr(e instanceof Error ? e.message : String(e));
      } finally {
        if (cancelled.current) return;
        setLoading(false);
        timer = setTimeout(tick, POLL_INTERVAL_MS);
      }
    };
    void tick();
    return () => {
      cancelled.current = true;
      if (timer) clearTimeout(timer);
    };
  }, []);

  return (
    <div className="app">
      <header className="app-header">
        <div className="app-header-row">
          <h1 className="app-title">WHISPER · PROTOCOL</h1>
          <div className="app-header-actions">
            <div className="mode-toggle" role="tablist" aria-label="session mode">
              <button
                type="button"
                aria-pressed={mode === "wallet"}
                onClick={() => setMode("wallet")}
              >
                wallet mode
              </button>
              {devSession.enabled && (
                <button
                  type="button"
                  aria-pressed={mode === "dev"}
                  onClick={() => setMode("dev")}
                >
                  dev mode
                </button>
              )}
            </div>
            <AuditToggle />
          </div>
        </div>
        <p className="app-sub">
          live view of the whisper protocol — sui-based private messaging where the chain stores
          the ciphertext, sender, and recipient publicly, but only the addressee can read the
          plaintext. flip <strong>audit ids</strong> to expand every on-chain reference and copy
          them by clicking.
        </p>
        <div className="app-meta">
          <span>
            <strong>package</strong> <RawId value={PACKAGE_ID} kind="package" />
          </span>
          <span>
            <strong>registry</strong> <RawId value={REGISTRY_ID} kind="registry" />
          </span>
        </div>
      </header>

      <IdentityBar
        registry={registry}
        account={account}
        keysState={keysState}
        mode={mode}
        txExecutor={txExecutor}
        devEnabled={devSession.enabled}
        devAccounts={devSession.accounts}
        onSelectDevAccount={devSession.setActiveLabel}
      />

      {protocolError && (
        <div className="notice" style={{ borderColor: "var(--bad)", color: "var(--bad)" }}>
          <strong>WRITE COMPATIBILITY MISMATCH ·</strong> {protocolError}
          <div style={{ marginTop: "0.5rem", color: "var(--text-faint)" }}>
            Reading older supported envelopes may still work, but posting the current envelope
            format against this package is unsafe. Update the SDK or point the dApp at a
            compatible deployment before sending.
          </div>
        </div>
      )}

      {err && (
        <div className="notice" style={{ borderColor: "var(--bad)", color: "var(--bad)" }}>
          <strong>RPC ERROR ·</strong> {err}
          <div style={{ marginTop: "0.5rem", color: "var(--text-faint)" }}>
            Check that the configured RPC is reachable and that the package + registry IDs match
            the current network.
          </div>
        </div>
      )}

      {mode === "dev" && (
        <div className="notice" style={{ marginTop: "1.5rem" }}>
          <strong>DEV MODE ·</strong> transactions are signed locally in-browser against{" "}
          <RawId value={ACTIVE_CHAIN} kind="bytes" forceRaw />. this bypasses wallet network
          support and is meant for protocol testing only.
        </div>
      )}

      {!account ? (
        <div className="notice" style={{ marginTop: "1.5rem" }}>
          <strong>{mode === "wallet" ? "OBSERVER MODE" : "DEV SIGNER UNAVAILABLE"} ·</strong>{" "}
          {mode === "wallet"
            ? "no wallet connected. you see only what a public indexer would: ciphertext, sender, recipient, schema, and key version. connect a wallet above to unlock encryption + decryption for your address."
            : "dev signer is enabled but not ready. check the local env config and reload the page."}
        </div>
      ) : !keysState.keys ? (
        <div className="notice" style={{ marginTop: "1.5rem" }}>
          <strong>{mode === "wallet" ? "SIGN TO UNLOCK" : "DERIVING DEV KEYS"} ·</strong>{" "}
          {mode === "wallet"
            ? "click derive in the bar above. your wallet will sign a fixed canonical message; we feed the signature directly into the BabyJubjub keypair-from-seed primitive. the signature itself never leaves the browser. cached in indexeddb so you only sign once per device."
            : "the configured dev signer derives a local BabyJubjub keypair from its personal-message signature before it can register or decrypt."}
        </div>
      ) : (
        <div className="notice" style={{ marginTop: "1.5rem" }}>
          <strong>READY ·</strong> envelopes addressed to your account decrypt locally using your
          derived BabyJubjub key. envelopes addressed to other recipients remain ciphertext —
          no on-chain access control, only cryptographic recipient binding.
        </div>
      )}

      <div className="section">
        <ComposeTabs
          registry={registry}
          keys={keysState.keys}
          account={account}
          mode={mode}
          txExecutor={txExecutor}
        />
      </div>

      <div className="section">
        <RegistryView entries={registry} loading={loading} account={account} />
      </div>

      <div className="section">
        <Feed
          events={feed}
          loading={loading}
          keys={keysState.keys}
          account={account}
          txExecutor={txExecutor}
        />
      </div>

      <footer className="footer">
        package · <RawId value={PACKAGE_ID} kind="package" forceRaw /> · registry ·{" "}
        <RawId value={REGISTRY_ID} kind="registry" forceRaw />
      </footer>
    </div>
  );
}
