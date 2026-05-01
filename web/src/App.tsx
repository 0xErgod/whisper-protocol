import { useEffect, useRef, useState } from "react";
import { useCurrentAccount } from "@mysten/dapp-kit";
import type { FeedEvent } from "@whisper-protocol/sdk/feed";
import { fetchFeed } from "@whisper-protocol/sdk/feed";
import type { RegistryEntry } from "@whisper-protocol/sdk";
import { suiClient, whisper, PACKAGE_ID, REGISTRY_ID } from "./whisper/client";
import { useWhisperKeys } from "./whisper/useWhisperKeys";
import { RegistryView } from "./components/RegistryView";
import { Feed } from "./components/Feed";
import { Compose } from "./components/Compose";
import { AuditToggle } from "./components/AuditToggle";
import { IdentityBar } from "./components/IdentityBar";
import { RawId } from "./components/RawId";

const POLL_INTERVAL_MS = 3000;

export function App() {
  const account = useCurrentAccount();
  const keysState = useWhisperKeys();
  const [registry, setRegistry] = useState<RegistryEntry[]>([]);
  const [feed, setFeed] = useState<FeedEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [err, setErr] = useState<string | null>(null);
  const cancelled = useRef(false);

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
          <AuditToggle />
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

      <IdentityBar registry={registry} keysState={keysState} />

      {err && (
        <div className="notice" style={{ borderColor: "var(--bad)", color: "var(--bad)" }}>
          <strong>RPC ERROR ·</strong> {err}
          <div style={{ marginTop: "0.5rem", color: "var(--text-faint)" }}>
            Check that the configured RPC is reachable and that the package + registry IDs match
            the current network.
          </div>
        </div>
      )}

      {!account ? (
        <div className="notice" style={{ marginTop: "1.5rem" }}>
          <strong>OBSERVER MODE ·</strong> no wallet connected. you see only what a public indexer
          would: ciphertext, sender, recipient, schema, and key version. connect a wallet above to
          unlock encryption + decryption for your address.
        </div>
      ) : !keysState.keys ? (
        <div className="notice" style={{ marginTop: "1.5rem" }}>
          <strong>SIGN TO UNLOCK ·</strong> click <em>derive</em> in the bar above. your wallet
          will sign a fixed canonical message; we feed the signature through HKDF to derive an
          X25519 keypair. the signature itself never leaves the browser. cached in indexeddb so
          you only sign once per device.
        </div>
      ) : (
        <div className="notice" style={{ marginTop: "1.5rem" }}>
          <strong>READY ·</strong> envelopes addressed to your account decrypt locally using your
          derived X25519 key. envelopes addressed to other recipients remain ciphertext — no
          on-chain access control, only cryptographic recipient binding.
        </div>
      )}

      <div className="section">
        <Compose registry={registry} keys={keysState.keys} />
      </div>

      <div className="section">
        <RegistryView entries={registry} loading={loading} />
      </div>

      <div className="section">
        <Feed events={feed} loading={loading} keys={keysState.keys} />
      </div>

      <footer className="footer">
        package · <RawId value={PACKAGE_ID} kind="package" forceRaw /> · registry ·{" "}
        <RawId value={REGISTRY_ID} kind="registry" forceRaw />
      </footer>
    </div>
  );
}
