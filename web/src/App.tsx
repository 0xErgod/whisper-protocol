import { useEffect, useRef, useState } from "react";
import { PerspectiveBar } from "./components/PerspectiveBar";
import { RegistryView } from "./components/RegistryView";
import { Feed } from "./components/Feed";
import { Compose } from "./components/Compose";
import { AuditToggle } from "./components/AuditToggle";
import { RawId } from "./components/RawId";
import { fetchFeed, fetchRegistryEntries } from "./sui/queries";
import type { FeedEvent, RegistryEntry } from "./sui/queries";
import { PACKAGE_ID, REGISTRY_ID } from "./sui/config";
import { usePerspective } from "./perspective/context";

const POLL_INTERVAL_MS = 3000;

export function App() {
  const { perspective, identity } = usePerspective();
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
        const [r, f] = await Promise.all([fetchRegistryEntries(), fetchFeed()]);
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

  const perspectiveLabel =
    perspective === "observer" ? "OBSERVER · RANDOM ADDRESS" : `AS ${identity?.label ?? perspective.toUpperCase()}`;

  return (
    <div className="app">
      <header className="app-header">
        <div className="app-header-row">
          <h1 className="app-title">WHISPER · PROTOCOL</h1>
          <AuditToggle />
        </div>
        <p className="app-sub">
          live view of the whisper protocol — an on-chain encrypted-messaging poc on sui. switch
          perspectives to see what each identity can read from the same public chain. flip{" "}
          <strong>audit ids</strong> to expand every on-chain reference and copy them by clicking.
        </p>
        <div className="app-meta">
          <span>
            <strong>package</strong> <RawId value={PACKAGE_ID} kind="package" />
          </span>
          <span>
            <strong>registry</strong> <RawId value={REGISTRY_ID} kind="registry" />
          </span>
          <span>
            <strong>viewing as</strong> {perspectiveLabel}
            {identity && (
              <>
                {" · "}
                <RawId value={identity.suiAddress} kind="address" />
              </>
            )}
          </span>
        </div>
      </header>

      {err && (
        <div className="notice" style={{ borderColor: "var(--bad)", color: "var(--bad)" }}>
          <strong>RPC ERROR ·</strong> {err}
          <div style={{ marginTop: "0.5rem", color: "var(--text-faint)" }}>
            Check that <code>sui start</code> is running on 127.0.0.1:9000 and that the configured
            package + registry ids match the current localnet.
          </div>
        </div>
      )}

      <PerspectiveBar />

      {perspective === "observer" ? (
        <div className="notice" style={{ marginTop: "1.5rem" }}>
          <strong>OBSERVER MODE ·</strong> you are looking at the chain from a random address that
          holds none of the demo key material. envelope payloads are AEAD-encrypted; you only see
          ciphertext, sender, recipient, schema, and key version — exactly what a public indexer
          would see.
        </div>
      ) : (
        <div className="notice" style={{ marginTop: "1.5rem" }}>
          <strong>AS {identity?.label} ·</strong> envelopes addressed to your account decrypt
          locally using your X25519 key. envelopes addressed to other recipients remain
          ciphertext — there is no on-chain access control, only cryptographic recipient binding.
        </div>
      )}

      <div className="section">
        <Compose registry={registry} />
      </div>

      <div className="section">
        <RegistryView entries={registry} loading={loading} />
      </div>

      <div className="section">
        <Feed events={feed} loading={loading} />
      </div>

      <footer className="footer">
        package · <RawId value={PACKAGE_ID} kind="package" forceRaw /> · registry ·{" "}
        <RawId value={REGISTRY_ID} kind="registry" forceRaw />
      </footer>
    </div>
  );
}
