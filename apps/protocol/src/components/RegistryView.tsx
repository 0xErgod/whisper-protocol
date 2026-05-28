import { normalizeAddress, type RegistryEntry } from "@whisper-protocol/sdk";
import type { ActiveAccount } from "../whisper/session";
import { RawId } from "./RawId";

interface Props {
  entries: RegistryEntry[];
  loading: boolean;
  account: ActiveAccount | null;
}

function formatTime(ms: number): string {
  if (!ms) return "—";
  const d = new Date(ms);
  return d.toISOString().replace("T", " ").slice(5, 19);
}

function shortCoord(s: string): string {
  if (s.length <= 12) return s;
  return `${s.slice(0, 6)}…${s.slice(-6)}`;
}

export function RegistryView({ entries, loading, account }: Props) {
  const youAddress = account ? normalizeAddress(account.address) : null;
  return (
    <div className="window">
      <div className="window-header">
        <span>KEY REGISTRY · {entries.length} ENTRIES</span>
        <span>{loading ? "syncing…" : "live"}</span>
      </div>
      <div className="window-body">
        {entries.length === 0 ? (
          <div className="feed-empty">No keys registered yet.</div>
        ) : (
          <table className="registry-table">
            <thead>
              <tr>
                <th>ACCOUNT</th>
                <th>BJJ PUBKEY (x, y)</th>
                <th>VER</th>
                <th>ROTATED</th>
              </tr>
            </thead>
            <tbody>
              {entries.map((e) => {
                const isYou = youAddress === e.account;
                return (
                  <tr key={e.account} className={isYou ? "you-row" : undefined}>
                    <td>
                      <RawId value={e.account} kind="address" />
                      {isYou && <span className="you-tag">YOU</span>}
                    </td>
                    <td className="mono-trunc" style={{ color: "var(--text-dim)" }}>
                      ({shortCoord(e.pubkeyX)}, {shortCoord(e.pubkeyY)})
                    </td>
                    <td>
                      <span className="registry-version">v{e.keyVersion}</span>
                    </td>
                    <td style={{ color: "var(--text-faint)" }}>{formatTime(e.rotatedAtMs)}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
