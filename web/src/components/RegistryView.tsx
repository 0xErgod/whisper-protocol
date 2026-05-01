import { bytesToHex } from "@noble/hashes/utils";
import { useCurrentAccount } from "@mysten/dapp-kit";
import { normalizeAddress, type RegistryEntry } from "@whisper-protocol/sdk";
import { RawId } from "./RawId";
import { useAudit } from "../perspective/audit";

interface Props {
  entries: RegistryEntry[];
  loading: boolean;
}

function formatTime(ms: number): string {
  if (!ms) return "—";
  const d = new Date(ms);
  return d.toISOString().replace("T", " ").slice(5, 19);
}

export function RegistryView({ entries, loading }: Props) {
  const account = useCurrentAccount();
  const { rawIds } = useAudit();
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
                <th>SCHEME</th>
                <th>X25519 PUBKEY</th>
                <th>VER</th>
                <th>ROTATED</th>
              </tr>
            </thead>
            <tbody>
              {entries.map((e) => {
                const isYou = youAddress === e.account;
                const pubHex = bytesToHex(e.encryptionPubkey);
                return (
                  <tr key={e.account} className={isYou ? "you-row" : undefined}>
                    <td>
                      <RawId value={e.account} kind="address" />
                      {isYou && <span className="you-tag">YOU</span>}
                    </td>
                    <td style={{ color: "var(--text-dim)" }}>{e.encryptionScheme}</td>
                    <td className="mono-trunc" style={{ color: "var(--text-dim)" }}>
                      {rawIds ? pubHex : `${pubHex.slice(0, 8)}…${pubHex.slice(-8)}`}
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
