// Read-side display: shows the on-chain event log as it arrives.
// Phase-3 minimal — renders metadata for each event kind but does NOT
// decrypt envelopes or recompute commitments (those flows wait for
// the dApp rewires in Phase 4, issue #38).

import type { DerivedBabyJubKeypair, RegistryEntry } from "@whisper-protocol/sdk";
import type { FeedEvent } from "@whisper-protocol/sdk/feed";
import type { ActiveAccount, TxExecutor } from "../whisper/session";
import { RawId } from "./RawId";

interface Props {
  events: FeedEvent[];
  loading: boolean;
  keys: DerivedBabyJubKeypair | null;
  account: ActiveAccount | null;
  txExecutor: TxExecutor | null;
  registry?: RegistryEntry[];
}

function formatTime(ms: number): string {
  if (!ms) return "—";
  const d = new Date(ms);
  return d.toISOString().replace("T", " ").slice(5, 19);
}

function shortCoord(s: string): string {
  if (s.length <= 14) return s;
  return `${s.slice(0, 6)}…${s.slice(-6)}`;
}

export function Feed({ events, loading }: Props) {
  return (
    <div className="window">
      <div className="window-header">
        <span>FEED · {events.length} EVENTS</span>
        <span>{loading ? "syncing…" : "live"}</span>
      </div>
      <div className="window-body">
        {events.length === 0 ? (
          <div className="feed-empty">No protocol events yet.</div>
        ) : (
          <ul className="feed-list">
            {events.map((e) => (
              <li key={`${e.txDigest}-${e.kind}`} className="feed-item">
                <div className="feed-item-head">
                  <span className="feed-kind">{e.kind.toUpperCase()}</span>
                  <span className="feed-time">{formatTime(e.timestampMs)}</span>
                  <RawId value={e.txDigest} kind="tx" />
                </div>
                <FeedItemBody event={e} />
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}

function FeedItemBody({ event }: { event: FeedEvent }) {
  switch (event.kind) {
    case "key":
      return (
        <div className="feed-item-body">
          <RawId value={event.account} kind="address" />
          <span className="feed-sep">·</span>
          <span style={{ color: "var(--text-dim)" }}>
            v{event.keyVersion} · pubkey ({shortCoord(event.pubkeyX)},{" "}
            {shortCoord(event.pubkeyY)})
          </span>
        </div>
      );
    case "envelope":
      return (
        <div className="feed-item-body">
          <RawId value={event.sender} kind="address" />
          <span className="feed-sep">→</span>
          <RawId value={event.recipient} kind="address" />
          <span className="feed-sep">·</span>
          <span style={{ color: "var(--text-dim)" }}>
            envelope_id {shortCoord(event.envelopeId)} · encoding{" "}
            {shortCoord(event.encodingId)}
          </span>
        </div>
      );
    case "committed":
      return (
        <div className="feed-item-body">
          <RawId value={event.author} kind="address" />
          <span className="feed-sep">·</span>
          <span style={{ color: "var(--text-dim)" }}>
            commitment ({shortCoord(event.commitmentX)},{" "}
            {shortCoord(event.commitmentY)}) · encoding{" "}
            {shortCoord(event.encodingId)}
          </span>
        </div>
      );
    case "opened":
      return (
        <div className="feed-item-body">
          <RawId value={event.author} kind="address" />
          <span className="feed-sep">·</span>
          <span style={{ color: "var(--text-dim)" }}>
            opened commitment ({shortCoord(event.commitmentX)},{" "}
            {shortCoord(event.commitmentY)}) · {event.stream.length} elements
          </span>
        </div>
      );
  }
}
