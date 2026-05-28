// Read-side display: shows the on-chain event log as it arrives, and
// lets the active account decrypt envelopes addressed to it. Decrypt
// is client-side: fetch the full envelope object, run the BJJ open
// path via the SDK, decode the recovered stream back to text.

import { useState } from "react";
import {
  cryptoWasm,
  normalizeAddress,
  WhisperOpenError,
  type DerivedBabyJubKeypair,
  type RegistryEntry,
} from "@whisper-protocol/sdk";
import type { FeedEvent, FeedEnvelopeEvent } from "@whisper-protocol/sdk/feed";
import { whisper } from "../whisper/client";
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

export function Feed({ events, loading, keys, account }: Props) {
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
                <FeedItemBody event={e} account={account} keys={keys} />
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}

function FeedItemBody({
  event,
  account,
  keys,
}: {
  event: FeedEvent;
  account: ActiveAccount | null;
  keys: DerivedBabyJubKeypair | null;
}) {
  switch (event.kind) {
    case "key":
      return (
        <div className="feed-item-body">
          <RawId value={event.account} kind="address" />
          <span className="feed-sep">·</span>
          <span style={{ color: "var(--text-dim)" }}>
            v{event.keyVersion} · pubkey ({shortCoord(event.pubkeyX)}, {shortCoord(event.pubkeyY)})
          </span>
        </div>
      );
    case "envelope":
      return <EnvelopeItem event={event} account={account} keys={keys} />;
    case "committed":
      return (
        <div className="feed-item-body">
          <RawId value={event.author} kind="address" />
          <span className="feed-sep">·</span>
          <span style={{ color: "var(--text-dim)" }}>
            commitment ({shortCoord(event.commitmentX)}, {shortCoord(event.commitmentY)}) · encoding{" "}
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
            opened ({shortCoord(event.commitmentX)}, {shortCoord(event.commitmentY)}) ·{" "}
            {event.stream.length} elements
          </span>
        </div>
      );
  }
}

function EnvelopeItem({
  event,
  account,
  keys,
}: {
  event: FeedEnvelopeEvent;
  account: ActiveAccount | null;
  keys: DerivedBabyJubKeypair | null;
}) {
  const [plaintext, setPlaintext] = useState<string | null>(null);
  const [decryptErr, setDecryptErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const isForMe =
    account != null && normalizeAddress(account.address) === event.recipient;
  const canDecrypt = isForMe && keys != null && !busy && plaintext === null;

  async function decrypt() {
    if (!keys) return;
    setBusy(true);
    setDecryptErr(null);
    try {
      // The feed event carries metadata only; fetch the full envelope
      // object to get the ciphertext + pubkeys the open path needs.
      const onChain = await whisper.fetchEnvelope(event.envelopeObjectId);
      if (!onChain) throw new Error("envelope object not found on chain");
      console.debug("[feed] decrypting envelope", {
        objectId: event.envelopeObjectId,
        ciphertextLen: onChain.ciphertext.length,
      });
      const payload = whisper.decryptEnvelope({
        envelope: onChain,
        recipientSeed: keys.seed,
        recipientPubkeyX: keys.pubkeyX,
        recipientPubkeyY: keys.pubkeyY,
      });
      const bytes = cryptoWasm.text_utf8_v1_decode(payload.stream);
      const text = new TextDecoder().decode(bytes);
      console.info("[feed] decrypted", { objectId: event.envelopeObjectId, chars: text.length });
      setPlaintext(text);
    } catch (e) {
      const msg =
        e instanceof WhisperOpenError ? e.message : e instanceof Error ? e.message : String(e);
      console.error("[feed] decrypt failed", msg);
      setDecryptErr(msg);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="feed-item-body">
      <RawId value={event.sender} kind="address" />
      <span className="feed-sep">→</span>
      <RawId value={event.recipient} kind="address" />
      {isForMe && <span className="you-tag">FOR YOU</span>}
      <span className="feed-sep">·</span>
      <span style={{ color: "var(--text-dim)" }}>
        envelope_id {shortCoord(event.envelopeId)}
      </span>
      {canDecrypt && (
        <button type="button" className="feed-decrypt" onClick={decrypt} disabled={busy}>
          {busy ? "decrypting…" : "decrypt"}
        </button>
      )}
      {plaintext !== null && (
        <div className="feed-plaintext" style={{ color: "var(--good)" }}>
          “{plaintext}”
        </div>
      )}
      {decryptErr && (
        <div className="feed-plaintext" style={{ color: "var(--bad)" }}>
          decrypt failed: {decryptErr}
        </div>
      )}
    </div>
  );
}
