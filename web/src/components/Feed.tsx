import { bytesToHex } from "@noble/hashes/utils";
import type { FeedEvent, FeedEnvelopeEvent, FeedKeyEvent } from "../sui/queries";
import {
  labelForAddress,
  normalizeAddress,
  shortAddress,
} from "../crypto/identities";
import { tryDecrypt } from "../crypto/decrypt";
import { usePerspective } from "../perspective/context";

interface Props {
  events: FeedEvent[];
  loading: boolean;
}

function formatRelative(ms: number, now: number): string {
  if (!ms) return "—";
  const delta = Math.max(0, now - ms);
  if (delta < 5_000) return "just now";
  if (delta < 60_000) return `${Math.round(delta / 1000)}s ago`;
  if (delta < 3_600_000) return `${Math.round(delta / 60_000)}m ago`;
  if (delta < 86_400_000) return `${Math.round(delta / 3_600_000)}h ago`;
  return `${Math.round(delta / 86_400_000)}d ago`;
}

function ciphertextPreview(b: Uint8Array): string {
  if (b.length === 0) return "<envelope deleted on-chain>";
  const hex = bytesToHex(b);
  if (hex.length <= 96) return hex;
  return `${hex.slice(0, 88)}…${hex.slice(-8)}`;
}

function KeyRow({ ev, now }: { ev: FeedKeyEvent; now: number }) {
  return (
    <div className="row-event kind-key">
      <div className="row-event-side">
        <span className="row-event-kind">KEY · v{ev.keyVersion}</span>
        <span>{formatRelative(ev.timestampMs, now)}</span>
      </div>
      <div className="row-event-body">
        <div className="bubble">
          <div className="bubble-header">
            <span className="tag tag-key">REGISTERED</span>
            <span className="address-known">{labelForAddress(ev.account)}</span>
            <span className="address-unknown">{shortAddress(ev.account)}</span>
          </div>
          <div className="bubble-body" style={{ color: "var(--text-dim)" }}>
            {ev.encryptionScheme} · key_version {ev.keyVersion}
          </div>
        </div>
      </div>
    </div>
  );
}

function EnvelopeRow({ ev, now }: { ev: FeedEnvelopeEvent; now: number }) {
  const { identity, perspective } = usePerspective();
  const youAddr = identity ? normalizeAddress(identity.suiAddress) : null;
  const isOutgoing = !!youAddr && youAddr === ev.sender;
  const isIncoming = !!youAddr && youAddr === ev.recipient;

  let plaintext: string | null = null;
  if (isIncoming && identity) {
    plaintext = tryDecrypt(identity, {
      sender: ev.sender,
      recipient: ev.recipient,
      ephPubkey: ev.ephPubkey,
      nonce: ev.nonce,
      ciphertext: ev.ciphertext,
    });
  }

  let stateClass = "locked";
  let bubbleClass = "bubble locked";
  let tagText = "ENCRYPTED";
  let tagClass = "tag tag-locked";
  if (isOutgoing) {
    stateClass = "outgoing";
    bubbleClass = "bubble";
    tagText = "SENT BY YOU";
    tagClass = "tag tag-outgoing";
  } else if (plaintext !== null) {
    stateClass = "unlocked";
    bubbleClass = "bubble";
    tagText = "DECRYPTED FOR YOU";
    tagClass = "tag tag-decrypted";
  }

  return (
    <div className={`row-event kind-envelope ${stateClass}`}>
      <div className="row-event-side">
        <span className="row-event-kind">ENV · v{ev.keyVersion}</span>
        <span>{formatRelative(ev.timestampMs, now)}</span>
      </div>
      <div className="row-event-body">
        <div className={bubbleClass}>
          <div className="bubble-header">
            <span className={tagClass}>{tagText}</span>
            <span className={youAddr === ev.sender ? "address you" : "address-known"}>
              {labelForAddress(ev.sender)}
            </span>
            <span className="arrow">→</span>
            <span className={youAddr === ev.recipient ? "address you" : "address-known"}>
              {labelForAddress(ev.recipient)}
            </span>
            <span style={{ marginLeft: "auto", color: "var(--text-faint)" }}>{ev.schema}</span>
          </div>
          {isOutgoing ? (
            <div className="bubble-body outgoing">
              <em style={{ fontStyle: "normal", color: "var(--text-dim)" }}>
                you authored this; the plaintext is not on chain. preview only available to{" "}
                {labelForAddress(ev.recipient)}.
              </em>
            </div>
          ) : plaintext !== null ? (
            <div className="bubble-body plaintext">{plaintext}</div>
          ) : (
            <div className="bubble-body cipher" title="raw ciphertext (AEAD-protected)">
              {ciphertextPreview(ev.ciphertext)}
              {perspective !== "observer" && ev.ciphertext.length > 0 && (
                <div style={{ marginTop: "0.4rem", color: "var(--text-faint)" }}>
                  · not addressed to you · cannot derive AEAD key
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

export function Feed({ events, loading }: Props) {
  const now = Date.now();
  return (
    <div>
      <div className="section-title">
        <span>EVENT FEED · {events.length}</span>
        <span className="section-title-actions">
          {loading ? <><span className="spinner" /> syncing</> : "polling every 3s"}
        </span>
      </div>
      {events.length === 0 ? (
        <div className="feed-empty">
          No events yet. Run <code>cargo run -- register-key alice</code> from the project root.
        </div>
      ) : (
        <div className="feed">
          {events.map((ev) =>
            ev.kind === "key" ? (
              <KeyRow key={`${ev.txDigest}-${ev.account}`} ev={ev} now={now} />
            ) : (
              <EnvelopeRow key={ev.envelopeId || ev.txDigest} ev={ev} now={now} />
            ),
          )}
        </div>
      )}
    </div>
  );
}
