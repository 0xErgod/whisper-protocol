import { bytesToHex } from "@noble/hashes/utils";
import { useCurrentAccount } from "@mysten/dapp-kit";
import { normalizeAddress, tryDecryptUtf8 } from "@whisper-protocol/sdk";
import type { FeedEvent, FeedEnvelopeEvent, FeedKeyEvent } from "@whisper-protocol/sdk/feed";
import type { DerivedEncryptionKeypair } from "@whisper-protocol/wallet-derived-keys";
import { RawId } from "./RawId";
import { gasBreakdownTooltip, shortGas } from "../whisper/gas";

interface Props {
  events: FeedEvent[];
  loading: boolean;
  keys: DerivedEncryptionKeypair | null;
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

function KeyRow({ ev, now, isYou }: { ev: FeedKeyEvent; now: number; isYou: boolean }) {
  return (
    <div className="row-event kind-key">
      <div className="row-event-side">
        <span className="row-event-kind">KEY · v{ev.keyVersion}</span>
        <span>{formatRelative(ev.timestampMs, now)}</span>
        <span className="row-event-gas" title={gasBreakdownTooltip(ev.gas)}>
          gas {shortGas(ev.gas)}
        </span>
      </div>
      <div className="row-event-body">
        <div className="bubble">
          <div className="bubble-header">
            <span className="tag tag-key">{isYou ? "YOU REGISTERED" : "REGISTERED"}</span>
            <RawId value={ev.account} kind="address" />
            <span style={{ marginLeft: "auto", color: "var(--text-faint)" }}>
              tx <RawId value={ev.txDigest} kind="tx" />
            </span>
          </div>
          <div className="bubble-body" style={{ color: "var(--text-dim)" }}>
            {ev.encryptionScheme} · key_version {ev.keyVersion}
          </div>
        </div>
      </div>
    </div>
  );
}

function EnvelopeRow({
  ev,
  now,
  myAddress,
  keys,
}: {
  ev: FeedEnvelopeEvent;
  now: number;
  myAddress: string | null;
  keys: DerivedEncryptionKeypair | null;
}) {
  const isOutgoing = !!myAddress && myAddress === ev.sender;
  const isIncoming = !!myAddress && myAddress === ev.recipient;

  let plaintext: string | null = null;
  if (isIncoming && keys) {
    plaintext = tryDecryptUtf8({
      recipientPrivateKey: keys.encryptionPrivateKey,
      senderAddress: ev.sender,
      recipientAddress: ev.recipient,
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
        <span className="row-event-gas" title={gasBreakdownTooltip(ev.gas)}>
          gas {shortGas(ev.gas)}
        </span>
      </div>
      <div className="row-event-body">
        <div className={bubbleClass}>
          <div className="bubble-header">
            <span className={tagClass}>{tagText}</span>
            <RawId value={ev.sender} kind="address" />
            <span className="arrow">→</span>
            <RawId value={ev.recipient} kind="address" />
            <span style={{ marginLeft: "auto", color: "var(--text-faint)" }}>{ev.schema}</span>
          </div>
          <div className="bubble-meta">
            <span>
              env <RawId value={ev.envelopeId} kind="envelope" />
            </span>
            <span>
              tx <RawId value={ev.txDigest} kind="tx" />
            </span>
          </div>
          {isOutgoing ? (
            <div className="bubble-body outgoing">
              <em style={{ fontStyle: "normal", color: "var(--text-dim)" }}>
                you authored this; the plaintext is not on chain. preview only available to the recipient.
              </em>
            </div>
          ) : plaintext !== null ? (
            <div className="bubble-body plaintext">{plaintext}</div>
          ) : (
            <div className="bubble-body cipher" title="raw ciphertext (AEAD-protected)">
              {ciphertextPreview(ev.ciphertext)}
              {myAddress && ev.ciphertext.length > 0 && !isIncoming && (
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

export function Feed({ events, loading, keys }: Props) {
  const account = useCurrentAccount();
  const myAddress = account ? normalizeAddress(account.address) : null;
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
          No events yet. Connect a wallet, derive your encryption keypair, and register it
          to start the feed.
        </div>
      ) : (
        <div className="feed">
          {events.map((ev) =>
            ev.kind === "key" ? (
              <KeyRow
                key={`${ev.txDigest}-${ev.account}`}
                ev={ev}
                now={now}
                isYou={!!myAddress && myAddress === ev.account}
              />
            ) : (
              <EnvelopeRow
                key={ev.envelopeId || ev.txDigest}
                ev={ev}
                now={now}
                myAddress={myAddress}
                keys={keys}
              />
            ),
          )}
        </div>
      )}
    </div>
  );
}
