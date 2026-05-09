import { bytesToHex } from "@noble/hashes/utils";
import {
  assertCanReadEnvelope,
  assertCanReadMultiEnvelope,
  normalizeAddress,
  UnsupportedEncryptionSchemeError,
  UnsupportedEnvelopeFormatVersionError,
  tryDecryptUtf8,
  tryDecryptMultiUtf8,
} from "@whisper-protocol/sdk";
import type {
  FeedEvent,
  FeedEnvelopeEvent,
  FeedKeyEvent,
  FeedMultiEnvelopeEvent,
} from "@whisper-protocol/sdk/feed";
import type { DerivedEncryptionKeypair } from "@whisper-protocol/wallet-derived-keys";
import type { ActiveAccount } from "../whisper/session";
import { RawId } from "./RawId";
import { gasBreakdownTooltip, shortGas } from "../whisper/gas";

interface Props {
  events: FeedEvent[];
  loading: boolean;
  keys: DerivedEncryptionKeypair | null;
  account: ActiveAccount | null;
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
  let unsupportedReason: string | null = null;

  let plaintext: string | null = null;
  if (isIncoming && keys) {
    try {
      assertCanReadEnvelope(ev);
      plaintext = tryDecryptUtf8({
        recipientPrivateKey: keys.encryptionPrivateKey,
        encryptionScheme: ev.encryptionScheme,
        senderAddress: ev.sender,
        recipientAddress: ev.recipient,
        ephPubkey: ev.ephPubkey,
        nonce: ev.nonce,
        ciphertext: ev.ciphertext,
      });
    } catch (error: unknown) {
      if (error instanceof UnsupportedEnvelopeFormatVersionError) {
        unsupportedReason = `unsupported format_version v${error.formatVersion}`;
      } else if (error instanceof UnsupportedEncryptionSchemeError) {
        unsupportedReason = `unsupported suite ${error.encryptionScheme}`;
      } else {
        unsupportedReason = "unsupported envelope";
      }
    }
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
        <span className="row-event-kind">ENV · fmt v{ev.formatVersion} · key v{ev.keyVersion}</span>
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
            <span style={{ marginLeft: "auto", color: "var(--text-faint)" }}>
              {ev.schema} · {ev.encryptionScheme}
            </span>
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
          ) : unsupportedReason ? (
            <div className="bubble-body cipher">
              <strong style={{ fontWeight: "normal" }}>cannot decrypt</strong>
              <div style={{ marginTop: "0.4rem", color: "var(--text-faint)" }}>
                · {unsupportedReason}
              </div>
            </div>
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

function MultiEnvelopeRow({
  ev,
  now,
  myAddress,
  keys,
}: {
  ev: FeedMultiEnvelopeEvent;
  now: number;
  myAddress: string | null;
  keys: DerivedEncryptionKeypair | null;
}) {
  const isOutgoing = !!myAddress && myAddress === ev.sender;
  const myIndex = myAddress ? ev.recipients.indexOf(myAddress) : -1;
  const isIncoming = myIndex >= 0;
  let unsupportedReason: string | null = null;

  let plaintext: string | null = null;
  if (isIncoming && keys && ev.wrappedKeys.length > myIndex && ev.wrapNonces.length > myIndex) {
    try {
      assertCanReadMultiEnvelope(ev);
      plaintext = tryDecryptMultiUtf8({
        recipientPrivateKey: keys.encryptionPrivateKey,
        encryptionScheme: ev.encryptionScheme,
        senderAddress: ev.sender,
        recipientAddress: ev.recipients[myIndex]!,
        ephPubkey: ev.ephPubkey,
        payloadNonce: ev.payloadNonce,
        ciphertext: ev.ciphertext,
        wrappedKey: ev.wrappedKeys[myIndex]!,
        wrapNonce: ev.wrapNonces[myIndex]!,
      });
    } catch (error: unknown) {
      if (error instanceof UnsupportedEnvelopeFormatVersionError) {
        unsupportedReason = `unsupported format_version v${error.formatVersion}`;
      } else if (error instanceof UnsupportedEncryptionSchemeError) {
        unsupportedReason = `unsupported suite ${error.encryptionScheme}`;
      } else {
        unsupportedReason = "unsupported envelope";
      }
    }
  }

  let stateClass = "locked";
  let bubbleClass = "bubble locked";
  let tagText = "ENCRYPTED";
  let tagClass = "tag tag-locked";
  if (isOutgoing) {
    stateClass = "outgoing";
    bubbleClass = "bubble";
    tagText = `SENT BY YOU TO ${ev.recipients.length}`;
    tagClass = "tag tag-outgoing";
  } else if (plaintext !== null) {
    stateClass = "unlocked";
    bubbleClass = "bubble";
    tagText = "DECRYPTED FOR YOU";
    tagClass = "tag tag-decrypted";
  }

  return (
    <div className={`row-event kind-envelope kind-multi ${stateClass}`}>
      <div className="row-event-side">
        <span className="row-event-kind">
          MULTI · fmt v{ev.formatVersion} · {ev.recipients.length} recipients
        </span>
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
            <span className="recipient-list">
              {ev.recipients.map((r, i) => (
                <span key={r} className={r === myAddress ? "recipient-list-you" : undefined}>
                  <RawId value={r} kind="address" />
                  {i < ev.recipients.length - 1 ? ", " : ""}
                </span>
              ))}
            </span>
            <span style={{ marginLeft: "auto", color: "var(--text-faint)" }}>
              {ev.schema} · {ev.encryptionScheme}
            </span>
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
                you authored this; the plaintext is not on chain. only the listed recipients can derive their wrap key and unlock K_msg.
              </em>
            </div>
          ) : plaintext !== null ? (
            <div className="bubble-body plaintext">{plaintext}</div>
          ) : unsupportedReason ? (
            <div className="bubble-body cipher">
              <strong style={{ fontWeight: "normal" }}>cannot decrypt</strong>
              <div style={{ marginTop: "0.4rem", color: "var(--text-faint)" }}>
                · {unsupportedReason}
              </div>
            </div>
          ) : (
            <div className="bubble-body cipher" title="raw ciphertext (AEAD-protected)">
              {ciphertextPreview(ev.ciphertext)}
              {myAddress && ev.ciphertext.length > 0 && !isIncoming && (
                <div style={{ marginTop: "0.4rem", color: "var(--text-faint)" }}>
                  · you are not in the recipient set · cannot derive any wrap key
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

export function Feed({ events, loading, keys, account }: Props) {
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
          {events.map((ev) => {
            if (ev.kind === "key") {
              return (
                <KeyRow
                  key={`${ev.txDigest}-${ev.account}`}
                  ev={ev}
                  now={now}
                  isYou={!!myAddress && myAddress === ev.account}
                />
              );
            }
            if (ev.kind === "multi-envelope") {
              return (
                <MultiEnvelopeRow
                  key={ev.envelopeId || ev.txDigest}
                  ev={ev}
                  now={now}
                  myAddress={myAddress}
                  keys={keys}
                />
              );
            }
            return (
              <EnvelopeRow
                key={ev.envelopeId || ev.txDigest}
                ev={ev}
                now={now}
                myAddress={myAddress}
                keys={keys}
              />
            );
          })}
        </div>
      )}
    </div>
  );
}
