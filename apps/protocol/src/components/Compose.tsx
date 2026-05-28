import { useMemo, useState } from "react";
import type { SuiTransactionBlockResponse } from "@mysten/sui/client";
import {
  cryptoWasm,
  normalizeAddress,
  type DerivedBabyJubKeypair,
  type Envelope,
  type RegistryEntry,
} from "@whisper-protocol/sdk";
import { whisper, suiClient } from "../whisper/client";
import type { ActiveAccount, DemoMode, TxExecutor } from "../whisper/session";
import { RawId } from "./RawId";

interface Props {
  registry: RegistryEntry[];
  keys: DerivedBabyJubKeypair | null;
  account: ActiveAccount | null;
  mode: DemoMode;
  txExecutor: TxExecutor | null;
}

interface Receipt {
  txDigest: string;
  recipient: string;
  envelopeId: string;
  encodingId: string;
  ciphertextLen: number;
  macTag: string;
}

/**
 * Generate a fresh per-envelope binding scalar as a decimal string.
 * `envelope_id` must be unique per (sender, recipient) pair —
 * reusing it under the same shared point repeats the cipher key and
 * leaks plaintext-difference information. 31 random bytes is well
 * under the BN254 base-field modulus, so the value is always a valid
 * Fq with no rejection-sampling needed.
 */
function freshEnvelopeId(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(31));
  let acc = 0n;
  for (const b of bytes) acc = (acc << 8n) | BigInt(b);
  return acc.toString(10);
}

export function Compose({ registry, keys, account, txExecutor }: Props) {
  const [recipient, setRecipient] = useState("");
  const [text, setText] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [receipt, setReceipt] = useState<Receipt | null>(null);

  const recipientEntry = useMemo<RegistryEntry | null>(() => {
    if (!recipient.startsWith("0x") || recipient.length < 4) return null;
    const norm = normalizeAddress(recipient);
    return registry.find((e) => e.account === norm) ?? null;
  }, [recipient, registry]);

  const canSend = Boolean(
    account && keys && txExecutor && recipientEntry && text.trim().length > 0 && !busy,
  );

  async function send() {
    if (!account || !keys || !txExecutor || !recipientEntry) return;
    setBusy(true);
    setErr(null);
    setReceipt(null);
    try {
      const encodingId = cryptoWasm.text_utf8_v1_id();
      const stream = cryptoWasm.text_utf8_v1_encode(new TextEncoder().encode(text));
      const envelopeId = freshEnvelopeId();
      console.debug("[compose] sealing envelope", {
        recipient: recipientEntry.account,
        encodingId,
        streamLen: stream.length,
        envelopeId,
      });

      const prepared = await whisper.prepareSend({
        senderAddress: account.address,
        senderSeed: keys.seed,
        senderPubkeyX: keys.pubkeyX,
        senderPubkeyY: keys.pubkeyY,
        recipientAddress: recipientEntry.account,
        envelopeId,
        payload: { encodingId, stream },
      });
      logEnvelope(prepared.envelope);

      const result = await txExecutor(prepared.tx);
      const full: SuiTransactionBlockResponse = await suiClient.waitForTransaction({
        digest: result.digest,
        options: { showEffects: true },
      });
      const status = full.effects?.status;
      if (!status || status.status !== "success") {
        throw new Error(`tx failed (${status?.status ?? "unknown"})${status?.error ? `: ${status.error}` : ""}`);
      }
      console.info("[compose] envelope posted", { txDigest: full.digest });
      setReceipt({
        txDigest: full.digest,
        recipient: recipientEntry.account,
        envelopeId,
        encodingId,
        ciphertextLen: prepared.envelope.ciphertext.length,
        macTag: prepared.envelope.macTag,
      });
      setText("");
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      console.error("[compose] send failed", msg);
      setErr(msg);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="window">
      <div className="window-header">
        <span>COMPOSE ENVELOPE</span>
        <span>{busy ? "sealing…" : "single recipient"}</span>
      </div>
      <div className="window-body">
        {!account || !keys ? (
          <p style={{ color: "var(--text-faint)" }}>
            Derive your encryption key (identity bar above) to compose.
          </p>
        ) : (
          <>
            <label className="compose-field">
              <span className="compose-label">RECIPIENT</span>
              <input
                type="text"
                value={recipient}
                placeholder="0x… (must be in the registry)"
                onChange={(e) => setRecipient(e.target.value)}
              />
            </label>
            {recipient.length >= 4 && !recipientEntry && (
              <p className="compose-hint" style={{ color: "var(--bad)" }}>
                no registry entry for this address — they must register a key first
              </p>
            )}
            {recipientEntry && (
              <p className="compose-hint" style={{ color: "var(--text-faint)" }}>
                key v{recipientEntry.keyVersion} · pubkey ({recipientEntry.pubkeyX.slice(0, 6)}…,{" "}
                {recipientEntry.pubkeyY.slice(0, 6)}…)
              </p>
            )}
            <label className="compose-field">
              <span className="compose-label">MESSAGE</span>
              <textarea
                value={text}
                placeholder="plaintext — encoded via text-utf8-v1, max 248 bytes"
                rows={3}
                onChange={(e) => setText(e.target.value)}
              />
            </label>
            <button type="button" className="compose-send" disabled={!canSend} onClick={send}>
              {busy ? "sealing + posting…" : "seal + post envelope"}
            </button>
          </>
        )}

        {err && (
          <div className="notice" style={{ borderColor: "var(--bad)", color: "var(--bad)", marginTop: "1rem" }}>
            <strong>SEND ERROR ·</strong> {err}
          </div>
        )}

        {receipt && (
          <div className="receipt" style={{ marginTop: "1rem" }}>
            <div className="receipt-row">
              <span>tx</span>
              <RawId value={receipt.txDigest} kind="tx" />
            </div>
            <div className="receipt-row">
              <span>recipient</span>
              <RawId value={receipt.recipient} kind="address" />
            </div>
            <div className="receipt-row">
              <span>envelope_id</span>
              <span className="mono-trunc">{receipt.envelopeId.slice(0, 12)}…</span>
            </div>
            <div className="receipt-row">
              <span>ciphertext</span>
              <span>{receipt.ciphertextLen} field elements</span>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

function logEnvelope(envelope: Envelope) {
  console.debug("[compose] sealed envelope", {
    senderPk: `(${envelope.senderPkX.slice(0, 8)}…, ${envelope.senderPkY.slice(0, 8)}…)`,
    recipientPk: `(${envelope.recipientPkX.slice(0, 8)}…, ${envelope.recipientPkY.slice(0, 8)}…)`,
    ciphertextLen: envelope.ciphertext.length,
    macTag: `${envelope.macTag.slice(0, 12)}…`,
  });
}
