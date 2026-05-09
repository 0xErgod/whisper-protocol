import { useMemo, useState } from "react";
import { bytesToHex } from "@noble/hashes/utils";
import type { SuiTransactionBlockResponse } from "@mysten/sui/client";
import {
  MAX_RECIPIENTS,
  MODULE_ENVELOPES,
  SCHEMA_TEXT_SECRET_V1,
  normalizeAddress,
  type RegistryEntry,
} from "@whisper-protocol/sdk";
import type { DerivedEncryptionKeypair } from "@whisper-protocol/wallet-derived-keys";
import { whisper, PACKAGE_ID, REGISTRY_ID } from "../whisper/client";
import { suiClient } from "../whisper/client";
import type { ActiveAccount, DemoMode, TxExecutor } from "../whisper/session";
import { RawId } from "./RawId";
import { formatMist } from "../whisper/gas";

interface Props {
  registry: RegistryEntry[];
  keys: DerivedEncryptionKeypair | null;
  account: ActiveAccount | null;
  mode: DemoMode;
  txExecutor: TxExecutor | null;
}

interface GasInfo {
  computationMist: bigint;
  storageMist: bigint;
  rebateMist: bigint;
  netMist: bigint;
}

interface Receipt {
  txDigest: string;
  envelopeId: string | null;
  formatVersion: number;
  recipients: Array<{ address: string; keyId: string; keyVersion: number }>;
  ephPubkeyHex: string;
  payloadNonceHex: string;
  ciphertextHex: string;
  ciphertextBytes: number;
  plaintextBytes: number;
  schema: string;
  scheme: string;
  senderAddress: string;
  package: string;
  registry: string;
  module: string;
  function: string;
  gas: GasInfo | null;
}

function gasFromEffects(summary: {
  computationCost?: string;
  storageCost?: string;
  storageRebate?: string;
} | undefined): GasInfo | null {
  if (!summary) return null;
  const computation = BigInt(summary.computationCost ?? "0");
  const storage = BigInt(summary.storageCost ?? "0");
  const rebate = BigInt(summary.storageRebate ?? "0");
  return {
    computationMist: computation,
    storageMist: storage,
    rebateMist: rebate,
    netMist: computation + storage - rebate,
  };
}

export function Compose({ registry, keys, account, mode, txExecutor }: Props) {
  const [recipientDraft, setRecipientDraft] = useState("");
  const [recipients, setRecipients] = useState<string[]>([]);
  const [text, setText] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [receipt, setReceipt] = useState<Receipt | null>(null);

  const draftLooksLikeAddress = recipientDraft.startsWith("0x") && recipientDraft.length >= 4;
  const draftEntry = useMemo<RegistryEntry | null>(() => {
    if (!draftLooksLikeAddress) return null;
    const norm = normalizeAddress(recipientDraft);
    return registry.find((e) => e.account === norm) ?? null;
  }, [recipientDraft, draftLooksLikeAddress, registry]);

  const draftIsOwn = useMemo(() => {
    if (!account || !recipientDraft) return false;
    return normalizeAddress(account.address) === normalizeAddress(recipientDraft);
  }, [account, recipientDraft]);

  const draftIsDuplicate = useMemo(() => {
    if (!draftLooksLikeAddress) return false;
    const norm = normalizeAddress(recipientDraft);
    return recipients.some((r) => normalizeAddress(r) === norm);
  }, [recipientDraft, draftLooksLikeAddress, recipients]);

  const recipientEntries = useMemo<Array<{ address: string; entry: RegistryEntry | null }>>(
    () =>
      recipients.map((r) => {
        const norm = normalizeAddress(r);
        return {
          address: r,
          entry: registry.find((e) => e.account === norm) ?? null,
        };
      }),
    [recipients, registry],
  );
  const allRecipientsRegistered = recipientEntries.every((r) => r.entry !== null);
  const isMulti = recipients.length > 1;
  const canAddRecipient =
    draftLooksLikeAddress && !!draftEntry && !draftIsOwn && !draftIsDuplicate && recipients.length < MAX_RECIPIENTS;

  function commitRecipient() {
    if (!canAddRecipient) return;
    setRecipients((prev) => [...prev, recipientDraft]);
    setRecipientDraft("");
  }

  function removeRecipient(addr: string) {
    setRecipients((prev) => prev.filter((r) => r !== addr));
  }

  if (!account) {
    return (
      <div className="window compose-window">
        <div className="window-header">
          <span>COMPOSE · LOCKED</span>
          <span>CONNECT WALLET</span>
        </div>
        <div className="window-body">
          <div className="feed-empty" style={{ padding: "1rem 1ch" }}>
            {mode === "wallet"
              ? "connect a sui wallet (top-right) to send a secret on-chain."
              : "configure the dev signer to send a secret on-chain."}
          </div>
        </div>
      </div>
    );
  }

  if (!keys) {
    return (
      <div className="window compose-window">
        <div className="window-header">
          <span>COMPOSE · KEYS NOT DERIVED</span>
          <span>SIGN TO UNLOCK</span>
        </div>
        <div className="window-body">
          <div className="feed-empty" style={{ padding: "1rem 1ch" }}>
            you need to derive your encryption keypair first. sign the canonical
            message in the bar above.
          </div>
        </div>
      </div>
    );
  }

  async function send(e: React.FormEvent) {
    e.preventDefault();
    if (!account || !keys) return;
    if (recipients.length === 0) {
      setErr("add at least one recipient.");
      return;
    }
    if (!allRecipientsRegistered) {
      setErr("at least one recipient has no registry entry. ask them to register first.");
      return;
    }
    if (!text.trim()) {
      setErr("plaintext is empty.");
      return;
    }
    setBusy(true);
    setErr(null);
    setReceipt(null);

    try {
      if (!txExecutor) throw new Error("no transaction signer available");

      const prepared = await whisper.prepareSendV5({
        senderAddress: account.address,
        recipientAddresses: recipients,
        plaintext: text,
      });
      const result = await txExecutor(prepared.tx);
      const full: SuiTransactionBlockResponse = await suiClient.waitForTransaction({
        digest: result.digest,
        options: { showObjectChanges: true, showEffects: true },
      });
      const execStatus = full.effects?.status;
      if (!execStatus || execStatus.status !== "success") {
        const code = execStatus?.status ?? "unknown";
        const errText = execStatus?.error;
        throw new Error(`tx failed (${code})${errText ? `: ${errText}` : ""}`);
      }

      let envelopeId: string | null = null;
      const target = `${PACKAGE_ID}::${MODULE_ENVELOPES}::Envelope`;
      for (const change of full.objectChanges ?? []) {
        if (change.type === "created" && change.objectType === target) {
          envelopeId = change.objectId;
          break;
        }
      }

      setReceipt({
        txDigest: full.digest,
        envelopeId,
        formatVersion: prepared.formatVersion,
        recipients: prepared.recipients.map((r: RegistryEntry) => ({
          address: r.account,
          keyId: r.currentKeyId,
          keyVersion: r.keyVersion,
        })),
        ephPubkeyHex: bytesToHex(prepared.payload.ephPubkey),
        payloadNonceHex: bytesToHex(prepared.payload.payloadNonce),
        ciphertextHex: bytesToHex(prepared.payload.ciphertext),
        ciphertextBytes: prepared.payload.ciphertext.length,
        plaintextBytes: new TextEncoder().encode(text).length,
        schema: SCHEMA_TEXT_SECRET_V1,
        scheme: prepared.payload.encryptionScheme,
        senderAddress: account.address,
        package: PACKAGE_ID,
        registry: REGISTRY_ID,
        module: MODULE_ENVELOPES,
        function: "post_envelope",
        gas: gasFromEffects(full.effects?.gasUsed),
      });
      setText("");
      setRecipients([]);
    } catch (e2) {
      setErr(e2 instanceof Error ? e2.message : String(e2));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="window compose-window">
      <div className="window-header">
        <span>
          COMPOSE · AS <RawId value={account.address} kind="address" />
        </span>
        <span>POST_ENVELOPE</span>
      </div>
      <div className="window-body">
        <form className="compose" onSubmit={send}>
          <label htmlFor="compose-recipient">to</label>
          <div className="recipient-input-row">
            {recipientEntries.map((r) => (
              <span
                key={r.address}
                className={`recipient-chip${r.entry === null ? " recipient-chip-error" : ""}`}
              >
                <RawId value={r.address} kind="address" />
                {r.entry !== null && (
                  <span className="recipient-chip-meta">v{r.entry.keyVersion}</span>
                )}
                <button
                  type="button"
                  className="recipient-chip-remove"
                  aria-label={`remove recipient ${r.address}`}
                  onClick={() => removeRecipient(r.address)}
                  disabled={busy}
                >
                  ×
                </button>
              </span>
            ))}
            <input
              id="compose-recipient"
              type="text"
              placeholder={
                recipients.length === 0
                  ? "0x… recipient sui address"
                  : recipients.length < MAX_RECIPIENTS
                    ? "+ add another recipient"
                    : `max ${MAX_RECIPIENTS} recipients`
              }
              value={recipientDraft}
              onChange={(e) => setRecipientDraft(e.target.value.trim())}
              onKeyDown={(e) => {
                if (e.key === "Enter" || e.key === ",") {
                  e.preventDefault();
                  commitRecipient();
                }
                if (e.key === "Backspace" && recipientDraft === "" && recipients.length > 0) {
                  removeRecipient(recipients[recipients.length - 1]!);
                }
              }}
              onBlur={() => {
                if (canAddRecipient) commitRecipient();
              }}
              disabled={busy || recipients.length >= MAX_RECIPIENTS}
              spellCheck={false}
              style={{ minWidth: "30ch", flex: 1 }}
            />
          </div>
          <label htmlFor="compose-text" className="sr-only">
            secret
          </label>
          <input
            id="compose-text"
            type="text"
            placeholder="plaintext secret (encrypted client-side before posting)"
            value={text}
            onChange={(e) => setText(e.target.value)}
            disabled={busy}
            maxLength={500}
          />
          <button
            type="submit"
            disabled={busy || !text.trim() || recipients.length === 0 || !allRecipientsRegistered}
          >
            {busy
              ? "sending…"
              : isMulti
                ? `send to ${recipients.length}`
                : "send"}
          </button>

          <div className="compose-status">
            {recipients.length === 0 && !recipientDraft ? (
              <>enter recipient addresses; press enter or comma to add each one.</>
            ) : recipients.length === 0 && recipientDraft && !draftEntry && draftLooksLikeAddress ? (
              <span className="compose-status error">
                no registry entry for this address. ask them to register first.
              </span>
            ) : recipients.length === 0 && draftIsOwn ? (
              <span className="compose-status error">
                cannot send to your own address.
              </span>
            ) : recipients.length === 0 && draftEntry ? (
              <>
                press enter to add <RawId value={draftEntry.account} kind="address" />.
              </>
            ) : recipientDraft && draftIsOwn ? (
              <span className="compose-status error">cannot add your own address.</span>
            ) : recipientDraft && draftIsDuplicate ? (
              <span className="compose-status error">recipient already in the list.</span>
            ) : recipientDraft && draftLooksLikeAddress && !draftEntry ? (
              <span className="compose-status error">
                no registry entry for this address. ask them to register first.
              </span>
            ) : recipientDraft && draftEntry ? (
              <>
                press enter to add <RawId value={draftEntry.account} kind="address" />.
              </>
            ) : isMulti ? (
              <>
                will hybrid-encrypt for {recipients.length} recipients (one ciphertext, {recipients.length}{" "}
                wrapped keys) — fmt v3, suite multi-wrap-v1.
              </>
            ) : (
              <>
                will encrypt to <RawId value={recipientEntries[0]!.address} kind="address" /> ·{" "}
                fmt v2, suite{" "}
                {recipientEntries[0]!.entry?.encryptionScheme}
              </>
            )}
          </div>

          {err && <div className="compose-status error">ERROR · {err}</div>}
        </form>

        {receipt && <ReceiptPanel receipt={receipt} />}
      </div>
    </div>
  );
}

function ReceiptPanel({ receipt }: { receipt: Receipt }) {
  return (
    <div className="receipt">
      <div className="receipt-header">
        <span className="tag tag-decrypted">RECEIPT · ON-CHAIN</span>
        <span style={{ color: "var(--text-faint)" }}>tap any id to copy</span>
      </div>
      <dl className="receipt-grid">
        <dt>tx digest</dt>
        <dd>
          <RawId value={receipt.txDigest} kind="tx" forceRaw />
        </dd>
        <dt>envelope object</dt>
        <dd>
          {receipt.envelopeId ? (
            <RawId value={receipt.envelopeId} kind="envelope" forceRaw />
          ) : (
            <span style={{ color: "var(--text-faint)" }}>not reported in tx response</span>
          )}
        </dd>
        <dt>sender</dt>
        <dd>
          <RawId value={receipt.senderAddress} kind="address" forceRaw />
        </dd>
        <dt>recipients ({receipt.recipients.length})</dt>
        <dd>
          <ul style={{ margin: 0, paddingLeft: "1.5ch" }}>
            {receipt.recipients.map((r) => (
              <li key={r.address}>
                <RawId value={r.address} kind="address" forceRaw /> · key v{r.keyVersion}
              </li>
            ))}
          </ul>
        </dd>
        <dt>move call</dt>
        <dd>
          <RawId value={receipt.package} kind="package" forceRaw />
          ::{receipt.module}::{receipt.function}
        </dd>
        <dt>registry input</dt>
        <dd>
          <RawId value={receipt.registry} kind="registry" forceRaw />
        </dd>
        <dt>format_version</dt>
        <dd>v{receipt.formatVersion}</dd>
        <dt>schema</dt>
        <dd>{receipt.schema}</dd>
        <dt>suite</dt>
        <dd style={{ color: "var(--text-dim)" }}>{receipt.scheme}</dd>
        <dt>plaintext bytes</dt>
        <dd>
          {receipt.plaintextBytes} → {receipt.ciphertextBytes} bytes ciphertext (+16-byte AEAD tag)
        </dd>
        <dt>gas</dt>
        <dd>
          {receipt.gas ? (
            <>
              <strong style={{ color: "var(--brand)", fontWeight: "normal" }}>
                {formatMist(receipt.gas.netMist)}
              </strong>{" "}
              <span style={{ color: "var(--text-faint)" }}>
                = computation {formatMist(receipt.gas.computationMist)} + storage{" "}
                {formatMist(receipt.gas.storageMist)} − rebate{" "}
                {formatMist(receipt.gas.rebateMist)}
              </span>
            </>
          ) : (
            <span style={{ color: "var(--text-faint)" }}>not reported</span>
          )}
        </dd>
        <dt>ephemeral pubkey</dt>
        <dd>
          <code className="receipt-bytes">{receipt.ephPubkeyHex}</code>
        </dd>
        <dt>payload nonce</dt>
        <dd>
          <code className="receipt-bytes">{receipt.payloadNonceHex}</code>
        </dd>
        <dt>ciphertext</dt>
        <dd>
          <code className="receipt-bytes receipt-bytes-wrap">{receipt.ciphertextHex}</code>
        </dd>
      </dl>
    </div>
  );
}
