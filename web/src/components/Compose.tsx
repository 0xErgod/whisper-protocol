import { useMemo, useState } from "react";
import { Transaction } from "@mysten/sui/transactions";
import { Ed25519Keypair } from "@mysten/sui/keypairs/ed25519";
import { bytesToHex } from "@noble/hashes/utils";
import { client } from "../sui/client";
import { MODULE, PACKAGE_ID, REGISTRY_ID } from "../sui/config";
import type { RegistryEntry } from "../sui/queries";
import { usePerspective } from "../perspective/context";
import { IDENTITIES, normalizeAddress } from "../crypto/identities";
import type { CharacterName, Identity } from "../crypto/identities";
import { encryptForRecipient } from "../crypto/encrypt";
import { RawId } from "./RawId";
import { formatMist } from "../sui/gas";
import type { GasInfo } from "../sui/queries";

interface Props {
  registry: RegistryEntry[];
}

const CLOCK_ID = "0x6";
const SCHEMA = "text_secret_v1";
const RECIPIENT_OPTIONS: CharacterName[] = ["alice", "bob", "charlie"];

interface Receipt {
  txDigest: string;
  envelopeId: string | null;
  recipient: string;
  recipientLabel: string;
  keyVersion: number;
  ephPubkeyHex: string;
  nonceHex: string;
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

function gasFromEffects(result: unknown): GasInfo | null {
  const summary = (result as { effects?: { gasUsed?: { computationCost?: string; storageCost?: string; storageRebate?: string } } } | undefined)
    ?.effects?.gasUsed;
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

function signerFor(identity: Identity): Ed25519Keypair {
  return Ed25519Keypair.fromSecretKey(identity.ed25519PrivateKey);
}

function findCreatedEnvelope(effects: unknown, packageId: string): string | null {
  // SuiTransactionBlockResponse.objectChanges entries with type=created and matching type.
  const changes = (effects as { objectChanges?: Array<Record<string, unknown>> } | undefined)
    ?.objectChanges;
  if (!changes) return null;
  const target = `${packageId}::${MODULE}::EncryptedEnvelope`;
  for (const change of changes) {
    if (change.type === "created" && change.objectType === target) {
      return String(change.objectId ?? "") || null;
    }
  }
  return null;
}

export function Compose({ registry }: Props) {
  const { perspective, identity } = usePerspective();
  const [recipient, setRecipient] = useState<CharacterName>("bob");
  const [text, setText] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [receipt, setReceipt] = useState<Receipt | null>(null);

  const validRecipients = useMemo(
    () => RECIPIENT_OPTIONS.filter((r) => r !== perspective),
    [perspective],
  );

  // Auto-correct recipient if user changed perspective.
  if (!validRecipients.includes(recipient) && validRecipients.length > 0) {
    setRecipient(validRecipients[0]);
  }

  if (perspective === "observer" || !identity) {
    return (
      <div className="window compose-window">
        <div className="window-header">
          <span>COMPOSE · LOCKED</span>
          <span>SWITCH POV</span>
        </div>
        <div className="window-body">
          <div className="feed-empty" style={{ padding: "1rem 1ch" }}>
            you are in observer mode. switch to alice / bob / charlie above to send a secret on
            their behalf.
          </div>
        </div>
      </div>
    );
  }

  const recipientIdentity = IDENTITIES[recipient];
  const recipientAddrNorm = normalizeAddress(recipientIdentity.suiAddress);
  const recipientEntry = registry.find((e) => e.account === recipientAddrNorm);

  async function send(e: React.FormEvent) {
    e.preventDefault();
    if (!identity) return;
    if (!recipientEntry) {
      setErr(
        `recipient ${recipientIdentity.label} has no key registered yet. run \`cargo run -- register-key ${recipient}\` and retry.`,
      );
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
      const payload = encryptForRecipient(
        identity,
        recipientEntry.encryptionPubkey,
        recipientIdentity.suiAddress,
        text,
      );

      const tx = new Transaction();
      tx.moveCall({
        target: `${PACKAGE_ID}::${MODULE}::post_envelope`,
        arguments: [
          tx.object(REGISTRY_ID),
          tx.pure.address(recipientIdentity.suiAddress),
          tx.pure.vector("u8", []),
          tx.pure.vector("u8", Array.from(new TextEncoder().encode(SCHEMA))),
          tx.pure.u64(BigInt(recipientEntry.keyVersion)),
          tx.pure.vector("u8", Array.from(payload.ephPubkey)),
          tx.pure.vector("u8", Array.from(payload.nonce)),
          tx.pure.vector("u8", Array.from(payload.ciphertext)),
          tx.object(CLOCK_ID),
        ],
      });

      const signer = signerFor(identity);
      tx.setSender(identity.suiAddress);
      const result = await client.signAndExecuteTransaction({
        transaction: tx,
        signer,
        options: { showObjectChanges: true, showEffects: true },
      });

      const status =
        (result.effects?.status as { status?: string; error?: string } | undefined)?.status ??
        "unknown";
      if (status !== "success") {
        const errText = (result.effects?.status as { error?: string } | undefined)?.error;
        throw new Error(`tx failed (${status})${errText ? `: ${errText}` : ""}`);
      }

      const envelopeId = findCreatedEnvelope(result, PACKAGE_ID);
      setReceipt({
        txDigest: result.digest,
        envelopeId,
        recipient: recipientIdentity.suiAddress,
        recipientLabel: recipientIdentity.label,
        keyVersion: recipientEntry.keyVersion,
        ephPubkeyHex: bytesToHex(payload.ephPubkey),
        nonceHex: bytesToHex(payload.nonce),
        ciphertextHex: bytesToHex(payload.ciphertext),
        ciphertextBytes: payload.ciphertext.length,
        plaintextBytes: new TextEncoder().encode(text).length,
        schema: SCHEMA,
        scheme: payload.encryptionScheme,
        senderAddress: identity.suiAddress,
        package: PACKAGE_ID,
        registry: REGISTRY_ID,
        module: MODULE,
        function: "post_envelope",
        gas: gasFromEffects(result),
      });
      setText("");
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
          COMPOSE · AS {identity.label}
        </span>
        <span>POST_ENVELOPE</span>
      </div>
      <div className="window-body">
        <form className="compose" onSubmit={send}>
          <label htmlFor="compose-recipient">to</label>
          <select
            id="compose-recipient"
            value={recipient}
            onChange={(e) => setRecipient(e.target.value as CharacterName)}
            disabled={busy}
          >
            {validRecipients.map((r) => (
              <option key={r} value={r}>
                {IDENTITIES[r].label}
              </option>
            ))}
          </select>
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
          <button type="submit" disabled={busy || !text.trim() || !recipientEntry}>
            {busy ? "sending…" : "send"}
          </button>

          <div className="compose-status">
            {recipientEntry ? (
              <>
                will encrypt to <RawId value={recipientAddrNorm} kind="address" resolveLabel /> ·{" "}
                key v{recipientEntry.keyVersion} · scheme {recipientEntry.encryptionScheme}
              </>
            ) : (
              <span className="compose-status error">
                no registry entry for {recipientIdentity.label}.
              </span>
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
          <RawId value={receipt.senderAddress} kind="address" resolveLabel /> ·{" "}
          <RawId value={receipt.senderAddress} kind="address" forceRaw />
        </dd>
        <dt>recipient</dt>
        <dd>
          {receipt.recipientLabel} · <RawId value={receipt.recipient} kind="address" forceRaw />
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
        <dt>declared key_version</dt>
        <dd>v{receipt.keyVersion} (asserted on-chain against current registry)</dd>
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
        <dt>schema</dt>
        <dd>{receipt.schema}</dd>
        <dt>scheme</dt>
        <dd style={{ color: "var(--text-dim)" }}>{receipt.scheme}</dd>
        <dt>plaintext bytes</dt>
        <dd>
          {receipt.plaintextBytes} → {receipt.ciphertextBytes} bytes ciphertext (+16-byte AEAD tag)
        </dd>
        <dt>ephemeral pubkey</dt>
        <dd>
          <code className="receipt-bytes">{receipt.ephPubkeyHex}</code>
        </dd>
        <dt>nonce</dt>
        <dd>
          <code className="receipt-bytes">{receipt.nonceHex}</code>
        </dd>
        <dt>ciphertext</dt>
        <dd>
          <code className="receipt-bytes receipt-bytes-wrap">{receipt.ciphertextHex}</code>
        </dd>
      </dl>
    </div>
  );
}
