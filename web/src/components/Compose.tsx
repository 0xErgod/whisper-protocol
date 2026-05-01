import { useMemo, useState } from "react";
import {
  useCurrentAccount,
  useSignAndExecuteTransaction,
} from "@mysten/dapp-kit";
import { bytesToHex } from "@noble/hashes/utils";
import {
  MODULE,
  normalizeAddress,
  type RegistryEntry,
} from "@whisper-protocol/sdk";
import type { DerivedEncryptionKeypair } from "@whisper-protocol/wallet-derived-keys";
import { whisper, PACKAGE_ID, REGISTRY_ID } from "../whisper/client";
import { suiClient } from "../whisper/client";
import { RawId } from "./RawId";
import { formatMist } from "../whisper/gas";

interface Props {
  registry: RegistryEntry[];
  keys: DerivedEncryptionKeypair | null;
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
  recipient: string;
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

export function Compose({ registry, keys }: Props) {
  const account = useCurrentAccount();
  const { mutateAsync: signAndExecute } = useSignAndExecuteTransaction();
  const [recipient, setRecipient] = useState("");
  const [text, setText] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [receipt, setReceipt] = useState<Receipt | null>(null);

  const validRecipientEntry = useMemo<RegistryEntry | null>(() => {
    if (!recipient || !recipient.startsWith("0x")) return null;
    const norm = normalizeAddress(recipient);
    return registry.find((e) => e.account === norm) ?? null;
  }, [recipient, registry]);

  const isOwnAddress = useMemo(() => {
    if (!account || !recipient) return false;
    return normalizeAddress(account.address) === normalizeAddress(recipient);
  }, [account, recipient]);

  if (!account) {
    return (
      <div className="window compose-window">
        <div className="window-header">
          <span>COMPOSE · LOCKED</span>
          <span>CONNECT WALLET</span>
        </div>
        <div className="window-body">
          <div className="feed-empty" style={{ padding: "1rem 1ch" }}>
            connect a sui wallet (top-right) to send a secret on-chain.
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
    if (isOwnAddress) {
      setErr("cannot send to your own address.");
      return;
    }
    if (!validRecipientEntry) {
      setErr(
        `recipient ${normalizeAddress(recipient)} has no registry entry. they must call register_encryption_key first.`,
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
      const prepared = await whisper.prepareSend({
        senderAddress: account.address,
        recipientAddress: recipient,
        plaintext: text,
      });

      const result = await signAndExecute({ transaction: prepared.tx });

      // dapp-kit's default execute path returns digest + raw effects only;
      // pull full effects via the SuiClient for receipt details.
      const full = await suiClient.waitForTransaction({
        digest: result.digest,
        options: { showObjectChanges: true, showEffects: true },
      });

      const status = (full.effects?.status as { status?: string; error?: string } | undefined)
        ?.status ?? "unknown";
      if (status !== "success") {
        const errText = (full.effects?.status as { error?: string } | undefined)?.error;
        throw new Error(`tx failed (${status})${errText ? `: ${errText}` : ""}`);
      }

      let envelopeId: string | null = null;
      const target = `${PACKAGE_ID}::${MODULE}::EncryptedEnvelope`;
      for (const change of full.objectChanges ?? []) {
        if (change.type === "created" && (change as { objectType?: string }).objectType === target) {
          envelopeId = (change as { objectId?: string }).objectId ?? null;
          break;
        }
      }

      setReceipt({
        txDigest: full.digest,
        envelopeId,
        recipient: prepared.recipient.account,
        keyVersion: prepared.keyVersion,
        ephPubkeyHex: bytesToHex(prepared.payload.ephPubkey),
        nonceHex: bytesToHex(prepared.payload.nonce),
        ciphertextHex: bytesToHex(prepared.payload.ciphertext),
        ciphertextBytes: prepared.payload.ciphertext.length,
        plaintextBytes: new TextEncoder().encode(text).length,
        schema: "text_secret_v1",
        scheme: prepared.payload.encryptionScheme,
        senderAddress: account.address,
        package: PACKAGE_ID,
        registry: REGISTRY_ID,
        module: MODULE,
        function: "post_envelope",
        gas: gasFromEffects(full.effects?.gasUsed),
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
          COMPOSE · AS <RawId value={account.address} kind="address" />
        </span>
        <span>POST_ENVELOPE</span>
      </div>
      <div className="window-body">
        <form className="compose" onSubmit={send}>
          <label htmlFor="compose-recipient">to</label>
          <input
            id="compose-recipient"
            type="text"
            placeholder="0x… recipient sui address"
            value={recipient}
            onChange={(e) => setRecipient(e.target.value.trim())}
            disabled={busy}
            spellCheck={false}
            style={{ minWidth: "44ch" }}
          />
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
            disabled={busy || !text.trim() || !validRecipientEntry || isOwnAddress}
          >
            {busy ? "sending…" : "send"}
          </button>

          <div className="compose-status">
            {!recipient ? (
              <>enter a recipient sui address.</>
            ) : isOwnAddress ? (
              <span className="compose-status error">
                cannot send to your own address.
              </span>
            ) : validRecipientEntry ? (
              <>
                will encrypt to <RawId value={validRecipientEntry.account} kind="address" /> ·{" "}
                key v{validRecipientEntry.keyVersion} · scheme {validRecipientEntry.encryptionScheme}
              </>
            ) : (
              <span className="compose-status error">
                no registry entry for this address. ask them to register first.
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
          <RawId value={receipt.senderAddress} kind="address" forceRaw />
        </dd>
        <dt>recipient</dt>
        <dd>
          <RawId value={receipt.recipient} kind="address" forceRaw />
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
        <dt>schema</dt>
        <dd>{receipt.schema}</dd>
        <dt>scheme</dt>
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
