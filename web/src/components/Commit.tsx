import { useState } from "react";
import { bytesToHex } from "@noble/hashes/utils";
import type { SuiTransactionBlockResponse } from "@mysten/sui/client";
import {
  COMMITMENT_DOMAIN_V1,
  HASH_SCHEME_BLAKE2B_256,
  MODULE_COMMITMENTS,
  buildCommitTx,
  createCommitment,
  encodeTextSecret,
} from "@whisper-protocol/sdk";
import { PACKAGE_ID, suiClient } from "../whisper/client";
import type { ActiveAccount, DemoMode, TxExecutor } from "../whisper/session";
import { saveOpening } from "../whisper/openings";
import { RawId } from "./RawId";
import { formatMist } from "../whisper/gas";

interface Props {
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

interface CommitReceipt {
  txDigest: string;
  commitmentObjectId: string | null;
  schema: string;
  hashScheme: string;
  commitmentHex: string;
  saltHex: string;
  plaintextBytes: number;
  authorAddress: string;
  package: string;
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

const DEFAULT_SCHEMA = "asset_location_v1";

export function Commit({ account, mode, txExecutor }: Props) {
  const [schema, setSchema] = useState(DEFAULT_SCHEMA);
  const [text, setText] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [receipt, setReceipt] = useState<CommitReceipt | null>(null);

  if (!account) {
    return (
      <div className="window compose-window">
        <div className="window-header">
          <span>COMMIT · LOCKED</span>
          <span>{mode === "wallet" ? "CONNECT WALLET" : "DEV SIGNER UNAVAILABLE"}</span>
        </div>
        <div className="window-body">
          <div className="feed-empty" style={{ padding: "1rem 1ch" }}>
            {mode === "wallet"
              ? "connect a sui wallet (top-right) to post a commitment."
              : "configure the dev signer to post a commitment."}
          </div>
        </div>
      </div>
    );
  }

  async function send(e: React.FormEvent) {
    e.preventDefault();
    if (!account) return;
    if (!schema.trim()) {
      setErr("schema is required.");
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

      const encoded = encodeTextSecret(text);
      const { commitment, salt } = createCommitment(encoded);
      const tx = buildCommitTx({
        packageId: PACKAGE_ID,
        schema,
        commitment,
      });
      const result = await txExecutor(tx);
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

      let commitmentObjectId: string | null = null;
      const target = `${PACKAGE_ID}::${MODULE_COMMITMENTS}::SecretCommitment`;
      for (const change of full.objectChanges ?? []) {
        if (change.type === "created" && change.objectType === target) {
          commitmentObjectId = change.objectId;
          break;
        }
      }

      // Persist the opening locally so we can reveal later. Without
      // (encodedSecret, salt) the commitment is unrecoverable.
      if (commitmentObjectId) {
        saveOpening(commitmentObjectId, {
          encodedSecret: encoded,
          salt,
          commitment,
          plaintext: text,
        });
      }

      setReceipt({
        txDigest: full.digest,
        commitmentObjectId,
        schema,
        hashScheme: HASH_SCHEME_BLAKE2B_256,
        commitmentHex: bytesToHex(commitment),
        saltHex: bytesToHex(salt),
        plaintextBytes: encoded.length,
        authorAddress: account.address,
        package: PACKAGE_ID,
        module: MODULE_COMMITMENTS,
        function: "commit_secret",
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
          COMMIT · AS <RawId value={account.address} kind="address" />
        </span>
        <span>COMMIT_SECRET</span>
      </div>
      <div className="window-body">
        <form className="compose" onSubmit={send}>
          <label htmlFor="commit-schema">schema</label>
          <input
            id="commit-schema"
            type="text"
            value={schema}
            onChange={(e) => setSchema(e.target.value.trim())}
            disabled={busy}
            spellCheck={false}
            style={{ minWidth: "30ch" }}
          />
          <label htmlFor="commit-text" className="sr-only">
            secret
          </label>
          <input
            id="commit-text"
            type="text"
            placeholder="plaintext secret (hashed locally before posting; opening stored in this browser)"
            value={text}
            onChange={(e) => setText(e.target.value)}
            disabled={busy}
            maxLength={500}
          />
          <button type="submit" disabled={busy || !text.trim() || !schema.trim()}>
            {busy ? "committing…" : "commit"}
          </button>

          <div className="compose-status">
            {!text.trim() ? (
              <>enter a plaintext secret. it will be encoded → salted → hashed locally; only the commitment goes on chain.</>
            ) : (
              <>
                domain <code>{COMMITMENT_DOMAIN_V1}</code> · hash <code>{HASH_SCHEME_BLAKE2B_256}</code>
              </>
            )}
          </div>

          {err && <div className="compose-status error">ERROR · {err}</div>}
        </form>

        {receipt && <CommitReceiptPanel receipt={receipt} />}
      </div>
    </div>
  );
}

function CommitReceiptPanel({ receipt }: { receipt: CommitReceipt }) {
  return (
    <div className="receipt">
      <div className="receipt-header">
        <span className="tag tag-decrypted">RECEIPT · COMMITTED</span>
        <span style={{ color: "var(--text-faint)" }}>tap any id to copy</span>
      </div>
      <dl className="receipt-grid">
        <dt>tx digest</dt>
        <dd>
          <RawId value={receipt.txDigest} kind="tx" forceRaw />
        </dd>
        <dt>commitment object</dt>
        <dd>
          {receipt.commitmentObjectId ? (
            <RawId value={receipt.commitmentObjectId} kind="envelope" forceRaw />
          ) : (
            <span style={{ color: "var(--text-faint)" }}>not reported in tx response</span>
          )}
        </dd>
        <dt>author</dt>
        <dd>
          <RawId value={receipt.authorAddress} kind="address" forceRaw />
        </dd>
        <dt>move call</dt>
        <dd>
          <RawId value={receipt.package} kind="package" forceRaw />
          ::{receipt.module}::{receipt.function}
        </dd>
        <dt>schema</dt>
        <dd>{receipt.schema}</dd>
        <dt>hash scheme</dt>
        <dd>{receipt.hashScheme}</dd>
        <dt>plaintext bytes</dt>
        <dd>{receipt.plaintextBytes}</dd>
        <dt>commitment</dt>
        <dd>
          <code className="receipt-bytes">{receipt.commitmentHex}</code>
        </dd>
        <dt>salt (kept locally — open with this)</dt>
        <dd>
          <code className="receipt-bytes">{receipt.saltHex}</code>
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
      </dl>
    </div>
  );
}
