import { useMemo, useState } from "react";
import { bytesToHex } from "@noble/hashes/utils";
import type { SuiTransactionBlockResponse } from "@mysten/sui/client";
import {
  COMMITMENT_DOMAIN_V1,
  HASH_SCHEME_BLAKE2B_256,
  HASH_SCHEME_POSEIDON_BN254_CIRCOMLIB_V1,
  MAX_POSEIDON_SECRET_BYTES,
  MODULE_COMMITMENTS,
  MODULE_ENVELOPES,
  SCHEMA_COMMITMENT_OPENING_V1,
  normalizeAddress,
  prepareCommitWithSelfOpening,
  type RegistryEntry,
} from "@whisper-protocol/sdk";
import { PACKAGE_ID, REGISTRY_ID, suiClient } from "../whisper/client";
import type { ActiveAccount, DemoMode, TxExecutor } from "../whisper/session";
import { RawId } from "./RawId";
import { formatMist } from "../whisper/gas";

interface Props {
  account: ActiveAccount | null;
  mode: DemoMode;
  txExecutor: TxExecutor | null;
  registry: RegistryEntry[];
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
  openingEnvelopeId: string | null;
  schema: string;
  openingSchema: string;
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

export function Commit({ account, mode, txExecutor, registry }: Props) {
  const [schema, setSchema] = useState(DEFAULT_SCHEMA);
  const [hashScheme, setHashScheme] = useState<string>(HASH_SCHEME_BLAKE2B_256);
  const [text, setText] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [receipt, setReceipt] = useState<CommitReceipt | null>(null);

  const isPoseidon = hashScheme === HASH_SCHEME_POSEIDON_BN254_CIRCOMLIB_V1;
  const textByteLen = useMemo(() => new TextEncoder().encode(text).length, [text]);
  const tooLongForPoseidon = isPoseidon && textByteLen > MAX_POSEIDON_SECRET_BYTES;

  const ownEntry = useMemo<RegistryEntry | null>(() => {
    if (!account) return null;
    const norm = normalizeAddress(account.address);
    return registry.find((e) => e.account === norm) ?? null;
  }, [account, registry]);

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

  if (!ownEntry) {
    return (
      <div className="window compose-window">
        <div className="window-header">
          <span>COMMIT · NOT REGISTERED</span>
          <span>REGISTER FIRST</span>
        </div>
        <div className="window-body">
          <div className="feed-empty" style={{ padding: "1rem 1ch" }}>
            commitments self-store their opening as an encrypted envelope addressed to you.
            register your encryption key on chain first (button in the identity bar above).
          </div>
        </div>
      </div>
    );
  }

  async function send(e: React.FormEvent) {
    e.preventDefault();
    if (!account || !ownEntry) return;
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

      const prepared = prepareCommitWithSelfOpening({
        packageId: PACKAGE_ID,
        registryId: REGISTRY_ID,
        authorAddress: account.address,
        authorRegistryEntry: ownEntry,
        schema,
        hashScheme,
        plaintextSecret: text,
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

      // The PTB creates two objects in the same tx: a SecretCommitment
      // and a v5 Envelope (the self-addressed opening).
      let commitmentObjectId: string | null = null;
      let openingEnvelopeId: string | null = null;
      const commitmentType = `${PACKAGE_ID}::${MODULE_COMMITMENTS}::SecretCommitment`;
      const envelopeType = `${PACKAGE_ID}::${MODULE_ENVELOPES}::Envelope`;
      for (const change of full.objectChanges ?? []) {
        if (change.type !== "created") continue;
        if (change.objectType === commitmentType) commitmentObjectId = change.objectId;
        else if (change.objectType === envelopeType) openingEnvelopeId = change.objectId;
      }

      setReceipt({
        txDigest: full.digest,
        commitmentObjectId,
        openingEnvelopeId,
        schema,
        openingSchema: prepared.openingSchema,
        hashScheme,
        commitmentHex: bytesToHex(prepared.commitment),
        saltHex: bytesToHex(prepared.salt),
        plaintextBytes: prepared.encodedSecret.length,
        authorAddress: account.address,
        package: PACKAGE_ID,
        module: MODULE_COMMITMENTS,
        function: "commit_secret + post_envelope (PTB)",
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
          <label htmlFor="commit-hash">hash</label>
          <select
            id="commit-hash"
            value={hashScheme}
            onChange={(e) => setHashScheme(e.target.value)}
            disabled={busy}
          >
            <option value={HASH_SCHEME_BLAKE2B_256}>
              blake2b-256 (fast, native)
            </option>
            <option value={HASH_SCHEME_POSEIDON_BN254_CIRCOMLIB_V1}>
              poseidon-bn254-circomlib-v1 (ZK-friendly)
            </option>
          </select>
          <label htmlFor="commit-text" className="sr-only">
            secret
          </label>
          <input
            id="commit-text"
            type="text"
            placeholder="plaintext secret (hashed locally; opening sealed to you in a self-envelope)"
            value={text}
            onChange={(e) => setText(e.target.value)}
            disabled={busy}
            maxLength={500}
          />
          <button
            type="submit"
            disabled={busy || !text.trim() || !schema.trim() || tooLongForPoseidon}
          >
            {busy ? "committing…" : "commit"}
          </button>

          <div className="compose-status">
            {!text.trim() ? (
              <>
                enter a plaintext secret. it gets encoded → salted → hashed; the commitment hash
                goes public on chain, and the (encoded_secret, salt) opening goes on chain too —
                but inside an encrypted envelope addressed to <strong>you</strong>. one PTB, both
                land or neither.
              </>
            ) : tooLongForPoseidon ? (
              <span className="compose-status error">
                Poseidon commitments are capped at {MAX_POSEIDON_SECRET_BYTES} bytes; this
                plaintext is {textByteLen} bytes. Shorten it or switch to blake2b-256.
              </span>
            ) : (
              <>
                domain <code>{COMMITMENT_DOMAIN_V1}</code> · hash <code>{hashScheme}</code>
                {isPoseidon && <> · {textByteLen} / {MAX_POSEIDON_SECRET_BYTES} bytes</>} ·
                opening schema <code>{SCHEMA_COMMITMENT_OPENING_V1}</code>
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
        <dt>self-opening envelope</dt>
        <dd>
          {receipt.openingEnvelopeId ? (
            <>
              <RawId value={receipt.openingEnvelopeId} kind="envelope" forceRaw />
              <div style={{ marginTop: "0.3rem", color: "var(--text-faint)", fontSize: "0.78rem" }}>
                schema <code>{receipt.openingSchema}</code> · sealed to you on chain — recoverable
                from any device with this wallet.
              </div>
            </>
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
        <dt>salt (also encrypted in the self-envelope)</dt>
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
