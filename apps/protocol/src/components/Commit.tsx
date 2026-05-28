import { useState } from "react";
import type { SuiTransactionBlockResponse } from "@mysten/sui/client";
import {
  buildCommitTx,
  buildOpenTx,
  cryptoWasm,
  verifyOpening,
  commit as sdkCommit,
  type Opening,
  type RegistryEntry,
} from "@whisper-protocol/sdk";
import { PACKAGE_ID, suiClient } from "../whisper/client";
import type { ActiveAccount, DemoMode, TxExecutor } from "../whisper/session";
import { RawId } from "./RawId";

interface Props {
  account: ActiveAccount | null;
  mode: DemoMode;
  txExecutor: TxExecutor | null;
  registry: RegistryEntry[];
}

interface PendingCommit {
  commitmentObjectId: string;
  commitmentX: string;
  commitmentY: string;
  opening: Opening;
  committed: boolean;
  opened: boolean;
}

/**
 * Fresh blinding scalar as a decimal string. Pedersen hiding requires
 * a uniformly-random blinding per commitment; reusing one across
 * commitments to different streams breaks hiding. 31 random bytes is
 * within the BJJ scalar field, and crypto-wasm reduces mod the
 * subgroup order anyway.
 */
function freshBlinding(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(31));
  let acc = 0n;
  for (const b of bytes) acc = (acc << 8n) | BigInt(b);
  return acc.toString(10);
}

/** Pull the created SecretCommitment object id out of the tx effects. */
function findCommitmentObjectId(full: SuiTransactionBlockResponse): string | null {
  const created = full.effects?.created ?? [];
  // The commitment is the owned object transferred to the author; the
  // only object this PTB creates. Take the first created owned object.
  for (const c of created) {
    const owner = c.owner;
    if (owner && typeof owner === "object" && "AddressOwner" in owner) {
      return c.reference.objectId;
    }
  }
  return created[0]?.reference.objectId ?? null;
}

export function Commit({ account, txExecutor }: Props) {
  const [text, setText] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [pending, setPending] = useState<PendingCommit | null>(null);

  const canCommit = Boolean(account && txExecutor && text.trim().length > 0 && !busy);

  async function postCommit() {
    if (!account || !txExecutor) return;
    setBusy(true);
    setErr(null);
    try {
      const encodingId = cryptoWasm.text_utf8_v1_id();
      const stream = cryptoWasm.text_utf8_v1_encode(new TextEncoder().encode(text));
      const blinding = freshBlinding();
      const result = sdkCommit({ encodingId, stream, blinding });
      console.debug("[commit] built commitment", {
        point: `(${result.commitmentX.slice(0, 8)}…, ${result.commitmentY.slice(0, 8)}…)`,
        encodingId,
        streamLen: stream.length,
      });

      // Self-check: the opening we keep must verify against the point
      // we're about to post. Catches an SDK/encoding bug before gas.
      if (!verifyOpening(result.commitmentX, result.commitmentY, result.opening)) {
        throw new Error("internal: freshly-built opening does not verify against its commitment");
      }

      const tx = buildCommitTx({
        packageId: PACKAGE_ID,
        encodingId,
        commitmentX: result.commitmentX,
        commitmentY: result.commitmentY,
      });
      const exec = await txExecutor(tx);
      const full = await suiClient.waitForTransaction({
        digest: exec.digest,
        options: { showEffects: true },
      });
      const status = full.effects?.status;
      if (!status || status.status !== "success") {
        throw new Error(`commit tx failed (${status?.status ?? "unknown"})${status?.error ? `: ${status.error}` : ""}`);
      }
      const objectId = findCommitmentObjectId(full);
      if (!objectId) throw new Error("commit succeeded but no commitment object id in effects");
      console.info("[commit] posted", { txDigest: full.digest, commitmentObjectId: objectId });

      setPending({
        commitmentObjectId: objectId,
        commitmentX: result.commitmentX,
        commitmentY: result.commitmentY,
        opening: result.opening,
        committed: true,
        opened: false,
      });
      setText("");
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      console.error("[commit] failed", msg);
      setErr(msg);
    } finally {
      setBusy(false);
    }
  }

  async function postOpen() {
    if (!account || !txExecutor || !pending) return;
    setBusy(true);
    setErr(null);
    try {
      const tx = buildOpenTx({
        packageId: PACKAGE_ID,
        commitmentObjectId: pending.commitmentObjectId,
        opening: pending.opening,
      });
      const exec = await txExecutor(tx);
      const full = await suiClient.waitForTransaction({
        digest: exec.digest,
        options: { showEffects: true },
      });
      const status = full.effects?.status;
      if (!status || status.status !== "success") {
        throw new Error(`open tx failed (${status?.status ?? "unknown"})${status?.error ? `: ${status.error}` : ""}`);
      }
      console.info("[commit] opened", { txDigest: full.digest, commitmentObjectId: pending.commitmentObjectId });
      setPending({ ...pending, opened: true });
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      console.error("[commit] open failed", msg);
      setErr(msg);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="window">
      <div className="window-header">
        <span>COMMIT SECRET</span>
        <span>{busy ? "working…" : "pedersen"}</span>
      </div>
      <div className="window-body">
        {!account ? (
          <p style={{ color: "var(--text-faint)" }}>Connect an account to commit.</p>
        ) : (
          <>
            <label className="compose-field">
              <span className="compose-label">SECRET</span>
              <textarea
                value={text}
                placeholder="text to commit — encoded via text-utf8-v1"
                rows={3}
                onChange={(e) => setText(e.target.value)}
                disabled={Boolean(pending && !pending.opened)}
              />
            </label>
            {!pending || pending.opened ? (
              <button type="button" className="compose-send" disabled={!canCommit} onClick={postCommit}>
                {busy ? "committing…" : "post commitment"}
              </button>
            ) : (
              <button type="button" className="compose-send" disabled={busy} onClick={postOpen}>
                {busy ? "opening…" : "reveal (open commitment)"}
              </button>
            )}
          </>
        )}

        {err && (
          <div className="notice" style={{ borderColor: "var(--bad)", color: "var(--bad)", marginTop: "1rem" }}>
            <strong>ERROR ·</strong> {err}
          </div>
        )}

        {pending && (
          <div className="receipt" style={{ marginTop: "1rem" }}>
            <div className="receipt-row">
              <span>commitment</span>
              <RawId value={pending.commitmentObjectId} kind="bytes" />
            </div>
            <div className="receipt-row">
              <span>point</span>
              <span className="mono-trunc">
                ({pending.commitmentX.slice(0, 8)}…, {pending.commitmentY.slice(0, 8)}…)
              </span>
            </div>
            <div className="receipt-row">
              <span>status</span>
              <span style={{ color: pending.opened ? "var(--good)" : "var(--text-dim)" }}>
                {pending.opened ? "opened (revealed on chain)" : "committed (opening held locally)"}
              </span>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
