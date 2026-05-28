// Phase-3 placeholder. The Pedersen-commit flow lives in Phase 4
// (issue #38). The SDK's `commit`, `verifyOpening`, `buildCommitTx`,
// and `buildOpenTx` are all ready; the React form (input field,
// blinding generator, post button) hasn't been rewired yet.

import type { RegistryEntry } from "@whisper-protocol/sdk";
import type { ActiveAccount, DemoMode, TxExecutor } from "../whisper/session";

interface Props {
  account: ActiveAccount | null;
  mode: DemoMode;
  txExecutor: TxExecutor | null;
  registry: RegistryEntry[];
}

export function Commit(_props: Props) {
  return (
    <div className="window">
      <div className="window-header">
        <span>COMMIT SECRET</span>
        <span>phase-4 wiring pending</span>
      </div>
      <div className="window-body">
        <p style={{ color: "var(--text-dim)" }}>
          The Pedersen commit + open flow is being rewritten in Phase 4 of the
          ZK-friendly stack migration (issue #38). The SDK exposes{" "}
          <code>commit</code>, <code>verifyOpening</code>,{" "}
          <code>buildCommitTx</code>, and <code>buildOpenTx</code> against the new
          on-chain shape (vector Pedersen commitments with encoding-id binding),
          but the React form hasn't been rewired yet.
        </p>
      </div>
    </div>
  );
}
