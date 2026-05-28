// Phase-3 placeholder. The full BJJ envelope flow lives in Phase 4
// (issue #38). The React glue that calls suite.seal +
// buildPostEnvelopeTx hasn't been written yet.
//
// Keeping the component's shape and rendering an explanatory banner
// so the dApp still compiles + boots. Tab navigation, registry view,
// and identity bar continue to work.

import type { DerivedBabyJubKeypair, RegistryEntry } from "@whisper-protocol/sdk";
import type { ActiveAccount, DemoMode, TxExecutor } from "../whisper/session";

interface Props {
  registry: RegistryEntry[];
  keys: DerivedBabyJubKeypair | null;
  account: ActiveAccount | null;
  mode: DemoMode;
  txExecutor: TxExecutor | null;
}

export function Compose(_props: Props) {
  return (
    <div className="window">
      <div className="window-header">
        <span>COMPOSE ENVELOPE</span>
        <span>phase-4 wiring pending</span>
      </div>
      <div className="window-body">
        <p style={{ color: "var(--text-dim)" }}>
          The compose-and-send flow is being rewritten in Phase 4 of the ZK-friendly
          stack migration (issue #38). The single-recipient BJJ envelope path lives
          in <code>@whisper-protocol/sdk</code> (<code>seal</code>,{" "}
          <code>buildPostEnvelopeTx</code>) and is exercised by the SDK's round-trip
          test, but the React form, recipient picker, and submit handler haven't been
          rewired yet.
        </p>
      </div>
    </div>
  );
}
