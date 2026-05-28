import { useState } from "react";
import type { DerivedBabyJubKeypair, RegistryEntry } from "@whisper-protocol/sdk";
import type { ActiveAccount, DemoMode, TxExecutor } from "../whisper/session";
import { Commit } from "./Commit";
import { Compose } from "./Compose";

interface Props {
  registry: RegistryEntry[];
  keys: DerivedBabyJubKeypair | null;
  account: ActiveAccount | null;
  mode: DemoMode;
  txExecutor: TxExecutor | null;
}

type Tab = "envelope" | "commitment";

export function ComposeTabs({ registry, keys, account, mode, txExecutor }: Props) {
  const [tab, setTab] = useState<Tab>("envelope");

  return (
    <div>
      <div className="compose-tabs" role="tablist" aria-label="post type">
        <button
          type="button"
          role="tab"
          aria-selected={tab === "envelope"}
          onClick={() => setTab("envelope")}
        >
          envelope
        </button>
        <button
          type="button"
          role="tab"
          aria-selected={tab === "commitment"}
          onClick={() => setTab("commitment")}
        >
          commitment
        </button>
      </div>
      {tab === "envelope" ? (
        <Compose
          registry={registry}
          keys={keys}
          account={account}
          mode={mode}
          txExecutor={txExecutor}
        />
      ) : (
        <Commit
          account={account}
          mode={mode}
          txExecutor={txExecutor}
          registry={registry}
        />
      )}
    </div>
  );
}
