import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import {
  SuiClientProvider,
  WalletProvider,
} from "@mysten/dapp-kit";
import { App } from "./App";
import { AuditProvider } from "./perspective/audit";
import { ACTIVE_NETWORK, RPC_URL } from "./whisper/client";
import { whisperTheme } from "./whisper/theme";
import "@mysten/dapp-kit/dist/index.css";
import "./styles/tokens.css";
import "./styles/app.css";

const queryClient = new QueryClient();

const networks = {
  [ACTIVE_NETWORK]: { url: RPC_URL },
} as const;

const root = document.getElementById("root");
if (!root) throw new Error("missing #root");

createRoot(root).render(
  <StrictMode>
    <QueryClientProvider client={queryClient}>
      <SuiClientProvider networks={networks} defaultNetwork={ACTIVE_NETWORK}>
        <WalletProvider autoConnect theme={whisperTheme}>
          <AuditProvider>
            <App />
          </AuditProvider>
        </WalletProvider>
      </SuiClientProvider>
    </QueryClientProvider>
  </StrictMode>,
);
