import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { App } from "./App";
import { PerspectiveProvider } from "./perspective/context";
import { AuditProvider } from "./perspective/audit";
import "./styles/tokens.css";
import "./styles/app.css";

const root = document.getElementById("root");
if (!root) throw new Error("missing #root");

createRoot(root).render(
  <StrictMode>
    <AuditProvider>
      <PerspectiveProvider>
        <App />
      </PerspectiveProvider>
    </AuditProvider>
  </StrictMode>,
);
