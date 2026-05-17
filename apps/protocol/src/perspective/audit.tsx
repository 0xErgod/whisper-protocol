import { createContext, useCallback, useContext, useState } from "react";
import type { ReactNode } from "react";

interface AuditValue {
  rawIds: boolean;
  setRawIds: (v: boolean) => void;
  toggle: () => void;
}

const Ctx = createContext<AuditValue | null>(null);

export function AuditProvider({ children }: { children: ReactNode }) {
  const [rawIds, setRawIds] = useState(false);
  const toggle = useCallback(() => setRawIds((v) => !v), []);
  return <Ctx.Provider value={{ rawIds, setRawIds, toggle }}>{children}</Ctx.Provider>;
}

export function useAudit(): AuditValue {
  const v = useContext(Ctx);
  if (!v) throw new Error("useAudit must be used inside AuditProvider");
  return v;
}
