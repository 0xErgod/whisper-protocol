import { createContext, useContext, useMemo, useState } from "react";
import type { ReactNode } from "react";
import { IDENTITIES } from "../crypto/identities";
import type { Identity, CharacterName } from "../crypto/identities";

export type PerspectiveKey = "observer" | CharacterName;

interface PerspectiveValue {
  perspective: PerspectiveKey;
  setPerspective: (p: PerspectiveKey) => void;
  identity: Identity | null;
}

const Ctx = createContext<PerspectiveValue | null>(null);

export function PerspectiveProvider({ children }: { children: ReactNode }) {
  const [perspective, setPerspective] = useState<PerspectiveKey>("observer");
  const value = useMemo<PerspectiveValue>(() => {
    const identity = perspective === "observer" ? null : IDENTITIES[perspective];
    return { perspective, setPerspective, identity };
  }, [perspective]);
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function usePerspective(): PerspectiveValue {
  const v = useContext(Ctx);
  if (!v) throw new Error("usePerspective must be used inside PerspectiveProvider");
  return v;
}

export const PERSPECTIVES: { key: PerspectiveKey; label: string; sub: string }[] = [
  { key: "observer", label: "OBSERVER", sub: "RANDOM ADDR" },
  { key: "alice", label: "ALICE", sub: "/AS-RECIPIENT" },
  { key: "bob", label: "BOB", sub: "/AS-RECIPIENT" },
  { key: "charlie", label: "CHARLIE", sub: "/AS-RECIPIENT" },
];
