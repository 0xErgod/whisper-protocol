import { useState } from "react";
import { useAudit } from "../perspective/audit";
import { labelForAddress, normalizeAddress, shortAddress } from "../crypto/identities";

type IdKind =
  | "package"
  | "registry"
  | "table"
  | "address"
  | "envelope"
  | "tx"
  | "bytes";

interface Props {
  value: string;
  kind: IdKind;
  // For "address" kind: also resolve to a known character label.
  resolveLabel?: boolean;
  // Force showing the raw value regardless of audit mode.
  forceRaw?: boolean;
  className?: string;
}

const KIND_LABEL: Record<IdKind, string> = {
  package: "package id",
  registry: "registry object id",
  table: "table object id",
  address: "sui address",
  envelope: "envelope object id",
  tx: "tx digest",
  bytes: "bytes",
};

function isHexish(value: string): boolean {
  return /^0x[0-9a-fA-F]+$/.test(value);
}

function friendly(value: string, kind: IdKind, resolveLabel: boolean): string {
  if (!value) return "—";
  if (kind === "address") {
    const addr = normalizeAddress(value);
    return resolveLabel ? labelForAddress(addr) : shortAddress(addr);
  }
  if (isHexish(value)) {
    return shortAddress(value);
  }
  return value.length > 14 ? `${value.slice(0, 8)}…${value.slice(-4)}` : value;
}

export function RawId({ value, kind, resolveLabel = false, forceRaw = false, className }: Props) {
  const { rawIds } = useAudit();
  const [copied, setCopied] = useState(false);
  const display = forceRaw || rawIds ? value : friendly(value, kind, resolveLabel);
  const tooltip = `${KIND_LABEL[kind]}\n${value}\nclick to copy`;
  const onClick = async (e: React.MouseEvent) => {
    e.stopPropagation();
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
      setTimeout(() => setCopied(false), 900);
    } catch {
      // ignore — clipboard may be unavailable in some contexts
    }
  };
  return (
    <span
      className={`raw-id ${rawIds || forceRaw ? "raw-id-full" : "raw-id-short"} ${
        copied ? "raw-id-copied" : ""
      } ${className ?? ""}`}
      title={tooltip}
      onClick={onClick}
      data-kind={kind}
      role="button"
      tabIndex={0}
    >
      {copied ? "copied" : display}
    </span>
  );
}
