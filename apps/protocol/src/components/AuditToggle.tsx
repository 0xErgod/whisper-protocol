import { useAudit } from "../perspective/audit";

export function AuditToggle() {
  const { rawIds, toggle } = useAudit();
  return (
    <button
      type="button"
      className="audit-toggle"
      aria-pressed={rawIds}
      onClick={toggle}
      title={
        rawIds
          ? "audit mode ON — every on-chain id is shown in full. click to switch back to friendly labels."
          : "audit mode OFF — addresses and object ids are abbreviated. click any id to copy its full value, or toggle this to expand them all."
      }
    >
      AUDIT IDs · {rawIds ? "ON" : "OFF"}
    </button>
  );
}
