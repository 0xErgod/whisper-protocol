import { PERSPECTIVES, usePerspective } from "../perspective/context";

export function PerspectiveBar() {
  const { perspective, setPerspective } = usePerspective();
  return (
    <div className="perspective-bar" role="tablist" aria-label="Observer perspective">
      {PERSPECTIVES.map((p) => (
        <button
          key={p.key}
          type="button"
          role="tab"
          aria-pressed={perspective === p.key}
          onClick={() => setPerspective(p.key)}
        >
          {p.label}
          <span className="perspective-label">{p.sub}</span>
        </button>
      ))}
    </div>
  );
}
