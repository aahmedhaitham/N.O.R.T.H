import { useMemo, useState } from 'react';
import { processTree } from './processLineage';

export function ProcessTree({ evidence, reveal }: {
  evidence: Parameters<typeof processTree>[0]; reveal: (id: string) => void;
}) {
  const [limit, setLimit] = useState(50);
  const { rows, truncated } = useMemo(() => processTree(evidence), [evidence]);
  return <section className="echo-process-tree">
    <h2>Process tree</h2>
    {rows.length === 0 && <p>This case has no process GUID evidence.</p>}
    {truncated && <p>Showing the first 500 distinct processes in this case.</p>}
    <ul aria-label="Observed process relationships">{rows.slice(0, limit).map((row) =>
      <li key={row.guid} style={{ paddingInlineStart: Math.min(row.depth, 6) * 12 }}>
        <button type="button" onClick={() => reveal(row.evidenceId)} title={row.guid}>
          {row.depth > 0 && <span aria-hidden="true">↳ </span>}{row.label}
        </button>
        {row.depth > 6 && <small>Depth {row.depth}</small>}
        {row.gap && <small>{row.gap}</small>}
      </li>)}</ul>
    {rows.length > limit && <button type="button" onClick={() => setLimit(limit + 50)}>
      Show more processes ({Math.min(limit, rows.length)} of {rows.length})
    </button>}
  </section>;
}
