import { ProcessTreeMessages as strings } from './messages';
import { useMemo, useState } from 'react';
import { processTree } from './processLineage';

export function ProcessTree({ evidence, reveal }: {
  evidence: Parameters<typeof processTree>[0]; reveal: (id: string) => void;
}) {
  const [limit, setLimit] = useState(50);
  const { rows, truncated } = useMemo(() => processTree(evidence), [evidence]);
  return <section className="echo-process-tree">
    <h2>{strings.processTree}</h2>
    {rows.length === 0 && <p>{strings.thisCaseHasNoProcessGuidEvidence}</p>}
    {truncated && <p>{strings.showingTheFirst500DistinctProcessesIn}</p>}
    <ul aria-label={strings.observedProcessRelationships}>{rows.slice(0, limit).map((row) =>
      <li key={row.guid} style={{ paddingInlineStart: Math.min(row.depth, 6) * 12 }}>
        <button type="button" onClick={() => reveal(row.evidenceId)} title={row.guid}>
          {row.depth > 0 && <span aria-hidden="true">↳ </span>}{row.label}
        </button>
        {row.depth > 6 && <small>{strings.depth}{row.depth}</small>}
        {row.gap && <small>{row.gap}</small>}
      </li>)}</ul>
    {rows.length > limit && <button type="button" onClick={() => setLimit(limit + 50)}>
      {strings.showMoreProcesses}{Math.min(limit, rows.length)}{strings.of}{rows.length})
    </button>}
  </section>;
}
