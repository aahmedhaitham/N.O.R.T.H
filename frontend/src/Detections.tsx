import { useEffect, useRef, useState } from 'react';
import { FindingEvidence } from './LocalFindings';
import { pollVisible } from './pollVisible';

type Coverage = 'covered' | 'partly' | 'blind';
type Requirement = { id: string; state: string; fix: string };
type Rule = {
  id: string; title: string; severity: string; enabled: boolean; attack: string[];
  coverage: Coverage; requires: Requirement[];
};
type Catalog = { rules: Rule[]; techniques: Record<string, Coverage> };
type TestResult = { evaluated_events: number; timed_out_rule_ids: string[]; matches: { evidence_ids: string[] }[] };

const coverageLabels = { covered: 'Covered', partly: 'Partly covered', blind: 'Blind' };
const techniqueId = (tag: string) => tag.replace(/^attack\./, '').toUpperCase();

async function readCatalog(options?: RequestInit) {
  const response = await fetch('/api/local/rules', { cache: 'no-store', ...options });
  const body = await response.json();
  if (!response.ok) throw new Error(body.detail || 'The local rule catalog is unavailable.');
  return body;
}

function useCatalog() {
  const [catalog, setCatalog] = useState<Catalog>();
  const [failed, setFailed] = useState(false);
  const [revision, setRevision] = useState(0);
  useEffect(() => {
    const abort = new AbortController();
    const stop = pollVisible(async () => {
      try {
        const list: Catalog = await readCatalog({ signal: abort.signal });
        if (!abort.signal.aborted) { setCatalog(list); setFailed(false); }
      } catch {
        if (!abort.signal.aborted) setFailed(true);
      }
    }, 30_000);
    return () => { abort.abort(); stop(); };
  }, [revision]);
  return { catalog, failed, reload: () => setRevision((current) => current + 1) };
}

function CoverageCounts({ catalog }: { catalog: Catalog }) {
  const levels = Object.values(catalog.techniques);
  return <ul className="finding-tags" aria-label="ATT&CK coverage totals">
    {(Object.keys(coverageLabels) as Coverage[]).map((status) =>
      <li key={status}><strong>{levels.filter((level) => level === status).length}</strong> {coverageLabels[status]}</li>)}
  </ul>;
}

export function LocalCoverage({ open }: { open: () => void }) {
  const { catalog, failed } = useCatalog();
  return <section>
    <h3>ATT&CK coverage</h3>
    {catalog && <CoverageCounts catalog={catalog} />}
    {failed ? <p role="status">Coverage could not refresh.</p> :
      !catalog && <p className="reference">Checking collector sources…</p>}
    {catalog && <p className="reference">Coverage uses recent source checks and event types observed on this computer.</p>}
    <button type="button" onClick={open}>Open Detections</button>
  </section>;
}

export function Detections() {
  const { catalog, failed, reload } = useCatalog();
  const [query, setQuery] = useState('');
  const [busy, setBusy] = useState('');
  const [message, setMessage] = useState('');
  const [result, setResult] = useState<{ id: string; test: TestResult }>();
  const [importFile, setImportFile] = useState<File>();
  const fileInput = useRef<HTMLInputElement>(null);

  async function submit(action: 'toggle' | 'test' | 'import', rule?: Rule) {
    setBusy(rule?.id ?? 'import');
    setMessage('');
    try {
      let command: Record<string, unknown> = { action, id: rule?.id, enabled: !rule?.enabled };
      if (action === 'import') {
        if (!importFile || importFile.size > 128_000) throw new Error('Choose a YAML file smaller than 128 KB.');
        command = { action, yaml: await importFile.text() };
      }
      const response = await readCatalog({
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(command),
      });
      if (action === 'test' && rule) setResult({ id: rule.id, test: response });
      else {
        if (action === 'import') {
          setMessage(`Imported ${response.imported} rule(s). Enable the rules you want to run automatically.`);
          setImportFile(undefined);
          if (fileInput.current) fileInput.current.value = '';
        } else if (rule) {
          setMessage(`${rule.title} ${response.enabled ? 'enabled' : 'disabled'}.`);
        }
        reload();
      }
    } catch (error) {
      setMessage(error instanceof Error ? error.message : 'The request failed.');
    } finally {
      setBusy('');
    }
  }

  const search = query.trim().toLowerCase();
  const rules = catalog?.rules.filter((rule) =>
    [rule.id, rule.title, ...rule.attack].some((value) => value.toLowerCase().includes(search)));
  return <main className="dashboard">
    <header className="dashboard-heading"><h1>Detections</h1></header>
    <section className="panel">
      <h2>ATT&CK coverage matrix</h2>
      {catalog && <>
        <CoverageCounts catalog={catalog} />
        <div className="coverage-matrix">
          {(Object.keys(coverageLabels) as Coverage[]).map((status) => <div key={status}>
            <h3>{coverageLabels[status]}</h3>
            <div className="finding-tags">{Object.entries(catalog.techniques).filter(([, level]) => level === status).map(([tag]) =>
              <button type="button" key={tag} aria-pressed={query === techniqueId(tag)}
                onClick={() => setQuery(query === techniqueId(tag) ? '' : techniqueId(tag))}>{techniqueId(tag)}</button>)}</div>
          </div>)}
        </div>
      </>}
      {failed && <p role="status">The local rule catalog could not refresh.</p>}
      {!catalog && !failed && <p>Loading detection rules…</p>}
    </section>
    <section className="panel">
      <h2>Rules</h2>
      <p className="reference">Enable rules to generate new findings automatically. Testing previews matches against up to 100 stored events.</p>
      <div className="finding-actions">
        <label>Find a rule <input type="search" value={query} onChange={(event) => setQuery(event.target.value)} /></label>
        <label>Custom YAML <input ref={fileInput} type="file" accept=".yaml,.yml"
          onChange={(event) => setImportFile(event.target.files?.[0])} /></label>
        <button type="button" disabled={!catalog || !importFile || !!busy}
          onClick={() => void submit('import')}>Import rules</button>
      </div>
      {message && <p role="status">{message}</p>}
      {rules?.length === 0 && <p>No rules match.</p>}
      {rules?.map((rule) => <details className="local-finding" key={rule.id}>
        <summary><strong>{rule.title}</strong> <span className="severity-label" data-severity={rule.severity}>{rule.severity}</span>
          {' · '}{rule.enabled ? coverageLabels[rule.coverage] : 'Disabled'}</summary>
        <ul>{rule.requires.map((need) => <li key={need.id}><code>{need.id}</code> · {need.state}
          {need.state !== 'Observed' && <details><summary>How to fix</summary><p>{need.fix}</p></details>}</li>)}</ul>
        <div className="finding-actions">
          <button type="button" disabled={!!busy} onClick={() => void submit('toggle', rule)}>{rule.enabled ? 'Disable' : 'Enable'}</button>
          <button type="button" disabled={!!busy} onClick={() => void submit('test', rule)}>Test against stored events</button>
          {busy === rule.id && <span role="status">Working…</span>}
        </div>
        {result?.id === rule.id && <div role="status">
          <p>{result.test.timed_out_rule_ids.length ? 'The rule reached its evaluation time limit.' :
            `${result.test.matches.length ? 'Matched' : 'No match in'} ${result.test.matches.length ?
              result.test.matches.flatMap((match) => match.evidence_ids).length + ' evidence events out of ' : ''}${result.test.evaluated_events} stored events.`}</p>
          {result.test.matches.flatMap((match) => match.evidence_ids).map((id) => <FindingEvidence key={id} id={id} />)}
        </div>}
      </details>)}
    </section>
  </main>;
}
