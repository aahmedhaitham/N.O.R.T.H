import { feedbackMessages } from './messages';
import { clientMessages } from './messages';
import { DetectionsMessages as strings, formatMessage } from './messages';
import { useEffect, useRef, useState } from 'react';
import { FindingEvidence } from './LocalFindings';
import { pollVisible } from './pollVisible';
import { useAssistant } from './Assistant';
import { readJson } from './readJson';
import tacticData from './attackTactics.json';

type Coverage = 'covered' | 'partly' | 'blind' | 'unchecked';
type Requirement = { id: string; state: string; fix: string };
type Rule = {
  id: string; title: string; severity: string; enabled: boolean; attack: string[];
  coverage: Coverage; requires: Requirement[];
};
type Catalog = { rules: Rule[]; techniques: Record<string, Coverage> };
type TestResult = { evaluated_events: number; timed_out_rule_ids: string[]; matches: { evidence_ids: string[] }[];
  event_ids?: string[];
  trace?: { event_id: string; source_matches: boolean; selections: Record<string, boolean>; condition: boolean };
  noise?: { alerts: number; hours: number; alerts_per_day: number | null };
};

const coverageLabels = { covered: 'Covered', partly: feedbackMessages.partlyCovered, blind: 'Blind', unchecked: 'Unchecked' };
const techniqueId = (tag: string) => tag.replace(/^attack\./, '').toUpperCase();
const tactics: Record<string, string[]> = tacticData;

function useCatalog() {
  const publish = useAssistant()?.publish;
  const [catalog, setCatalog] = useState<Catalog>();
  const [failed, setFailed] = useState(false);
  const [revision, setRevision] = useState(0);
  useEffect(() => {
    if (catalog) publish?.('coverage', catalog.rules.map((rule) => ({
      id: rule.id, label: rule.title, status: rule.coverage,
      detail: rule.requires.map((item) => item.id + ' · ' + item.state).join(', '),
      guidance: rule.requires.filter((item) => item.state !== 'Observed').map((item) => item.fix).join(' '),
      terms: [...rule.attack, ...rule.requires.map((item) => item.id)],
    })));
  }, [catalog, publish]);
  useEffect(() => {
    const abort = new AbortController();
    const stop = pollVisible(async () => {
      try {
        const list = await readJson<Catalog>('/api/local/rules', { signal: abort.signal });
        if (!Array.isArray(list?.rules) || !list.techniques) throw new Error();
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
  return <ul className="finding-tags" aria-label={strings.attCkCoverageTotals}>
    {(Object.keys(coverageLabels) as Coverage[]).map((status) =>
      <li key={status}><strong>{levels.filter((level) => level === status).length}</strong> {coverageLabels[status]}</li>)}
  </ul>;
}

export function LocalCoverage({ open }: { open: () => void }) {
  const { catalog, failed, reload } = useCatalog();
  return <section>
    <h3>{strings.attCkCoverage}</h3>
    {catalog && <CoverageCounts catalog={catalog} />}
    {failed ? <p role="status">{strings.coverageCouldNotRefresh} <button type="button" onClick={reload}>Try again</button></p> :
      !catalog && <p className="reference">{strings.checkingCollectorSources}</p>}
    {catalog && <p className="reference">{strings.coverageUsesRecentSourceChecksAndEvent}</p>}
    <button type="button" onClick={open}>{strings.openDetections}</button>
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

  async function submit(action: 'toggle' | 'test' | 'import', rule?: Rule, eventId?: string) {
    setBusy(rule?.id ?? 'import');
    setMessage('');
    try {
      let command: Record<string, unknown> = { action, id: rule?.id, enabled: !rule?.enabled, event_id: eventId };
      if (action === 'import') {
        if (!importFile || importFile.size > 128_000) throw new Error(clientMessages.chooseAYamlFileSmallerThanKb);
        command = { action, yaml: await importFile.text() };
      }
      const response = await readJson<TestResult & { enabled?: boolean; imported?: number }>('/api/local/rules', {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(command),
      });
      if (action === 'test' && rule) setResult({ id: rule.id, test: response });
      else {
        if (action === 'import') {
          setMessage(formatMessage(strings.imported0RuleSEnableTheRules, response.imported));
          setImportFile(undefined);
          if (fileInput.current) fileInput.current.value = '';
        } else if (rule) {
          setMessage(`${rule.title} ${response.enabled ? 'enabled' : 'disabled'}.`);
        }
        reload();
      }
    } catch {
      setMessage('NORTH couldn’t complete the rule request. Check your input and try again.');
    } finally {
      setBusy('');
    }
  }

  const search = query.trim().toLowerCase();
  const rules = catalog?.rules.filter((rule) =>
    [rule.id, rule.title, ...rule.attack].some((value) => value.toLowerCase().includes(search)));
  const groups = new Map<string, [string, Coverage][]>();
  for (const item of Object.entries(catalog?.techniques ?? {})) {
    for (const tactic of tactics[item[0]]?.length ? tactics[item[0]] : ['Tactic unavailable']) {
      const group = groups.get(tactic) ?? [];
      group.push(item);
      groups.set(tactic, group);
    }
  }
  return <main className="dashboard">
    <header className="dashboard-heading"><h1>{strings.detections}</h1></header>
    <section className="panel">
      <h2>{strings.attCkCoverageMatrix}</h2>
      {catalog && <>
        <CoverageCounts catalog={catalog} />
        <div className="coverage-matrix">
          {[...groups].sort(([a], [b]) => a.localeCompare(b)).map(([tactic, techniques]) => <div key={tactic}>
            <h3>{tactic}</h3>
            <ul className="coverage-techniques">{techniques.map(([tag, status]) => {
              const related = catalog.rules.filter((rule) => rule.attack.includes(tag));
              const reasons = [...new Set(related.flatMap((rule) => rule.enabled ?
                rule.requires.filter((need) => need.state !== 'Observed').map((need) => need.state) : ['Rule disabled']))];
              return <li key={tag}>
              <button type="button" key={tag} aria-pressed={query === techniqueId(tag)}
                onClick={() => {
                  setQuery(query === techniqueId(tag) ? '' : techniqueId(tag));
                  document.getElementById('detection-rule-search')?.focus();
                }}>{techniqueId(tag)} · {coverageLabels[status]}</button>
              {status !== 'covered' && reasons.length > 0 && <small>{reasons.join(' · ')}</small>}
              </li>;
            })}</ul>
          </div>)}
        </div>
      </>}
      {failed && <p role="status">{strings.theLocalRuleCatalogCouldNotRefresh} <button type="button" onClick={reload}>Try again</button></p>}
      {!catalog && !failed && <p>{strings.loadingDetectionRules}</p>}
    </section>
    <section className="panel">
      <h2>{strings.rules}</h2>
      <p className="reference">{strings.enableRulesToGenerateNewFindingsAutomatically}</p>
      <div className="finding-actions">
        <label>{strings.findARule}<input id="detection-rule-search" type="search" value={query} onChange={(event) => setQuery(event.target.value)} /></label>
        <label>{strings.customYaml}<input ref={fileInput} type="file" accept=".yaml,.yml"
          onChange={(event) => setImportFile(event.target.files?.[0])} /></label>
        <button type="button" disabled={!catalog || !importFile || !!busy}
          onClick={() => void submit('import')}>{strings.importRules}</button>
      </div>
      {message && <p role="status">{message}</p>}
      {rules?.length === 0 && <p>{strings.noRulesMatch}</p>}
      {rules?.map((rule) => <details className="local-finding" key={rule.id} id={'assistant-coverage-' + rule.id} tabIndex={-1}>
        <summary><strong>{rule.title}</strong> <span className="severity-label" data-severity={rule.severity}>{rule.severity}</span>
          {' · '}{rule.enabled ? coverageLabels[rule.coverage] : strings.disabled}</summary>
        <ul>{rule.requires.map((need) => <li key={need.id}><code>{need.id}</code> · {need.state}
          {need.state !== 'Observed' && <details><summary>{strings.howToFix}</summary><p>{need.fix}</p></details>}</li>)}</ul>
        <div className="finding-actions">
          <button type="button" disabled={!!busy} onClick={() => void submit('toggle', rule)}>{rule.enabled ? strings.disable : strings.enable}</button>
          <button type="button" disabled={!!busy} onClick={() => void submit('test', rule)}>{strings.testAgainstStoredEvents}</button>
          {busy === rule.id && <span role="status">{strings.working}</span>}
        </div>
        {result?.id === rule.id && <div role="status">
          <p>{result.test.timed_out_rule_ids.length ? strings.theRuleReachedItsEvaluationTimeLimit :
            formatMessage(strings.message012StoredEvents, result.test.matches.length ? 'Matched' : feedbackMessages.noMatchIn, result.test.matches.length ?
              result.test.matches.flatMap((match) => match.evidence_ids).length + feedbackMessages.evidenceEventsOutOf : '', result.test.evaluated_events)}</p>
          {result.test.noise && <p>{result.test.noise.alerts} replay alerts over {result.test.noise.hours.toFixed(2)} hours.
            {result.test.noise.alerts_per_day === null ? ' At least one hour is needed for a daily estimate.' :
              ` Estimated ${result.test.noise.alerts_per_day} alerts per day in this sample.`}</p>}
          {result.test.trace && <div>
            <p>Event trace · {result.test.trace.event_id}</p>
            <ul>
              <li>Source: {result.test.trace.source_matches ? 'matched' : 'did not match'}</li>
              {Object.entries(result.test.trace.selections).map(([name, matched]) =>
                <li key={name}>{name}: {matched ? 'matched' : 'did not match'}</li>)}
              <li>Condition: {result.test.trace.condition ? 'matched' : 'did not match'}</li>
            </ul>
            <details><summary>Choose a replay event</summary>
              <ul>{result.test.event_ids?.map((id) => <li key={id}>
                <button type="button" disabled={!!busy || id === result.test.trace?.event_id}
                  onClick={() => void submit('test', rule, id)}>{id}</button>
              </li>)}</ul>
            </details>
          </div>}
          {result.test.matches.flatMap((match) => match.evidence_ids).map((id) => <FindingEvidence key={id} id={id} />)}
        </div>}
      </details>)}
    </section>
  </main>;
}
