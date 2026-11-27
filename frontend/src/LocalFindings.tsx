import { LocalFindingsMessages as strings, formatMessage } from './messages';
import { useEffect, useRef, useState } from 'react';
import { TimeDisplay } from './TimeDisplay';
import { useDisplayMode } from './DisplayMode';
import { Explain, useAssistant } from './Assistant';

type FindingStatus = 'new' | 'reviewed' | 'benign';
type Finding = {
  confidence?: string; rarity?: string;
  id: string; title: string; severity: string; last_seen: string; status: FindingStatus; attack?: string[];
  plain_summary: string; what_to_do: string; evidence_ids: string[];
  rule_id?: string; falsepositives?: string[];
};
export type FindingHealth = { unreviewed: number; severe: boolean; current: boolean };
type Feed = {
  findings: Finding[]; has_more?: boolean; monitor?: 'running' | 'stopped' | 'failed';
  summary?: { unreviewed: number; severe: number };
};
const isSevere = (finding: Finding) => finding.severity === 'critical' || finding.severity === 'high';
const findingRow = (finding: Finding) => ({ id: finding.id, label: finding.title, detail: finding.plain_summary,
  timestamp: finding.last_seen, status: finding.status, guidance: finding.what_to_do,
  score: `Severity: ${finding.severity} · Confidence: ${finding.confidence === "unrated" ? "unknown" : finding.confidence ?? "unknown"} · Baseline rarity: ${finding.rarity ?? "unknown"}`,
  alternative: finding.falsepositives?.[0], terms: [finding.severity, finding.rule_id ?? '', ...(finding.attack ?? [])] });
type Evidence = {
  host: string; timestamp?: string; ts?: string; source?: string;
  process?: string | { path?: string }; destination?: string; target?: string;
  cloud?: { action?: string; region?: string };
  addresses?: string[]; listener?: { address?: string; port?: string };
};

export function FindingEvidence({ id }: { id: string }) {
  const [evidence, setEvidence] = useState<Evidence>();
  const [failed, setFailed] = useState(false);
  const [loading, setLoading] = useState(false);
  async function open() {
    setLoading(true);
    setFailed(false);
    try {
      const response = await fetch('/api/local/evidence/' + encodeURIComponent(id));
      if (!response.ok) throw new Error();
      setEvidence(await response.json());
    } catch {
      setFailed(true);
    } finally {
      setLoading(false);
    }
  }
  if (evidence) {
    const process = typeof evidence.process === 'string' ? evidence.process : evidence.process?.path;
    const endpoint = evidence.listener?.address && evidence.listener.port ?
      evidence.listener.address + ' · port ' + evidence.listener.port : undefined;
    return <p><strong>{evidence.host}</strong> · <TimeDisplay value={evidence.ts ?? evidence.timestamp} />
      {[evidence.source, process, evidence.destination, evidence.target, evidence.cloud?.action, evidence.cloud?.region, endpoint, ...(evidence.addresses ?? [])].filter(Boolean).map((value, index) =>
        <span key={index}> · <code>{value}</code></span>)}</p>;
  }
  return <div><button type="button" disabled={loading} onClick={() => void open()}>
    {loading ? strings.loadingEvidence : formatMessage(strings.openEvidence, id.slice(0, 8))}
  </button>{failed && <p role="status">{strings.thisEvidenceCouldNotBeLoadedIt}</p>}</div>;
}

function FindingRow({ finding, onReviewed }: {
  finding: Finding; onReviewed: (id: string, status: FindingStatus) => void;
}) {
  const [pending, setPending] = useState(false);
  const [failed, setFailed] = useState(false);
  const { mode } = useDisplayMode();

  async function review(status: FindingStatus) {
    setPending(true);
    setFailed(false);
    try {
      const response = await fetch('/api/local/findings/' + encodeURIComponent(finding.id) + '/review', {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ status }),
      });
      if (!response.ok) throw new Error();
      onReviewed(finding.id, status);
    } catch {
      setFailed(true);
    } finally {
      setPending(false);
    }
  }

  return <details className="local-finding" id={'assistant-findings-' + finding.id} tabIndex={-1}>
    <summary>
      <strong>{finding.title}</strong> <span className="severity-label" data-severity={finding.severity}>{finding.severity}</span>
      {' '}<span className="review-status">{finding.status === 'new' ? strings.unreviewed : finding.status}</span>
      {' '}<TimeDisplay value={finding.last_seen} />
    </summary>
    <p>{finding.plain_summary}</p>
    <p>Confidence: {finding.confidence === "correlated" || finding.confidence === "single observation" ? finding.confidence : "unknown"} · Baseline rarity: {finding.rarity ?? "unknown"}</p>
    <p>{finding.what_to_do}</p>
    {!!finding.falsepositives?.length && <p>{finding.falsepositives[0]}</p>}
    {(finding.rule_id || !!finding.attack?.length) && <details open={mode === 'analyst' || undefined}>
      <summary>{strings.technicalDetails}</summary>
      {finding.rule_id && <code>{finding.rule_id}</code>}
      {!!finding.attack?.length && <ul className="finding-tags" aria-label={strings.attCkTechniques}>
        {finding.attack.map((tag) => <li key={tag}><code>{tag.replace(/^attack\./, '').toUpperCase()}</code></li>)}
      </ul>}
    </details>}
    {finding.evidence_ids.map((id) => <FindingEvidence key={id} id={id} />)}
    <Explain area="findings" question="Why am I seeing this alert?" row={findingRow(finding)} />
    <div className="finding-actions">
      {finding.status === 'new' ? <>
        <button type="button" disabled={pending} onClick={() => void review('reviewed')}>{strings.markReviewed}</button>
        <button type="button" disabled={pending} onClick={() => void review('benign')}>{strings.markBenign}</button>
      </> : <button type="button" disabled={pending} onClick={() => void review('new')}>{strings.reopenFinding}</button>}
    </div>
    {failed && <p role="status">{strings.theReviewCouldNotBeSavedTry}</p>}
  </details>;
}

export function LocalFindings({ desktop, onHealth }: { desktop: boolean; onHealth?: (health: FindingHealth) => void }) {
  const publish = useAssistant()?.publish;
  const [feed, setFeed] = useState<Feed>();
  const [unavailable, setUnavailable] = useState(false);
  const [starting, setStarting] = useState(false);
  const [startError, setStartError] = useState(false);
  const [page, setPage] = useState(0);
  const revision = useRef(0);
  useEffect(() => { if (feed) publish?.('findings', feed.findings.map(findingRow)); }, [feed, publish]);

  useEffect(() => {
    if (!onHealth || (!feed && page !== 0)) return;
    const unreviewed = feed?.findings.filter((item) => item.status === 'new') ?? [];
    onHealth({
      unreviewed: feed?.summary?.unreviewed ?? unreviewed.length,
      severe: feed?.summary ? feed.summary.severe > 0 : unreviewed.some(isSevere),
      current: !!feed && !unavailable && (!desktop || feed.monitor === 'running'),
    });
  }, [desktop, feed, onHealth, page, unavailable]);

  useEffect(() => {
    const controller = new AbortController();
    let next: ReturnType<typeof setTimeout>;
    async function refresh() {
      const requested = revision.current;
      try {
        const response = await fetch('/api/local/findings?offset=' + page * 100,
          { signal: controller.signal, cache: 'no-store' });
        if (!response.ok) throw new Error();
        const result = await response.json() as Feed;
        if (!Array.isArray(result.findings)) throw new Error();
        if (!controller.signal.aborted && requested === revision.current) {
          setFeed(result);
          setUnavailable(false);
        }
      } catch {
        if (!controller.signal.aborted) setUnavailable(true);
      } finally {
        if (!controller.signal.aborted) next = setTimeout(refresh, 5000);
      }
    }
    void refresh();
    return () => { controller.abort(); clearTimeout(next); };
  }, [page]);

  async function start() {
    setStarting(true);
    setStartError(false);
    try {
      const response = await fetch('/api/local/findings/monitor', { method: 'POST' });
      if (!response.ok || !(await response.json()).running) throw new Error();
      revision.current++;
      setFeed((previous) => ({ ...previous, findings: previous?.findings ?? [], monitor: 'running' }));
    } catch {
      setStartError(true);
    } finally {
      setStarting(false);
    }
  }

  function onReviewed(id: string, status: FindingStatus) {
    revision.current++;
    setFeed((previous) => {
      const original = previous?.findings.find((finding) => finding.id === id);
      if (!previous || !original) return previous;
      const delta = Number(status === 'new') - Number(original.status === 'new');
      return {
        ...previous, findings: previous.findings.map((finding) => finding.id === id ? { ...finding, status } : finding),
        summary: previous.summary && {
          unreviewed: previous.summary.unreviewed + delta,
          severe: previous.summary.severe + (isSevere(original) ? delta : 0),
        },
      };
    });
  }

  const findings = feed?.findings ?? [];
  const unreviewed = findings.filter((finding) => finding.status === 'new');
  const reviewed = findings.filter((finding) => finding.status !== 'new');
  function goToPage(next: number) {
    revision.current++;
    setFeed(undefined);
    setPage(next);
  }
  return <section aria-labelledby="local-findings-title">
    <h3 id="local-findings-title">{strings.localFindings}</h3>
    {desktop && feed?.monitor === 'running' && <p className="reference">{strings.monitoringThisComputer}</p>}
    {desktop && feed && feed.monitor !== 'running' && <div className="overview-source-row">
      <p>{strings.northCanCheckWindowsEventsAndLocal}</p>
      <button type="button" disabled={starting} onClick={() => void start()}>
        {starting ? strings.starting : feed?.monitor === 'failed' ? strings.restartMonitoring : strings.startMonitoring}
      </button>
    </div>}
    {(startError || feed?.monitor === 'failed') && <p role="status">{strings.theLocalCollectorCouldNotRun}</p>}
    {unavailable && <p role="status">{strings.localFindingsCouldNotRefresh}</p>}
    {!unavailable && !unreviewed.length && <p className="reference">{!feed ? strings.checkingLocalFindings :
      strings.noUnreviewedLocalFindings}</p>}
    {unreviewed.map((finding) => <FindingRow key={finding.id} finding={finding} onReviewed={onReviewed} />)}
    {reviewed.length > 0 && <details className="finding-history">
      <summary>{strings.recentReviewedFindings}{reviewed.length})</summary>
      {reviewed.map((finding) => <FindingRow key={finding.id} finding={finding} onReviewed={onReviewed} />)}
    </details>}
    {(page > 0 || feed?.has_more) && <div className="finding-actions">
      <button type="button" disabled={page === 0} onClick={() => goToPage(page - 1)}>{strings.previousFindings}</button>
      <button type="button" disabled={!feed?.has_more} onClick={() => goToPage(page + 1)}>{strings.moreFindings}</button>
    </div>}
  </section>;
}
