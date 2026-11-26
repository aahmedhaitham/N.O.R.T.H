import { useEffect, useRef, useState } from 'react';
import { TimeDisplay } from './TimeDisplay';
import { useDisplayMode } from './DisplayMode';

type FindingStatus = 'new' | 'reviewed' | 'benign';
type Finding = {
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
type Evidence = {
  host: string; timestamp?: string; ts?: string; source?: string;
  process?: string | { path?: string }; destination?: string; target?: string;
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
      {[evidence.source, process, evidence.destination, evidence.target, endpoint, ...(evidence.addresses ?? [])].filter(Boolean).map((value, index) =>
        <span key={index}> · <code>{value}</code></span>)}</p>;
  }
  return <div><button type="button" disabled={loading} onClick={() => void open()}>
    {loading ? 'Loading evidence…' : 'Open evidence ' + id.slice(0, 8)}
  </button>{failed && <p role="status">This evidence could not be loaded. It may have expired.</p>}</div>;
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

  return <details className="local-finding">
    <summary>
      <strong>{finding.title}</strong> <span className="severity-label" data-severity={finding.severity}>{finding.severity}</span>
      {' '}<span className="review-status">{finding.status === 'new' ? 'Unreviewed' : finding.status}</span>
      {' '}<TimeDisplay value={finding.last_seen} />
    </summary>
    <p>{finding.plain_summary}</p>
    <p>{finding.what_to_do}</p>
    {!!finding.falsepositives?.length && <p>{finding.falsepositives[0]}</p>}
    {(finding.rule_id || !!finding.attack?.length) && <details open={mode === 'analyst' || undefined}>
      <summary>Technical details</summary>
      {finding.rule_id && <code>{finding.rule_id}</code>}
      {!!finding.attack?.length && <ul className="finding-tags" aria-label="ATT&CK techniques">
        {finding.attack.map((tag) => <li key={tag}><code>{tag.replace(/^attack\./, '').toUpperCase()}</code></li>)}
      </ul>}
    </details>}
    {finding.evidence_ids.map((id) => <FindingEvidence key={id} id={id} />)}
    <div className="finding-actions">
      {finding.status === 'new' ? <>
        <button type="button" disabled={pending} onClick={() => void review('reviewed')}>Mark reviewed</button>
        <button type="button" disabled={pending} onClick={() => void review('benign')}>Mark benign</button>
      </> : <button type="button" disabled={pending} onClick={() => void review('new')}>Reopen finding</button>}
    </div>
    {failed && <p role="status">The review could not be saved. Try again.</p>}
  </details>;
}

export function LocalFindings({ desktop, onHealth }: { desktop: boolean; onHealth?: (health: FindingHealth) => void }) {
  const [feed, setFeed] = useState<Feed>();
  const [unavailable, setUnavailable] = useState(false);
  const [starting, setStarting] = useState(false);
  const [startError, setStartError] = useState(false);
  const [page, setPage] = useState(0);
  const revision = useRef(0);

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
    <h3 id="local-findings-title">Local findings</h3>
    {desktop && feed?.monitor === 'running' && <p className="reference">Monitoring this computer</p>}
    {desktop && feed && feed.monitor !== 'running' && <div className="overview-source-row">
      <p>NORTH can check Windows events and local network observations while this app runs.</p>
      <button type="button" disabled={starting} onClick={() => void start()}>
        {starting ? 'Starting…' : feed?.monitor === 'failed' ? 'Restart monitoring' : 'Start monitoring'}
      </button>
    </div>}
    {(startError || feed?.monitor === 'failed') && <p role="status">The local collector could not run.</p>}
    {unavailable && <p role="status">Local findings could not refresh.</p>}
    {!unavailable && !unreviewed.length && <p className="reference">{!feed ? 'Checking local findings…' :
      'No unreviewed local findings.'}</p>}
    {unreviewed.map((finding) => <FindingRow key={finding.id} finding={finding} onReviewed={onReviewed} />)}
    {reviewed.length > 0 && <details className="finding-history">
      <summary>Recent reviewed findings ({reviewed.length})</summary>
      {reviewed.map((finding) => <FindingRow key={finding.id} finding={finding} onReviewed={onReviewed} />)}
    </details>}
    {(page > 0 || feed?.has_more) && <div className="finding-actions">
      <button type="button" disabled={page === 0} onClick={() => goToPage(page - 1)}>Previous findings</button>
      <button type="button" disabled={!feed?.has_more} onClick={() => goToPage(page + 1)}>More findings</button>
    </div>}
  </section>;
}
