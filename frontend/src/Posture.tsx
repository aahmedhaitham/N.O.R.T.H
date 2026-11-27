import { useEffect, useState } from 'react';
import { pollVisible } from './pollVisible';
import { readJson } from './readJson';

type Check = { id: string; title: string; status: 'pass' | 'fail' | 'unknown'; reason: string; weight: number };
type Drift = { compared_at?: string | null; unavailable?: boolean;
  changes?: { id: string; title: string; before: Check['status']; after: Check['status'] }[] };
type Snapshot = { state: string; checks: Check[]; updated_at: string | null; score: { earned: number; possible: number; unknown: number }; drift?: Drift };

type Details = { state: string; pending_updates?: number | null; recent_defender_detections?: number | null;
  support_end?: string | null; support_reviewed?: string | null; last_update_at?: string | null; last_scan_at?: string | null };

const labels = { pass: 'Observed', fail: 'Needs a look', unknown: 'Could not check' };

export function Posture() {
  const [details, setDetails] = useState<Details>();
  const [snapshot, setSnapshot] = useState<Snapshot>();
  const [running, setRunning] = useState(false);
  const [failed, setFailed] = useState(false);

  const [enabled, setEnabled] = useState(false);
  useEffect(() => {
    if (!enabled) return;
    const controller = new AbortController();
    const stop = pollVisible(async () => {
      setRunning(true);
      setFailed(false);
      const readDetails = readJson<Details>('/api/local/posture/details', { signal: controller.signal }, 15_000)
        .then((value) => { if (!controller.signal.aborted) setDetails(value); })
        .catch(() => { if (!controller.signal.aborted) setDetails({ state: 'unavailable' }); });
      try {
        const result = await readJson<Snapshot>('/api/local/posture', { signal: controller.signal }, 15_000);
        if (result.state !== 'ready' || !Array.isArray(result.checks)) throw new Error();
        if (!controller.signal.aborted) setSnapshot(result);
      } catch {
        if (!controller.signal.aborted) setFailed(true);
      } finally {
        if (!controller.signal.aborted) setRunning(false);
        await readDetails;
      }
    }, 300_000);
    return () => { controller.abort(); stop(); };
  }, [enabled]);

  const [scanPending, setScanPending] = useState(false);
  const [scanMessage, setScanMessage] = useState('');
  async function requestScan() {
    setScanPending(true);
    setScanMessage('');
    try {
      const result = await readJson<{ state: string }>('/api/local/posture/quick-scan', { method: 'POST' }, 180_000);
      setScanMessage(result.state === 'accepted' ? 'Defender accepted the quick-scan request. Check Windows Security for results.'
        : 'Quick-scan request canceled.');
    } catch {
      setScanMessage('NORTH could not confirm the scan request. Check Windows Security before retrying.');
    } finally {
      setScanPending(false);
    }
  }

  return <section className="panel">
    <h2>Windows posture</h2>
    <button type="button" onClick={() => { setRunning(false); setEnabled(!enabled); }}>
      {enabled ? 'Pause posture checks' : 'Start posture checks'}
    </button>
    {' '}<button type="button" disabled={scanPending} onClick={() => void requestScan()}>
      {scanPending ? 'Waiting for Defender…' : 'Request Defender quick scan'}
    </button>
    {scanMessage && <p role="status">{scanMessage}</p>}
    {running && <p role="status">Checking settings…</p>}
    {!snapshot && !failed && <p>Read firewall, Defender and other Windows settings on this PC.</p>}
    {failed && <p role="status">Windows posture could not be read. Try again.</p>}
    {snapshot && <p role="status">
      {snapshot.score.possible ? `Posture score: ${snapshot.score.earned} of ${snapshot.score.possible} available points.` : 'No score available yet.'}
      {' '}{snapshot.score.unknown} checks could not be scored.
    </p>}
    {snapshot?.drift?.unavailable && <p role="status">The previous posture snapshot could not be read.</p>}
    {snapshot?.drift?.compared_at && <details>
      <summary>Changes since the previous check</summary>
      {snapshot.drift.changes?.length ? <ul>{snapshot.drift.changes.map((change) => <li key={change.id}>
        {change.title} · {labels[change.before]} → {labels[change.after]}
      </li>)}</ul> : <p>None of the check results changed.</p>}
    </details>}
    {details && <details>
      <summary>Windows Update and Defender details</summary>
      <ul>
        <li>Windows servicing end date: {details.support_end
          ? `${details.support_end} (reference checked ${details.support_reviewed})` : 'Could not check'}</li>
        <li>Pending updates in the local cache: {details.pending_updates ?? 'Could not check'}</li>
        <li>Last successful update in recent history: {details.last_update_at
          ? new Date(details.last_update_at).toLocaleString() : 'Could not check'}</li>
        <li>Last Defender scan: {details.last_scan_at
          ? new Date(details.last_scan_at).toLocaleString() : 'Could not check'}</li>
        <li>Defender detection events in the last week: {details.recent_defender_detections === 50
          ? '50 or more' : details.recent_defender_detections ?? 'Could not check'}</li>
      </ul>
      <p>Cached update results depend on the most recent Windows Update scan.</p>
    </details>}
    {snapshot && <ul>{snapshot.checks.map((item) => <li key={item.id}>
      <strong>{item.title}</strong> · {labels[item.status]}. {item.reason}{item.status === 'fail' && ` · ${item.weight} points missed`}
    </li>)}</ul>}
  </section>;
}
