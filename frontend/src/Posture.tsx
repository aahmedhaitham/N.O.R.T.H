import { useEffect, useState } from 'react';
import { pollVisible } from './pollVisible';
import { readJson } from './readJson';

type Check = { id: string; title: string; status: 'pass' | 'fail' | 'unknown'; reason: string; weight: number };
type Drift = { compared_at?: string | null; unavailable?: boolean;
  changes?: { id: string; title: string; before: Check['status']; after: Check['status'] }[] };
type Snapshot = { state: string; checks: Check[]; updated_at: string | null; score: { earned: number; possible: number; unknown: number }; drift?: Drift };

const labels = { pass: 'Observed', fail: 'Needs a look', unknown: 'Could not check' };

export function Posture() {
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
      try {
        const result = await readJson<Snapshot>('/api/local/posture', { signal: controller.signal }, 15_000);
        if (result.state !== 'ready' || !Array.isArray(result.checks)) throw new Error();
        if (!controller.signal.aborted) setSnapshot(result);
      } catch {
        if (!controller.signal.aborted) setFailed(true);
      } finally {
        if (!controller.signal.aborted) setRunning(false);
      }
    }, 300_000);
    return () => { controller.abort(); stop(); };
  }, [enabled]);

  return <section className="panel">
    <h2>Windows posture</h2>
    <button type="button" onClick={() => { setRunning(false); setEnabled(!enabled); }}>
      {enabled ? 'Pause posture checks' : 'Start posture checks'}
    </button>
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
    {snapshot && <ul>{snapshot.checks.map((item) => <li key={item.id}>
      <strong>{item.title}</strong> · {labels[item.status]}. {item.reason}{item.status === 'fail' && ` · ${item.weight} points missed`}
    </li>)}</ul>}
  </section>;
}
