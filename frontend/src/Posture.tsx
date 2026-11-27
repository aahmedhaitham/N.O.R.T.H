import { useState } from 'react';
import { readJson } from './readJson';

type Check = { id: string; title: string; status: 'pass' | 'fail' | 'unknown'; reason: string };
type Snapshot = { state: string; checks: Check[]; updated_at: string | null };

const labels = { pass: 'Observed', fail: 'Needs a look', unknown: 'Could not check' };

export function Posture() {
  const [snapshot, setSnapshot] = useState<Snapshot>();
  const [running, setRunning] = useState(false);
  const [failed, setFailed] = useState(false);

  async function check() {
    setRunning(true);
    setFailed(false);
    try {
      const result = await readJson<Snapshot>('/api/local/posture', {}, 15_000);
      if (result.state !== 'ready' || !Array.isArray(result.checks)) throw new Error();
      setSnapshot(result);
    } catch {
      setFailed(true);
    } finally {
      setRunning(false);
    }
  }

  return <section className="panel">
    <h2>Windows posture</h2>
    <button type="button" disabled={running} onClick={() => void check()}>
      {running ? 'Checking settings…' : 'Check Windows settings'}
    </button>
    {!snapshot && !failed && <p>Read firewall, Defender and other Windows settings on this PC.</p>}
    {failed && <p role="status">Windows posture could not be read. Try again.</p>}
    {snapshot && <ul>{snapshot.checks.map((item) => <li key={item.id}>
      <strong>{item.title}</strong> · {labels[item.status]}. {item.reason}
    </li>)}</ul>}
  </section>;
}
