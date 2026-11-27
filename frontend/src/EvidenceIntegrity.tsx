import { useState } from 'react';
import { readJson } from './readJson';

type Verification = { state: string; records?: number; start?: string; event_id?: string | null; sequence?: number;
  checkpoint?: Record<string, string | number> };

export function EvidenceIntegrity() {
  const [result, setResult] = useState<Verification>();
  const [busy, setBusy] = useState(false);

  async function verify() {
    setBusy(true);
    setResult(undefined);
    try {
      setResult(await readJson<Verification>('/api/local/integrity', { method: 'POST' }, 125_000));
    } catch {
      setResult({ state: 'unavailable' });
    } finally { setBusy(false); }
  }

  function exportCheckpoint(checkpoint: Record<string, string | number>) {
    const url = URL.createObjectURL(new Blob([JSON.stringify(checkpoint, null, 2)], { type: 'application/json' }));
    const file = document.createElement('a');
    file.href = url;
    file.download = 'north-evidence-checkpoint.json';
    file.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  return <section className="panel">
    <h2>Local evidence integrity</h2>
    <p>Verify the event chain from its recorded start. Earlier evidence is outside this check.</p>
    <button type="button" disabled={busy} onClick={() => void verify()}>{busy ? 'Verifying…' : 'Verify evidence'}</button>
    {result && <p role="status">{result.state === 'verified'
      ? `Verified ${result.records} linked records since ${result.start}.`
      : result.state === 'broken'
        ? `The first broken link is at record ${result.sequence}${result.event_id ? ' · ' + result.event_id : ''}.`
        : result.state === 'head_invalid' ? 'The integrity checkpoint could not be authenticated.'
          : 'NORTH could not verify the evidence chain on this PC.'}</p>}
    {result?.checkpoint && <button type="button" onClick={() => exportCheckpoint(result.checkpoint!)}>
      Export verification checkpoint
    </button>}
  </section>;
}
