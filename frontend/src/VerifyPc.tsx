import { useEffect, useState } from 'react';
import { useAssistant } from './Assistant';
import { readJson } from './readJson';

type Section = 'fine' | 'review' | 'unknown';
type Row = { id: string; title: string; detail: string };
type Run = { id: string; at: string; readable: number; compared_at: string | null; verdict: Record<Section, Row[]> };
type History = { baseline: string | null; timeline: Run[] };
const sections: Record<Section, string> = { fine: 'Checked and fine', review: 'Needs a look', unknown: 'Could not check' };
const keys = Object.keys(sections) as Section[];
const when = (value: string) => new Date(value).toLocaleString();

export function VerifyPc({ openDetections }: { openDetections?: () => void }) {
  const publish = useAssistant()?.publishVerification;
  const [history, setHistory] = useState<History>();
  const [selected, setSelected] = useState('');
  const [confirm, setConfirm] = useState(false);
  const [busy, setBusy] = useState('');
  const [failed, setFailed] = useState(false);
  const latest = history?.timeline[0];
  const report = history?.timeline.find((item) => item.id === selected) ?? latest;
  useEffect(() => {
    const controller = new AbortController();
    void readJson<History>('/api/local/verify-pc', { signal: controller.signal })
      .then((data) => { if (!controller.signal.aborted) setHistory(data); })
      .catch(() => { if (!controller.signal.aborted) setFailed(true); });
    return () => controller.abort();
  }, []);
  useEffect(() => {
    publish?.(latest ? { at: latest.at, counts: keys.map((key) => latest.verdict[key].length) } : undefined);
    return () => publish?.(undefined);
  }, [latest, publish]);

  async function submit(baseline?: string) {
    setBusy(baseline ? 'baseline' : 'run');
    setFailed(false);
    try {
      const data = await readJson<History>('/api/local/verify-pc' + (baseline ? '?baseline=' + encodeURIComponent(baseline) : ''),
        { method: 'POST' }, 95_000);
      setHistory(data);
      if (!baseline) setSelected('');
      setConfirm(false);
    } catch {
      setFailed(true);
    } finally {
      setBusy('');
    }
  }
  function exportReport(run: Run) {
    const markdown = ['# Verify my PC', '', run.at, '',
      ...keys.flatMap((key) => ['## ' + sections[key], '', ...run.verdict[key].map((row) => '- ' + row.title + ' — ' + row.detail), '']),
    ].join('\n');
    const url = URL.createObjectURL(new Blob([markdown], { type: 'text/markdown' }));
    const file = document.createElement('a');
    file.href = url;
    file.download = 'north-verify-pc.md';
    file.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }
  return <section className="panel" id="north-verify-pc">
    <h2>Verify my PC</h2>
    <p>Check local sources, Windows settings, changes and findings.</p>
    <button type="button" disabled={!!busy} onClick={() => void submit()}>Run PC check</button>
    {busy && <p role="status">NORTH is checking this PC…</p>}
    {failed && <p role="status">NORTH could not complete this request. Try again.</p>}
    {report && <>
      <label>Snapshot timeline <select value={report.id} onChange={(event) => { setSelected(event.target.value); setConfirm(false); }}>
        {history!.timeline.map((run) => <option key={run.id} value={run.id}>{when(run.at)}</option>)}
      </select></label>
      <p>{history?.baseline ? 'Known-good snapshot: ' + when(history.baseline) : 'No known-good snapshot selected.'}</p>
      <p>{report.readable} of 11 snapshot categories were readable. A baseline uses only readable categories.</p>
      {report.compared_at && <p>This report compared with {when(report.compared_at)}.</p>}
      {report.readable > 0 && <button type="button" disabled={!!busy} onClick={() => setConfirm(true)}>Mark this snapshot as known good</button>}
      {confirm && <p>Use this snapshot as the reference for future comparisons?
        {' '}<button type="button" disabled={!!busy} onClick={() => void submit(report.id)}>Confirm baseline</button>
        {' '}<button type="button" onClick={() => setConfirm(false)}>Cancel</button>
      </p>}
      {keys.map((key) => <details key={key} open={key === 'review' || undefined}>
        <summary>{sections[key]} · {report.verdict[key].length}</summary>
        {report.verdict[key].length ? <ul>{report.verdict[key].map((row) => <li key={row.id}>
          <strong>{row.title}</strong> · {row.detail}
        </li>)}</ul> : <p>No items in this section.</p>}
      </details>)}
      <button type="button" onClick={() => exportReport(report)}>Export Markdown</button>
      {openDetections && <button type="button" onClick={openDetections}>Open sensor evidence check</button>}
    </>}
  </section>;
}
