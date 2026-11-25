import { useEffect, useState } from 'react';
import { pollVisible } from './pollVisible';

type Pairing = { source_id: string; label: string; revoked_at: string | null; updated_at: string | null };
type Created = { source_id: string; label: string; token: string };

export function CollectorSetup({ back }: { back: () => void }) {
  const [items, setItems] = useState<Pairing[]>([]);
  const [loading, setLoading] = useState(true);
  const [label, setLabel] = useState('');
  const [created, setCreated] = useState<Created | null>(null);
  const [message, setMessage] = useState('');
  const [busy, setBusy] = useState(false);
  const [confirm, setConfirm] = useState('');
  const [copyStatus, setCopyStatus] = useState('');
  const paired = items.find((item) => item.source_id === created?.source_id);
  const workspace = /^https:\/\/[a-z0-9.-]+(?::\d+)?$/i.test(location.origin) ? location.origin : '';
  const command = created ? "& '.\\Start NORTH Collector.cmd' -Source " + created.source_id +
    (workspace ? ' -Workspace ' + workspace : '') : '';

  async function update(signal?: AbortSignal) {
    const response = await fetch('/api/cloud/pairings', { signal });
    if (!response.ok) throw new Error('Could not load collectors.');
    const data = await response.json();
    if (!signal?.aborted) { setItems(data.pairings); setLoading(false); }
  }

  useEffect(() => {
    const controller = new AbortController();
    const stop = pollVisible(() => update(controller.signal).catch(() => {
      if (!controller.signal.aborted) { setLoading(false); setMessage('Could not load collectors.'); }
    }), 10000);
    return () => { controller.abort(); stop(); };
  }, []);

  async function copy(value: string, label: string) {
    try {
      await navigator.clipboard.writeText(value);
      setCopyStatus(label + ' copied.');
    } catch {
      setCopyStatus('Select the ' + label.toLowerCase() + ' and copy it manually.');
    }
  }

  async function mutate(path: string, body: object, showKey: boolean) {
    setBusy(true);
    setMessage('');
    try {
      const response = await fetch(path, { method: 'POST',
        headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
      const result = await response.json();
      if (!response.ok) throw new Error(result.detail ?? 'Cloud request failed.');
      if (showKey) { setCreated(result); setLabel(''); }
      setConfirm('');
      await update();
    } catch (error) {
      setMessage(error instanceof Error ? error.message : 'Cloud request failed.');
    } finally {
      setBusy(false);
    }
  }

  return <main className="collector-settings">
    <header className="collector-heading">
      <div><h1>Collectors</h1><p>Connect a device to this workspace and manage its access.</p></div>
      <button onClick={back}>Back to dashboard</button>
    </header>
    {message && <p role="alert">{message}</p>}
    <section className="panel">
      <h2>Add collector</h2>
      <p>Run the collector on the Windows PC you want to monitor. It needs Python 3.11 or later. Approve pairing only on PCs you manage.</p>
      <a className="button" href="/downloads/NORTH-Collector-Windows.zip" target="_blank" rel="noopener">Download Windows collector</a>
      <form className="event-filters" onSubmit={(event) => {
        event.preventDefault(); void mutate('/api/cloud/pairings', { label }, true);
      }}>
        <label>Collector name <input required maxLength={80} placeholder="Office PC" value={label}
          onChange={(event) => setLabel(event.target.value)} /></label>
        <button className="primary-action" type="submit" disabled={busy || !label.trim()}>Create pairing</button>
      </form>
      {created && <div className="pairing-secret">
        <h3>Connect {created.label}</h3>
        <ol>
          <li>Extract the collector ZIP on the Windows PC you want to monitor.</li>
          <li>Open PowerShell in the extracted folder and run this command.</li>
          <li>{workspace ? 'Paste' : 'Enter the workspace address and paste'} the pairing key when prompted. Leave the collector window open during setup.</li>
        </ol>
        <pre>{command}</pre>
        <button onClick={() => void copy(command, 'Command')}>Copy command</button>
        <label>Pairing key <input readOnly value={created.token} onFocus={(event) => event.currentTarget.select()} /></label>
        <div className="case-links">
          <button onClick={() => void copy(created.token, 'Pairing key')}>Copy pairing key</button>
          <button onClick={() => { setCreated(null); setCopyStatus(''); }}>Hide key</button>
        </div>
        <p role="status">{paired?.revoked_at ? 'Pairing revoked.' : paired?.updated_at ?
          'Connected. NORTH received the first sync.' : 'Waiting for the first sync…'}{copyStatus && ' ' + copyStatus}</p>
      </div>}
    </section>
    <section className="panel">
      <h2>Paired collectors</h2>
      {loading && <p>Loading collectors…</p>}
      {!loading && !items.length && <p>No collector pairings have been created.</p>}
      <ul className="network-list">{items.map((item) => <li key={item.source_id} className="collector-row">
        <div>
          <strong>{item.label}</strong>
          <small>{item.revoked_at ? 'Revoked' : item.updated_at ?
            'Last synced ' + new Date(item.updated_at).toLocaleString() : 'Waiting for first sync'}</small>
        </div>
        {!item.revoked_at && (confirm === item.source_id ? <div className="case-links">
          <button disabled={busy} onClick={() => void mutate('/api/cloud/pairings/' + item.source_id + '/revoke', {}, false)}>
            Confirm revoke
          </button>
          <button onClick={() => setConfirm('')}>Cancel</button>
        </div> : <button onClick={() => setConfirm(item.source_id)}>Revoke</button>)}
      </li>)}</ul>
    </section>
  </main>;
}
