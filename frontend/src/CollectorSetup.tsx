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
  const [listError, setListError] = useState(false);
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
    if (!signal?.aborted) { setItems(data.pairings); setLoading(false); setListError(false); }
  }

  useEffect(() => {
    const controller = new AbortController();
    const stop = pollVisible(() => update(controller.signal).catch(() => {
      if (!controller.signal.aborted) { setLoading(false); setListError(true); }
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
      if (showKey) {
        setCreated(result);
        setLabel('');
        setCopyStatus('');
      } else if (created?.source_id === confirm) {
        setCreated(null);
        setCopyStatus('');
      }
      setConfirm('');
      await update().catch(() => setListError(true));
    } catch (error) {
      setMessage(error instanceof Error ? error.message : 'Cloud request failed.');
    } finally {
      setBusy(false);
    }
  }

  return <main className="collector-settings collector-workspace">
    <header className="collector-heading dashboard-heading">
      <h1>Collectors</h1>
      <button type="button" onClick={back}>Back to workspace</button>
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
      {loading && <p role="status">Loading collectors…</p>}
      {listError && <p role="status">Collector status could not refresh. Retrying…</p>}
      {!loading && !listError && !items.length && <p>No collector pairings have been created.</p>}
      {items.length > 0 && <div className="collector-table-wrap">
        <table className="investigation-table collector-table" aria-label="Paired collectors">
          <thead><tr><th scope="col">Collector</th><th scope="col">Pairing status</th><th scope="col">Last sync</th><th scope="col">Actions</th></tr></thead>
          <tbody>{items.map((item) => <tr key={item.source_id}>
            <th scope="row">{item.label}</th>
            <td><span className="collector-state" data-state={item.revoked_at ? 'revoked' : item.updated_at ? 'synced' : 'waiting'}>
              {item.revoked_at ? 'Revoked' : item.updated_at ? 'Has synced' : 'Waiting for first sync'}
            </span></td>
            <td>{item.updated_at ? <time dateTime={item.updated_at}>{new Date(item.updated_at).toLocaleString()}</time> : '—'}</td>
            <td>{!item.revoked_at && (confirm === item.source_id ? <div className="case-links">
              <button type="button" disabled={busy} onClick={() => void mutate('/api/cloud/pairings/' + item.source_id + '/revoke', {}, false)}>
                Confirm revoke
              </button>
              <button type="button" onClick={() => setConfirm('')}>Cancel</button>
            </div> : <button type="button" aria-label={`Revoke ${item.label}`} onClick={() => setConfirm(item.source_id)}>Revoke</button>)}</td>
          </tr>)}</tbody>
        </table>
      </div>}
    </section>
  </main>;
}
