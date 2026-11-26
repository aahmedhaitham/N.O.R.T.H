import { Fragment, useEffect, useState } from 'react';
import { pollVisible } from './pollVisible';

type Pairing = { source_id: string; label: string; revoked_at: string | null; updated_at: string | null };
type Created = { source_id: string; label: string; token: string; issued_at?: string };
type StartupTask = { state: string; last_start?: string | null; last_result?: number | null };

export function CollectorSetup({ back, availableSources, useCollector }: {
  back: () => void; availableSources: string[]; useCollector: (id: string) => void;
}) {
  const [items, setItems] = useState<Pairing[]>([]);
  const [loading, setLoading] = useState(true);
  const [label, setLabel] = useState('');
  const [created, setCreated] = useState<Created | null>(null);
  const [message, setMessage] = useState('');
  const [listError, setListError] = useState(false);
  const [busy, setBusy] = useState(false);
  const [confirm, setConfirm] = useState('');
  const [confirmReplace, setConfirmReplace] = useState(false);
  const [copyStatus, setCopyStatus] = useState('');
  const [opened, setOpened] = useState('');
  const [detailsCopyStatus, setDetailsCopyStatus] = useState('');
  const [desktopSetupMessage, setDesktopSetupMessage] = useState('');
  const [desktopSetupBusy, setDesktopSetupBusy] = useState(false);
  const [installedSource, setInstalledSource] = useState('');
  const [taskMessage, setTaskMessage] = useState('');
  const [startupStatus, setStartupStatus] = useState<{ source: string; task: StartupTask } | null>(null);
  const [startupRevision, setStartupRevision] = useState(0);
  const [guidedSource, setGuidedSource] = useState('');
  const [guidedMessage, setGuidedMessage] = useState('');
  const desktop = location.protocol === 'north:';
  const paired = items.find((item) => item.source_id === created?.source_id);
  const workspace = /^https:\/\/[a-z0-9.-]+(?::\d+)?$/i.test(location.origin) ? location.origin : '';
  const restartCommand = "& '.\\Start NORTH Collector.cmd'";
  function startCommand(id: string) {
    return "& '.\\Start NORTH Collector.cmd' -Source " + id + (workspace ? ' -Workspace ' + workspace : '');
  }
  const command = created ? startCommand(created.source_id) : '';
  const synced = paired?.updated_at && (!created?.issued_at || paired.updated_at >= created.issued_at);

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

  useEffect(() => {
    if (!desktop || !opened) return;
    const controller = new AbortController();
    const stop = pollVisible(async () => {
      try {
        const response = await fetch('/api/desktop/collector/status?source=' + encodeURIComponent(opened),
          { signal: controller.signal, cache: 'no-store' });
        if (!response.ok) return;
        const result = await response.json();
        if (!controller.signal.aborted) {
          setInstalledSource(result.installed === true ? opened : '');
          setStartupStatus(result.task ? { source: opened, task: result.task } : null);
        }
      } catch {
        if (!controller.signal.aborted) setStartupStatus({ source: opened, task: { state: 'Unavailable' } });
      }
    }, 15000);
    return () => { controller.abort(); stop(); };
  }, [desktop, opened, startupRevision]);

  async function copy(value: string, label: string, report = setCopyStatus) {
    try {
      await navigator.clipboard.writeText(value);
      report(label + ' copied.');
    } catch {
      report('Select the ' + label.toLowerCase() + ' and copy it manually.');
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
        setDesktopSetupMessage('');
      } else if (created?.source_id === confirm) {
        setCreated(null);
        setCopyStatus('');
      }
      setConfirm('');
      setConfirmReplace(false);
      await update().catch(() => setListError(true));
    } catch (error) {
      setMessage(error instanceof Error ? error.message : 'Cloud request failed.');
    } finally {
      setBusy(false);
    }
  }

  async function setupDesktop(pairing: Created) {
    setDesktopSetupBusy(true);
    setDesktopSetupMessage('Preparing the collector. This can take a few minutes…');
    try {
      const response = await fetch('/api/desktop/collector/setup', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ source: pairing.source_id, token: pairing.token }),
      });
      if (response.status === 204) { setDesktopSetupMessage('Setup cancelled.'); return; }
      const result = await response.json();
      if (!response.ok) throw new Error(result.detail || 'Collector setup failed.');
      setInstalledSource(pairing.source_id);
      setDesktopSetupMessage('Windows requested a background collector start. Waiting for a sync.');
    } catch (error) {
      setDesktopSetupMessage(error instanceof Error ? error.message : 'Collector setup failed.');
    } finally {
      setDesktopSetupBusy(false);
    }
  }

  async function connectDesktop() {
    setDesktopSetupBusy(true);
    setGuidedMessage('Waiting for confirmation…');
    setGuidedSource('');
    try {
      const response = await fetch('/api/desktop/collector/connect', {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ label }),
      });
      if (response.status === 204) {
        setGuidedMessage('Setup cancelled.');
        return;
      }
      const result = await response.json();
      if (result.source_id) {
        setLabel('');
        setOpened(result.source_id);
        await update().catch(() => setListError(true));
      }
      if (!response.ok) throw new Error(result.detail || 'Could not connect this PC.');
      setInstalledSource(result.source_id);
      setGuidedSource(result.source_id);
      setGuidedMessage('Windows requested a background collector start.');
    } catch (error) {
      setGuidedMessage(error instanceof Error ? error.message : 'Could not connect this PC.');
    } finally {
      setDesktopSetupBusy(false);
    }
  }

  async function changeStartup(source: string, action: 'enable' | 'disable' | 'restart') {
    setDesktopSetupBusy(true);
    setTaskMessage('');
    try {
      const response = await fetch('/api/desktop/collector/' + action +
        '?source=' + encodeURIComponent(source), { method: 'POST' });
      if (response.status === 204) return;
      if (!response.ok) throw new Error((await response.json()).detail);
      setTaskMessage(action === 'disable' ? 'Background startup is disabled.' :
        action === 'restart' ? 'Windows requested a collector restart.' : 'Windows requested a background collector start.');
      setStartupRevision((value) => value + 1);
    } catch (error) {
      setTaskMessage(error instanceof Error ? error.message : 'Windows could not update the collector task.');
    } finally {
      setDesktopSetupBusy(false);
    }
  }
  const task = startupStatus?.source === opened ? startupStatus.task : undefined;

  const keyPanel = created && <div className="pairing-secret">
        <h3>{created.issued_at ? 'Reconnect ' : 'Connect '}{created.label}</h3>
        {desktop && <>
          <p>Set up the collector on this Windows PC. If this build has no bundled runtime, setup uses Python 3.11 or newer and the Windows Python launcher.</p>
          <button type="button" className="primary-action" disabled={desktopSetupBusy || busy}
            onClick={() => void setupDesktop(created)}>Set up on this PC</button>
          {desktopSetupMessage && <p role="status">{desktopSetupMessage}</p>}
        </>}
        <ol>
          <li>{created.issued_at ? 'Stop the current collector with Ctrl+C and keep its existing folder.' :
            'Extract the collector ZIP on the Windows PC you want to monitor.'}</li>
          <li>Open PowerShell in the extracted folder and run this command.</li>
          <li>{workspace ? 'Paste' : 'Enter the workspace address and paste'} the pairing key when prompted. Leave the collector window open during setup.</li>
        </ol>
        <pre>{command}</pre>
        <button onClick={() => void copy(command, 'Command')}>Copy command</button>
        <details>
          <summary>Connect on Linux</summary>
          <p>Open a terminal in the extracted Linux collector folder and run the command. Paste the same pairing key when prompted.</p>
          <pre>{'bash tools/Start-NorthCollectorLinux.sh ' + created.source_id + (workspace ? ' ' + workspace : '')}</pre>
        </details>
        <label>Pairing key <input readOnly value={created.token} onFocus={(event) => event.currentTarget.select()} /></label>
        <div className="case-links">
          <button onClick={() => void copy(created.token, 'Pairing key')}>Copy pairing key</button>
          <button disabled={desktopSetupBusy} onClick={() => { setCreated(null); setCopyStatus(''); }}>Hide key</button>
        </div>
        <p role="status">{paired?.revoked_at ? 'Pairing revoked.' : synced ?
          'NORTH received a sync.' : created.issued_at ? 'Waiting for a sync with the replacement key…' :
          'Waiting for the first sync…'}{copyStatus && ' ' + copyStatus}</p>
      </div>;

  return <main className="collector-settings collector-workspace">
    <header className="collector-heading dashboard-heading">
      <h1>Collectors</h1>
      <button type="button" onClick={back}>Back to workspace</button>
    </header>
    {message && <p role="alert">{message}</p>}
    <section className="panel">
      <h2>Add collector</h2>
      <p>Use a separate pairing for each Windows or Linux computer you manage. The collector needs Python 3.11 or later.</p>
      <a className="button" href="/downloads/NORTH-Collector-Windows.zip" target="_blank" rel="noopener">Download Windows collector</a>
      <a className="button" href="/downloads/NORTH-Collector-Linux.zip" target="_blank" rel="noopener">Download Linux collector</a>
      <details>
        <summary>Start the collector automatically at Windows sign-in</summary>
        <p>Pair the collector and verify a sync first. Stop its PowerShell window, then run this from the same collector folder. Windows starts it under your account, including while NORTH is closed.</p>
        <pre>{'powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\\tools\\Set-NorthCollectorStartup.ps1 -Action Enable'}</pre>
        <p>Use <code>-Action Status</code> to check startup or <code>-Action Disable</code> to turn it off.</p>
      </details>
      <form className="event-filters" onSubmit={(event) => {
        event.preventDefault();
        if (desktop) void connectDesktop();
        else void mutate('/api/cloud/pairings', { label }, true);
      }}>
        <label>Collector name <input required maxLength={80} placeholder="Office PC" value={label}
          onChange={(event) => setLabel(event.target.value)} /></label>
        <button className="primary-action" type="submit" disabled={busy || desktopSetupBusy || !label.trim()}>
          {desktop ? 'Connect this PC' : 'Create pairing'}
        </button>
        {desktop && <button type="button" disabled={busy || desktopSetupBusy || !label.trim()}
          onClick={() => void mutate('/api/cloud/pairings', { label }, true)}>Pair another device</button>}
      </form>
      {guidedMessage && <p role="status">{guidedMessage}</p>}
      {guidedSource && (availableSources.includes(guidedSource) ?
        <button type="button" onClick={() => useCollector(guidedSource)}>View this PC’s telemetry</button> :
        <p role="status">Waiting for this PC’s first sync…</p>)}
      {!created?.issued_at && keyPanel}
    </section>
    <section className="panel">
      <h2>Paired collectors</h2>
      {loading && <p role="status">Loading collectors…</p>}
      {listError && <p role="status">Collector status could not refresh. Retrying…</p>}
      {!loading && !listError && !items.length && <p>No collector pairings have been created.</p>}
      {items.length > 0 && <div className="collector-table-wrap">
        <table className="investigation-table collector-table" aria-label="Paired collectors">
          <thead><tr><th scope="col">Collector</th><th scope="col">Pairing status</th><th scope="col">Last sync</th><th scope="col">Actions</th></tr></thead>
          <tbody>{items.map((item) => <Fragment key={item.source_id}>
          <tr>
            <th scope="row"><button type="button" className="collector-details-toggle"
              aria-expanded={opened === item.source_id}
              aria-controls={opened === item.source_id ? 'collector-details' : undefined}
              onClick={() => {
                setOpened(opened === item.source_id ? '' : item.source_id);
                setDetailsCopyStatus('');
                setConfirmReplace(false);
                setTaskMessage('');
              }}>{item.label}</button></th>
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
          </tr>
          {opened === item.source_id && <tr>
            <td colSpan={4}>
              <section className="collector-details" id="collector-details" aria-label={`${item.label} details`}>
                <h3>{item.label}</h3>
                <p>Source ID <code>{item.source_id}</code></p>
                <p>{item.updated_at ? <>Last synced <time dateTime={item.updated_at}>{new Date(item.updated_at).toLocaleString()}</time></> :
                  'No sync recorded yet.'}</p>
                {desktop && installedSource === item.source_id && <div className="case-links" aria-label="Local collector startup">
                  {!item.revoked_at && <button type="button" disabled={desktopSetupBusy}
                    onClick={() => void changeStartup(item.source_id, 'enable')}>Enable background startup</button>}
                  {!item.revoked_at && task && ['Ready', 'Running'].includes(task.state) &&
                    <button type="button" disabled={desktopSetupBusy}
                      onClick={() => void changeStartup(item.source_id, 'restart')}>Restart collector</button>}
                  <button type="button" disabled={desktopSetupBusy}
                    onClick={() => void changeStartup(item.source_id, 'disable')}>Disable background startup</button>
                </div>}
                {task && <p className="reference">Windows task: {task.state}
                  {task.last_start && <> · Last start <time dateTime={task.last_start}>{new Date(task.last_start).toLocaleString()}</time></>}
                  {task.last_result != null && task.state !== 'Running' && <> · Result {task.last_result}</>}</p>}
                {desktop && taskMessage && <p role="status">{taskMessage}</p>}
                {!item.revoked_at && <>
                  <p>Restart from the folder where you originally paired this collector. Windows uses the saved key.</p>
                  <pre>{restartCommand}</pre>
                  <div className="case-links">
                    <button type="button" onClick={() => void copy(restartCommand, 'Command', setDetailsCopyStatus)}>Copy restart command</button>
                    {availableSources.includes(item.source_id) && <button type="button"
                      onClick={() => useCollector(item.source_id)}>Use this collector in the workspace</button>}
                  </div>
                  <details open={!item.updated_at || undefined}>
                    <summary>Set up in a new folder</summary>
                    <p>First-time setup needs the key issued when this pairing was created. NORTH Cloud stores a hash and cannot display the original key again.</p>
                    <pre>{startCommand(item.source_id)}</pre>
                    <button type="button" onClick={() => void copy(startCommand(item.source_id), 'Setup command', setDetailsCopyStatus)}>Copy setup command</button>
                  </details>
                  {confirmReplace ? <div className="case-links">
                    <p>The old key will stop working immediately. NORTH keeps this collector and its history.</p>
                    <button type="button" disabled={busy}
                      onClick={() => void mutate('/api/cloud/pairings/' + item.source_id + '/replace-key', {}, true)}>
                      Confirm replace key
                    </button>
                    <button type="button" disabled={busy} onClick={() => setConfirmReplace(false)}>Cancel</button>
                  </div> : <button type="button" disabled={busy || Boolean(created?.issued_at && created.source_id === item.source_id)}
                    onClick={() => setConfirmReplace(true)}>Replace pairing key</button>}
                  {created?.issued_at && created.source_id === item.source_id && keyPanel}
                  {detailsCopyStatus && <p role="status">{detailsCopyStatus}</p>}
                </>}
              </section>
            </td>
          </tr>}
          </Fragment>)}</tbody>
        </table>
      </div>}
    </section>
  </main>;
}
