import { feedbackMessages } from './messages';
import { clientMessages } from './messages';
import { CollectorSetupMessages as strings, formatMessage } from './messages';
import { TimeDisplay } from './TimeDisplay';
import { Fragment, useEffect, useState } from 'react';
import { pollVisible } from './pollVisible';

type Pairing = { source_id: string; label: string; revoked_at: string | null; updated_at: string | null };
type Created = { source_id: string; label: string; token: string; issued_at?: string };
type StartupTask = { state: string; last_start?: string | null; last_result?: number | null };
type CollectorBundle = { current: string | null; available: boolean };

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
  const [startupStatus, setStartupStatus] = useState<{
    source: string; task: StartupTask; bundle?: CollectorBundle | null;
  } | null>(null);
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
    if (!response.ok) throw new Error(clientMessages.couldNotLoadCollectors);
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
          setStartupStatus(result.task ? { source: opened, task: result.task, bundle: result.bundle } : null);
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
      report(feedbackMessages.selectThe + label.toLowerCase() + feedbackMessages.andCopyItManually);
    }
  }

  async function mutate(path: string, body: object, showKey: boolean) {
    setBusy(true);
    setMessage('');
    try {
      const response = await fetch(path, { method: 'POST',
        headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
      const result = await response.json();
      if (!response.ok) throw new Error(result.detail ?? feedbackMessages.cloudRequestFailed);
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
      setMessage(error instanceof Error ? error.message : strings.cloudRequestFailed);
    } finally {
      setBusy(false);
    }
  }

  async function setupDesktop(pairing: Created) {
    setDesktopSetupBusy(true);
    setDesktopSetupMessage(feedbackMessages.preparingTheCollectorThisCanTakeA);
    try {
      const response = await fetch('/api/desktop/collector/setup', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ source: pairing.source_id, token: pairing.token }),
      });
      if (response.status === 204) { setDesktopSetupMessage(feedbackMessages.setupCancelled); return; }
      const result = await response.json();
      if (!response.ok) throw new Error(result.detail || feedbackMessages.collectorSetupFailed);
      setInstalledSource(pairing.source_id);
      setDesktopSetupMessage(feedbackMessages.windowsRequestedABackgroundCollectorStartWaiting);
    } catch (error) {
      setDesktopSetupMessage(error instanceof Error ? error.message : feedbackMessages.collectorSetupFailed);
    } finally {
      setDesktopSetupBusy(false);
    }
  }

  async function connectDesktop() {
    setDesktopSetupBusy(true);
    setGuidedMessage(feedbackMessages.waitingForConfirmation);
    setGuidedSource('');
    try {
      const response = await fetch('/api/desktop/collector/connect', {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ label }),
      });
      if (response.status === 204) {
        setGuidedMessage(feedbackMessages.setupCancelled);
        return;
      }
      const result = await response.json();
      if (result.source_id) {
        setLabel('');
        setOpened(result.source_id);
        await update().catch(() => setListError(true));
      }
      if (!response.ok) throw new Error(result.detail || feedbackMessages.couldNotConnectThisPc);
      setInstalledSource(result.source_id);
      setGuidedSource(result.source_id);
      setGuidedMessage(feedbackMessages.windowsRequestedABackgroundCollectorStart);
    } catch (error) {
      setGuidedMessage(error instanceof Error ? error.message : feedbackMessages.couldNotConnectThisPc);
    } finally {
      setDesktopSetupBusy(false);
    }
  }

  async function changeStartup(source: string, action: 'enable' | 'disable' | 'restart' | 'update') {
    setDesktopSetupBusy(true);
    setTaskMessage('');
    try {
      const response = await fetch('/api/desktop/collector/' + action +
        '?source=' + encodeURIComponent(source), { method: 'POST' });
      if (response.status === 204) return;
      const result = await response.json();
      if (!response.ok) throw new Error(result.detail);
      if (action === 'update') {
        setTaskMessage(!result.updated ? feedbackMessages.thisCollectorAlreadyHasTheBundledVersion :
          result.restarted === false ? feedbackMessages.collectorUpdatedWindowsCouldNotRestartIt :
          result.restarted ? feedbackMessages.collectorUpdatedWindowsRequestedARestart : feedbackMessages.collectorUpdatedBackgroundStartupSettingsWereKept);
      } else {
        setTaskMessage(action === 'disable' ? feedbackMessages.backgroundStartupIsDisabled :
          action === 'restart' ? feedbackMessages.windowsRequestedACollectorRestart : feedbackMessages.windowsRequestedABackgroundCollectorStart);
      }
      setStartupRevision((value) => value + 1);
    } catch (error) {
      setTaskMessage(error instanceof Error ? error.message : feedbackMessages.windowsCouldNotUpdateTheCollectorTask);
    } finally {
      setDesktopSetupBusy(false);
    }
  }
  const task = startupStatus?.source === opened ? startupStatus.task : undefined;
  const bundle = startupStatus?.source === opened ? startupStatus.bundle : undefined;

  const keyPanel = created && <div className="pairing-secret">
        <h3>{created.issued_at ? strings.reconnect : strings.connect}{created.label}</h3>
        {desktop && <>
          <p>{strings.setUpTheCollectorOnThisWindows}</p>
          <button type="button" className="primary-action" disabled={desktopSetupBusy || busy}
            onClick={() => void setupDesktop(created)}>{strings.setUpOnThisPc}</button>
          {desktopSetupMessage && <p role="status">{desktopSetupMessage}</p>}
        </>}
        <ol>
          <li>{created.issued_at ? strings.stopTheCurrentCollectorWithCtrlC :
            strings.extractTheCollectorZipOnTheWindows}</li>
          <li>{strings.openPowershellInTheExtractedFolderAnd}</li>
          <li>{workspace ? strings.paste : strings.enterTheWorkspaceAddressAndPaste}{strings.thePairingKeyWhenPromptedLeaveThe}</li>
        </ol>
        <pre>{command}</pre>
        <button onClick={() => void copy(command, 'Command')}>{strings.copyCommand}</button>
        <details>
          <summary>{strings.connectOnLinux}</summary>
          <p>{strings.openATerminalInTheExtractedLinux}</p>
          <pre>{formatMessage(strings.bashToolsStartNorthcollectorlinuxSh, created.source_id, (workspace ? ' ' + workspace : ''))}</pre>
        </details>
        <label>{strings.pairingKey}<input readOnly value={created.token} onFocus={(event) => event.currentTarget.select()} /></label>
        <div className="case-links">
          <button onClick={() => void copy(created.token, 'Pairing key')}>{strings.copyPairingKey}</button>
          <button disabled={desktopSetupBusy} onClick={() => { setCreated(null); setCopyStatus(''); }}>{strings.hideKey}</button>
        </div>
        <p role="status">{paired?.revoked_at ? strings.pairingRevoked : synced ?
          strings.northReceivedASync : created.issued_at ? strings.waitingForASyncWithTheReplacement :
          strings.waitingForTheFirstSync}{copyStatus && ' ' + copyStatus}</p>
      </div>;

  return <main className="collector-settings collector-workspace">
    <header className="collector-heading dashboard-heading">
      <h1>{strings.collectors}</h1>
      <button type="button" onClick={back}>{strings.backToWorkspace}</button>
    </header>
    {message && <p role="alert">{message}</p>}
    <section className="panel">
      <h2>{strings.addCollector}</h2>
      <p>{strings.useASeparatePairingForEachWindows}</p>
      <a className="button" href="/downloads/NORTH-Collector-Windows.zip" target="_blank" rel="noopener">{strings.downloadWindowsCollector}</a>
      <a className="button" href="/downloads/NORTH-Collector-Linux.zip" target="_blank" rel="noopener">{strings.downloadLinuxCollector}</a>
      <details>
        <summary>{strings.startTheCollectorAutomaticallyAtWindowsSign}</summary>
        <p>{strings.pairTheCollectorAndVerifyASync}</p>
        <pre>{strings.powershellExeNoprofileExecutionpolicyBypassFileTools}</pre>
        <p>{strings.use}<code>{strings.actionStatus}</code>{strings.toCheckStartupOr}<code>{strings.actionDisable}</code>{strings.toTurnItOff}</p>
      </details>
      <form className="event-filters" onSubmit={(event) => {
        event.preventDefault();
        if (desktop) void connectDesktop();
        else void mutate('/api/cloud/pairings', { label }, true);
      }}>
        <label>{strings.collectorName}<input required maxLength={80} placeholder={strings.officePc} value={label}
          onChange={(event) => setLabel(event.target.value)} /></label>
        <button className="primary-action" type="submit" disabled={busy || desktopSetupBusy || !label.trim()}>
          {desktop ? strings.connectThisPc : strings.createPairing}
        </button>
        {desktop && <button type="button" disabled={busy || desktopSetupBusy || !label.trim()}
          onClick={() => void mutate('/api/cloud/pairings', { label }, true)}>{strings.pairAnotherDevice}</button>}
      </form>
      {guidedMessage && <p role="status">{guidedMessage}</p>}
      {guidedSource && (availableSources.includes(guidedSource) ?
        <button type="button" onClick={() => useCollector(guidedSource)}>{strings.viewThisPcSTelemetry}</button> :
        <p role="status">{strings.waitingForThisPcSFirstSync}</p>)}
      {!created?.issued_at && keyPanel}
    </section>
    <section className="panel">
      <h2>{strings.pairedCollectors}</h2>
      {loading && <p role="status">{strings.loadingCollectors}</p>}
      {listError && <p role="status">{strings.collectorStatusCouldNotRefreshRetrying}</p>}
      {!loading && !listError && !items.length && <p>{strings.noCollectorPairingsHaveBeenCreated}</p>}
      {items.length > 0 && <div className="collector-table-wrap">
        <table className="investigation-table collector-table" aria-label={strings.pairedCollectors}>
          <thead><tr><th scope="col">{strings.collector}</th><th scope="col">{strings.pairingStatus}</th><th scope="col">{strings.lastSync}</th><th scope="col">{strings.actions}</th></tr></thead>
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
              {item.revoked_at ? strings.revoked : item.updated_at ? strings.hasSynced : strings.waitingForFirstSync}
            </span></td>
            <td>{item.updated_at ? <TimeDisplay value={item.updated_at} /> : '—'}</td>
            <td>{!item.revoked_at && (confirm === item.source_id ? <div className="case-links">
              <button type="button" disabled={busy} onClick={() => void mutate('/api/cloud/pairings/' + item.source_id + '/revoke', {}, false)}>
                {strings.confirmRevoke}
              </button>
              <button type="button" onClick={() => setConfirm('')}>{strings.cancel}</button>
            </div> : <button type="button" aria-label={formatMessage(strings.revoke0, item.label)} onClick={() => setConfirm(item.source_id)}>{strings.revoke}</button>)}</td>
          </tr>
          {opened === item.source_id && <tr>
            <td colSpan={4}>
              <section className="collector-details" id="collector-details" aria-label={formatMessage(strings.message0Details, item.label)}>
                <h3>{item.label}</h3>
                <p>{strings.sourceId}<code>{item.source_id}</code></p>
                <p>{item.updated_at ? <>{strings.lastSynced}<TimeDisplay value={item.updated_at} /></> :
                  strings.noSyncRecordedYet}</p>
                {desktop && installedSource === item.source_id && <div className="case-links" aria-label={strings.localCollectorStartup}>
                  {!item.revoked_at && <button type="button" disabled={desktopSetupBusy}
                    onClick={() => void changeStartup(item.source_id, 'enable')}>{strings.enableBackgroundStartup}</button>}
                  {!item.revoked_at && task && ['Ready', 'Running'].includes(task.state) &&
                    <button type="button" disabled={desktopSetupBusy}
                      onClick={() => void changeStartup(item.source_id, 'restart')}>{strings.restartCollector}</button>}
                  {!item.revoked_at && bundle?.available && <button type="button" disabled={desktopSetupBusy}
                    onClick={() => void changeStartup(item.source_id, 'update')}>{strings.updateCollector}</button>}
                  <button type="button" disabled={desktopSetupBusy}
                    onClick={() => void changeStartup(item.source_id, 'disable')}>{strings.disableBackgroundStartup}</button>
                </div>}
                {task && <p className="reference">{strings.windowsTask}{task.state}
                  {task.last_start && <>{strings.lastStart}<TimeDisplay value={task.last_start} /></>}
                  {task.last_result != null && task.state !== 'Running' && <>{strings.result}{task.last_result}</>}</p>}
                {bundle && <p className="reference">{strings.collectorBuild}{bundle.current?.slice(0, 10) ?? strings.unrecorded}
                  {bundle.available && strings.updateAvailableInThisApp}</p>}
                {desktop && taskMessage && <p role="status">{taskMessage}</p>}
                {!item.revoked_at && <>
                  <p>{strings.restartFromTheFolderWhereYouOriginally}</p>
                  <pre>{restartCommand}</pre>
                  <div className="case-links">
                    <button type="button" onClick={() => void copy(restartCommand, 'Command', setDetailsCopyStatus)}>{strings.copyRestartCommand}</button>
                    {availableSources.includes(item.source_id) && <button type="button"
                      onClick={() => useCollector(item.source_id)}>{strings.useThisCollectorInTheWorkspace}</button>}
                  </div>
                  <details open={!item.updated_at || undefined}>
                    <summary>{strings.setUpInANewFolder}</summary>
                    <p>{strings.firstTimeSetupNeedsTheKeyIssued}</p>
                    <pre>{startCommand(item.source_id)}</pre>
                    <button type="button" onClick={() => void copy(startCommand(item.source_id), 'Setup command', setDetailsCopyStatus)}>{strings.copySetupCommand}</button>
                  </details>
                  {confirmReplace ? <div className="case-links">
                    <p>{strings.theOldKeyWillStopWorkingImmediately}</p>
                    <button type="button" disabled={busy}
                      onClick={() => void mutate('/api/cloud/pairings/' + item.source_id + '/replace-key', {}, true)}>
                      {strings.confirmReplaceKey}
                    </button>
                    <button type="button" disabled={busy} onClick={() => setConfirmReplace(false)}>{strings.cancel}</button>
                  </div> : <button type="button" disabled={busy || Boolean(created?.issued_at && created.source_id === item.source_id)}
                    onClick={() => setConfirmReplace(true)}>{strings.replacePairingKey}</button>}
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
