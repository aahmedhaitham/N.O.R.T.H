import { feedbackMessages } from './messages';
import { LocalTcpMessages as strings } from './messages';
import { useEffect, useState } from 'react';
import { pollVisible } from './pollVisible';
import { TimeDisplay } from './TimeDisplay';

type Row = {
  state: string; local_address: string; local_port: number; remote_address: string;
  remote_port: number; pid: number; process: string;
};
type Sample = {
  state: 'ready' | 'access_denied' | 'unavailable' | 'read_failed';
  updated_at: string | null; rows: Row[]; limited: boolean;
  listener_history?: {
    unavailable?: boolean;
    baseline_at?: string | null;
    full?: boolean;
    recent?: { local_address: string; local_port: number; first_seen: string; last_seen: string }[];
  };
};
const problems = {
  access_denied: feedbackMessages.windowsDeniedAccessToTheTcpTable,
  unavailable: feedbackMessages.theWindowsTcpReaderIsUnavailableCheck,
  read_failed: feedbackMessages.windowsCouldNotReadItsTcpTable,
};

function endpoint(address: string, port: number) {
  return (address.includes(':') ? '[' + address + ']' : address) + ':' + port;
}

export function LocalTcp({ query }: { query: string }) {
  const [sample, setSample] = useState<Sample | null>(null);
  const [view, setView] = useState<'active' | 'listening'>('active');
  useEffect(() => {
    const request = new AbortController();
    const stop = pollVisible(async () => {
      try {
        const response = await fetch('/api/local/tcp', { signal: request.signal, cache: 'no-store' });
        if (!response.ok) throw new Error();
        const value: Sample = await response.json();
        if (!request.signal.aborted) setSample(value);
      } catch {
        if (!request.signal.aborted) setSample({ state: 'read_failed', updated_at: null, limited: false, rows: [] });
      }
    }, 15000);
    return () => { request.abort(); stop(); };
  }, []);
  const listening = sample?.rows.filter((row) => row.state === 'Listen') ?? [];
  const active = sample?.rows.filter((row) => row.state !== 'Listen') ?? [];
  const rows = (view === 'active' ? active : listening).filter((row) =>
    [row.process, row.local_address, row.local_port, row.remote_address, row.remote_port, row.pid]
      .some((value) => String(value).toLowerCase().includes(query)));

  return <section className="panel" aria-labelledby="local-tcp-heading">
    <h2 id="local-tcp-heading">{strings.liveTcpOnThisPc}</h2>
    <p className="reference">{strings.windowsSocketSnapshotsRefreshAutomaticallyWhileThis}</p>
    {!sample && <p role="status">{strings.readingWindowsTcpConnections}</p>}
    {sample && sample.state !== 'ready' && <p role="status">{problems[sample.state]}</p>}
    {sample?.state === 'ready' && <>
      <p className="reference">{strings.lastSampled}<TimeDisplay value={sample.updated_at} />
        {sample.limited && strings.upTo100SocketsPerView}</p>
      <div className="case-links" role="group" aria-label={strings.tcpSocketView}>
        <button type="button" aria-pressed={view === 'active'} onClick={() => setView('active')}>{strings.connections}{active.length})</button>
        <button type="button" aria-pressed={view === 'listening'} onClick={() => setView('listening')}>{strings.listeningPorts}{listening.length})</button>
      </div>
      {rows.length ? <div className="router-traffic-table-wrap"><table className="investigation-table" aria-label={strings.windowsTcpSockets}>
        <thead><tr><th scope="col">{strings.process}</th><th scope="col">{strings.pid}</th><th scope="col">{strings.local}</th>
          {view === 'active' && <><th scope="col">{strings.remote}</th><th scope="col">{strings.state}</th></>}</tr></thead>
        <tbody>{rows.map((row, index) => <tr key={index}>
          <th scope="row">{row.process || strings.unknownProcess}</th><td>{row.pid || '—'}</td>
          <td><code>{endpoint(row.local_address, row.local_port)}</code></td>
          {view === 'active' && <><td><code>{endpoint(row.remote_address, row.remote_port)}</code></td><td>{row.state}</td></>}
        </tr>)}</tbody>
      </table></div> : <p>{query ? strings.noSocketsMatchTheSearch : view === 'active' ?
        strings.windowsReportedNoMatchingConnectionsInThis : strings.windowsReportedNoListeningTcpPortsIn}</p>}
      {view === 'listening' && sample.listener_history && <section aria-label={strings.listeningPortHistory}>
        <h3>{strings.listeningPortHistory}</h3>
        <p className="reference">{strings.northComparesLocalAddressAndPortAgainst}</p>
        {sample.listener_history.unavailable ? <p role="status">{strings.northCouldnTAccessTheLocalHistory}</p>
          : !sample.listener_history.baseline_at ? <p role="status">{strings.waitingForACompleteSampleWithAt}</p>
          : <>
            <p className="reference">{strings.baselineStarted}<TimeDisplay value={sample.listener_history.baseline_at} /></p>
            {sample.listener_history.full && <p role="status">{strings.localHistoryReachedItsCapacityNewAddresses}</p>}
            {sample.listener_history.recent?.length ? <div className="router-traffic-table-wrap">
              <table className="investigation-table" aria-label={strings.recentlyObservedListeningPorts}>
                <thead><tr><th scope="col">{strings.endpoint}</th><th scope="col">{strings.firstObserved}</th><th scope="col">{strings.lastObserved}</th></tr></thead>
                <tbody>{sample.listener_history.recent.map((row) => <tr key={endpoint(row.local_address, row.local_port)}>
                  <th scope="row"><code>{endpoint(row.local_address, row.local_port)}</code></th>
                  <td><TimeDisplay value={row.first_seen} /></td><td><TimeDisplay value={row.last_seen} /></td>
                </tr>)}</tbody>
              </table></div> : <p>{strings.noNewListeningEndpointsHaveAppearedSince}</p>}
          </>}
      </section>}
    </>}
  </section>;
}
