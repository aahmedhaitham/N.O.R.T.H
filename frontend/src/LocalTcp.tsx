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
  access_denied: 'Windows denied access to the TCP table. Check this account’s access to the Windows TCP/IP provider.',
  unavailable: 'The Windows TCP reader is unavailable. Check that the Windows NetTCPIP module is available.',
  read_failed: 'Windows could not read its TCP table. NORTH will retry while this view is open.',
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
    <h2 id="local-tcp-heading">Live TCP on this PC</h2>
    <p className="reference">Windows socket snapshots refresh automatically while this view is open.</p>
    {!sample && <p role="status">Reading Windows TCP connections…</p>}
    {sample && sample.state !== 'ready' && <p role="status">{problems[sample.state]}</p>}
    {sample?.state === 'ready' && <>
      <p className="reference">Last sampled <TimeDisplay value={sample.updated_at} />
        {sample.limited && ' · Up to 100 sockets per view'}</p>
      <div className="case-links" role="group" aria-label="TCP socket view">
        <button type="button" aria-pressed={view === 'active'} onClick={() => setView('active')}>Connections ({active.length})</button>
        <button type="button" aria-pressed={view === 'listening'} onClick={() => setView('listening')}>Listening ports ({listening.length})</button>
      </div>
      {rows.length ? <div className="router-traffic-table-wrap"><table className="investigation-table" aria-label="Windows TCP sockets">
        <thead><tr><th scope="col">Process</th><th scope="col">PID</th><th scope="col">Local</th>
          {view === 'active' && <><th scope="col">Remote</th><th scope="col">State</th></>}</tr></thead>
        <tbody>{rows.map((row, index) => <tr key={index}>
          <th scope="row">{row.process || 'Unknown process'}</th><td>{row.pid || '—'}</td>
          <td><code>{endpoint(row.local_address, row.local_port)}</code></td>
          {view === 'active' && <><td><code>{endpoint(row.remote_address, row.remote_port)}</code></td><td>{row.state}</td></>}
        </tr>)}</tbody>
      </table></div> : <p>{query ? 'No sockets match the search.' : view === 'active' ?
        'Windows reported no matching connections in this sample.' : 'Windows reported no listening TCP ports in this sample.'}</p>}
      {view === 'listening' && sample.listener_history && <section aria-label="Listening port history">
        <h3>Listening port history</h3>
        <p className="reference">NORTH compares local address and port against its first complete listening sample. A new listener can be normal.</p>
        {sample.listener_history.unavailable ? <p role="status">NORTH couldn’t access the local history. The current socket sample is still available.</p>
          : !sample.listener_history.baseline_at ? <p role="status">Waiting for a complete sample with at least one listening port.</p>
          : <>
            <p className="reference">Baseline started <TimeDisplay value={sample.listener_history.baseline_at} /></p>
            {sample.listener_history.full && <p role="status">Local history reached its capacity. New addresses and ports may be missing from history.</p>}
            {sample.listener_history.recent?.length ? <div className="router-traffic-table-wrap">
              <table className="investigation-table" aria-label="Recently observed listening ports">
                <thead><tr><th scope="col">Endpoint</th><th scope="col">First observed</th><th scope="col">Last observed</th></tr></thead>
                <tbody>{sample.listener_history.recent.map((row) => <tr key={endpoint(row.local_address, row.local_port)}>
                  <th scope="row"><code>{endpoint(row.local_address, row.local_port)}</code></th>
                  <td><TimeDisplay value={row.first_seen} /></td><td><TimeDisplay value={row.last_seen} /></td>
                </tr>)}</tbody>
              </table></div> : <p>No new listening endpoints have appeared since the baseline.</p>}
          </>}
      </section>}
    </>}
  </section>;
}
