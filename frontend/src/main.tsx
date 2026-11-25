import { useEffect, useState } from 'react';
import { createRoot } from 'react-dom/client';
import { Background, Controls, ReactFlow } from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import './style.css';

type Evidence = {
  id: string; timestamp: string; kind: number; process: string;
  target: string; destination: string; source_ip?: string; raw: unknown;
};
type Case = {
  id: string; title: string; host: string; asset_id: string; summary: string;
  evidence: Evidence[]; links: { destination: string; evidence_id: string; direction?: 'inbound' }[];
};
type Claim = { text: string; evidence_ids: string[] };

const eventNames: Record<number, string> = {
  1: 'Process created', 3: 'Network connection observed', 11: 'File created', 1001: 'SSH authentication failed',
};
const portfolio = import.meta.env.MODE === 'portfolio';
const publicDemo = portfolio || import.meta.env.MODE === 'hosted';

function App() {
  const [cases, setCases] = useState<Case[]>([]);
  const [selected, setSelected] = useState('');
  const [online, setOnline] = useState(false);
  const [loaded, setLoaded] = useState(false);
  const [loadError, setLoadError] = useState(false);
  const incident = cases.find((item) => item.id === selected) ?? cases[0];

  useEffect(() => {
    if (portfolio) {
      const controller = new AbortController();
      fetch('/demo/cases.json', { signal: controller.signal })
        .then((response) => {
          if (!response.ok) throw new Error('Demo case data unavailable');
          return response.json() as Promise<Case[]>;
        })
        .then((items) => { setCases(items); setLoaded(true); })
        .catch(() => { if (!controller.signal.aborted) setLoadError(true); });
      return () => controller.abort();
    }

    let disposed = false;
    let socket: WebSocket | undefined;
    let retry: number | undefined;
    function connect() {
      const protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
      socket = new WebSocket(protocol + '//' + location.host + '/api/live');
      socket.onmessage = (event) => {
        if (disposed) return;
        setCases(JSON.parse(event.data));
        setLoaded(true);
        setOnline(true);
      };
      socket.onerror = () => socket?.close();
      socket.onclose = () => {
        if (disposed) return;
        setOnline(false);
        retry = window.setTimeout(connect, 2500);
      };
    }
    connect();
    return () => {
      disposed = true;
      window.clearTimeout(retry);
      socket?.close();
    };
  }, []);

  return (
    <div className="shell">
      <header className="topbar">
        <a className="brand" href="/">NORTH</a>
        <span>Investigation console</span>
        <span role="status" className={online ? 'status online' : 'status'}>
          {portfolio ? 'Portfolio demo · Synthetic telemetry' : online ? (publicDemo ? 'Live demo · Synthetic telemetry' : 'Live feed connected') : 'Connecting to live feed'}
        </span>
      </header>
      <div className="workspace">
        <aside aria-label="Investigations">
          <h2>Investigations</h2>
          {cases.map((item) => (
            <button key={item.id} className="case" aria-pressed={item.id === incident?.id}
              onClick={() => setSelected(item.id)}>
              <strong>{item.title}</strong><small>{item.host}</small>
            </button>
          ))}
          {loaded && cases.length === 0 && <p>No correlated events.</p>}
        </aside>
        <main>
          {incident ? <Investigation key={incident.id} incident={incident} /> :
            <section className="panel"><h1>{loadError ? 'Demo cases could not load' : loaded ? 'No investigations' : 'Waiting for telemetry'}</h1></section>}
        </main>
      </div>
    </div>
  );
}

function Investigation({ incident }: { incident: Case }) {
  const [cursor, setCursor] = useState<number | null>(null);
  const [playing, setPlaying] = useState(false);
  const [claims, setClaims] = useState<Claim[]>([]);
  const [message, setMessage] = useState('');
  const [busy, setBusy] = useState(false);
  const last = incident.evidence.length - 1;
  const active = Math.min(cursor ?? last, last);

  useEffect(() => {
    if (!playing) return;
    const timer = window.setTimeout(() => {
      if (active >= last) setPlaying(false);
      else setCursor(active + 1);
    }, 900);
    return () => window.clearTimeout(timer);
  }, [playing, active, last]);

  async function requestDraft() {
    setBusy(true);
    setMessage('');
    setClaims([]);
    try {
      const response = await fetch('/api/cases/' + incident.id + '/draft', { method: 'POST' });
      const body = await response.json();
      if (!response.ok) throw new Error(body.detail || 'Draft request failed.');
      setClaims(body.claims);
    } catch (error) {
      setMessage(error instanceof Error ? error.message : 'Draft request failed.');
    } finally {
      setBusy(false);
    }
  }

  const destinations = [...new Set(incident.links.map((link) => link.destination))];
  const inbound = incident.links.some((link) => link.direction === 'inbound');
  const nodes = [
    { id: incident.asset_id, position: { x: inbound ? 250 : 0, y: 0 }, data: { label: incident.host } },
    ...destinations.map((ip, index) => (
      { id: 'ip-' + ip, position: { x: inbound ? 0 : 250, y: index * 90 }, data: { label: ip } }
    )),
  ];
  const edges = destinations.map((ip) => {
    const inbound = incident.links.some((link) => link.destination === ip && link.direction === 'inbound');
    return {
      id: 'edge-' + ip, source: inbound ? 'ip-' + ip : incident.asset_id,
      target: inbound ? incident.asset_id : 'ip-' + ip, animated: true,
    };
  });

  return <>
    <section className="panel overview">
      <div>
        <span className="module">IRIS / INVESTIGATION</span>
        <h1>{incident.title}</h1>
        <p>{incident.summary}</p>
      </div>
      <a className="button" download={portfolio ? 'north-' + incident.id + '.md' : undefined}
        href={portfolio ? '/demo/' + incident.id + '.md' : '/api/cases/' + incident.id + '/report'}>Export report</a>
    </section>
    <div className="columns">
      <section className="panel">
        <span className="module">ATLAS / INFRASTRUCTURE</span>
        <h2>Observed connections</h2>
        <div className="graph">
          <ReactFlow key={destinations.join(',')} nodes={nodes} edges={edges}
            fitView fitViewOptions={{ maxZoom: 1 }} nodesDraggable={false} nodesConnectable={false} colorMode="dark">
            <Background gap={18} /><Controls showInteractive={false} />
          </ReactFlow>
        </div>
        {incident.links.map((link) => <p key={link.evidence_id} className="reference">
          {link.destination}{' '}<a href={'#event-' + link.evidence_id}>View evidence</a>
        </p>)}
        {incident.links.length === 0 && <p>No connection events for this case.</p>}
      </section>
      <section className="panel">
        <span className="module">ECHO / RECONSTRUCTION</span>
        <h2>Evidence timeline</h2>
        <div className="replay">
          <button onClick={() => {
            if (!playing && active === last) setCursor(0);
            setPlaying(!playing);
          }}>
            {playing ? 'Pause' : 'Play'}
          </button>
          <input aria-label="Timeline position" type="range" min="0" max={last} value={active}
            onChange={(event) => { setPlaying(false); setCursor(Number(event.target.value)); }} />
          <span>{active + 1} / {last + 1}</span>
        </div>
        <ol className="timeline">
          {incident.evidence.map((item, index) => (
            <li id={'event-' + item.id} key={item.id} className={index === active ? 'current' : ''}>
              <time dateTime={item.timestamp}>{item.timestamp.slice(11, 19)} UTC</time>
              <strong>{eventNames[item.kind]}</strong>
              <small>{item.target || item.destination || item.source_ip || item.process}</small>
              <details><summary>Raw evidence</summary><pre>{JSON.stringify(item.raw, null, 2)}</pre></details>
            </li>
          ))}
        </ol>
      </section>
    </div>
    <section className="panel">
      <span className="module">IRIS / ANALYST REVIEW</span>
      <h2>{publicDemo ? 'Review case evidence' : 'Local AI draft'}</h2>
      {publicDemo ? <p>This demo uses a bundled case. Open the original events in ECHO to verify the findings. Live AI drafts are available when running NORTH with Ollama.</p> : <>
        <p>Ollama ranks observations that NORTH derives from case evidence. The available events do not establish intent.</p>
        <button type="button" disabled={busy} onClick={requestDraft}>{busy ? 'Drafting…' : 'Generate draft'}</button>
      </>}
      {message && <p role="status">{message}</p>}
      {claims.length > 0 && <ul>{claims.map((claim, index) => (
        <li key={index}>{claim.text}{' '}{claim.evidence_ids.map((id, position) => (
          <a className="citation" key={id + position} href={'#event-' + id}>{id.slice(0, 8)}</a>
        ))}</li>
      ))}</ul>}
    </section>
  </>;
}

createRoot(document.getElementById('root')!).render(<App />);
