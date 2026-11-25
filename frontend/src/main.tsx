import { useCallback, useEffect, useRef, useState } from 'react';
import { createRoot } from 'react-dom/client';
import { Background, Controls, ReactFlow } from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import './style.css';
import { Network } from './Network';
import { Events } from './Events';
import { eventNames } from './eventNames';
import { Dashboard } from './Dashboard';
import { InstallApp } from './InstallApp';
import { CloudGate, type WorkspacePanel } from './CloudGate';
import { CaseReview } from './CaseReview';
import { Appearance } from './Appearance';
import { readWorkspacePreference, writeWorkspacePreference } from './workspaceSession';

type Evidence = {
  id: string; timestamp: string; kind: number; process: string;
  target: string; destination: string; source_ip?: string; raw: unknown;
};
type Case = {
  id: string; title: string; host: string; asset_id: string; summary: string;
  evidence: Evidence[]; links: { destination: string; evidence_id: string; direction?: 'inbound' }[];
};
type Claim = { text: string; evidence_ids: string[] };
type RelatedEvent = { id: string; source_id: string; timestamp: string; kind: number; collector: string; host: string; address: string };
const evidenceAnchor = '#event-';

const portfolio = import.meta.env.MODE === 'portfolio';
const publicDemo = portfolio || import.meta.env.MODE === 'hosted';
const desktop = location.protocol === 'north:';
const desktopLocal = desktop && location.pathname === '/';
const cloud = import.meta.env.MODE === 'cloud' && !desktopLocal;
if (desktopLocal) document.title = 'NORTH | This computer';

const navigation = [
  { id: 'dashboard', label: 'Overview', detail: 'Security dashboard' },
  { id: 'network', label: 'ATLAS', detail: 'Network inventory' },
  { id: 'events', label: 'IRIS', detail: 'Event explorer' },
  { id: 'cases', label: 'ECHO', detail: 'Investigations' },
] as const;

type View = (typeof navigation)[number]['id'];

function QuickNavigation({ view, open }: { view?: View; open: (view: View) => void }) {
  const dialog = useRef<HTMLDialogElement>(null);
  const searchInput = useRef<HTMLInputElement>(null);
  const [query, setQuery] = useState('');
  const search = query.trim().toLowerCase();
  const matches = navigation.filter(({ label, detail }) => `${label} ${detail}`.toLowerCase().includes(search));
  const apple = /Mac|iPhone|iPad/.test(navigator.platform);

  const show = useCallback(() => {
    dialog.current?.showModal();
    searchInput.current?.focus();
  }, []);

  useEffect(() => {
    function handleShortcut(event: KeyboardEvent) {
      if (event.defaultPrevented || event.repeat || event.altKey || event.shiftKey ||
          !(event.ctrlKey || event.metaKey) || event.key.toLowerCase() !== 'k') return;
      const picker = dialog.current;
      if (!picker || picker.open || document.querySelector('dialog[open]')) return;
      event.preventDefault();
      show();
    }
    window.addEventListener('keydown', handleShortcut);
    return () => window.removeEventListener('keydown', handleShortcut);
  }, [show]);

  function goTo(destination: View) {
    dialog.current?.close();
    open(destination);
  }

  return <>
    <button className="quick-nav-trigger" type="button" aria-haspopup="dialog"
      aria-keyshortcuts={apple ? 'Meta+K' : 'Control+K'} onClick={show}>
      Go to <kbd aria-hidden="true">{apple ? '⌘ K' : 'Ctrl K'}</kbd>
    </button>
    <dialog ref={dialog} className="quick-nav" aria-labelledby="quick-nav-title" onClose={() => setQuery('')}>
      <div className="quick-nav-heading">
        <h2 id="quick-nav-title">Go to a page</h2>
        <button type="button" onClick={() => dialog.current?.close()}>Close</button>
      </div>
      <form className="quick-nav-search" onSubmit={(event) => {
        event.preventDefault();
        if (matches[0]) goTo(matches[0].id);
      }}>
        <input ref={searchInput} type="search" aria-label="Find a page" placeholder="Find a page"
          value={query} onChange={(event) => setQuery(event.target.value)} />
      </form>
      <ul className="quick-nav-results">
        {matches.map((item) => <li key={item.id}>
          <button type="button" aria-current={item.id === view ? 'page' : undefined} onClick={() => goTo(item.id)}>
            <span className={`nav-icon nav-icon-${item.id}`} aria-hidden="true" />
            <strong>{item.label}</strong><small>{item.detail}</small>
          </button>
        </li>)}
      </ul>
      {matches.length === 0 && <p role="status">No matching pages.</p>}
    </dialog>
  </>;
}

function App({ source = null, openCollectors, controls, panel }: {
  source?: string | null;
  openCollectors?: () => void;
  controls?: import('react').ReactNode;
  panel?: WorkspacePanel;
}) {
  const [view, updateView] = useState<View>(() => {
    const saved = readWorkspacePreference('view');
    return navigation.find((item) => item.id === saved)?.id ?? 'dashboard';
  });
  const handledCitation = useRef('');
  const viewContent = useRef<HTMLDivElement>(null);
  const [eventSearch, setEventSearch] = useState('');
  const [cases, setCases] = useState<Case[]>([]);
  const [selected, updateSelected] = useState(() => {
    const saved = readWorkspacePreference('case');
    const prefix = (source ?? '') + ':';
    return saved.startsWith(prefix) ? saved.slice(prefix.length) : '';
  });
  const [online, setOnline] = useState(false);
  const [loaded, setLoaded] = useState(false);
  const [loadError, setLoadError] = useState(false);
  const incident = cases.find((item) => item.id === selected) ?? cases[0];
  const sourceQuery = source ? '?source=' + encodeURIComponent(source) : '';
  const networkEndpoint = portfolio ? '/demo/network.json' : '/api/network' + sourceQuery;

  useEffect(() => {
    if (viewContent.current) viewContent.current.scrollTop = 0;
  }, [view, panel?.title]);

  function setView(next: View) {
    panel?.close();
    updateView(next);
    writeWorkspacePreference('view', next);
  }

  function setSelected(id: string) {
    updateSelected(id);
    writeWorkspacePreference('case', (source ?? '') + ':' + id);
  }

  function openCase(id: string) {
    setSelected(id);
    setView('cases');
  }

  useEffect(() => {
    function openLinkedCase() {
      const hash = location.hash;
      if (!hash.startsWith(evidenceAnchor)) {
        handledCitation.current = '';
        return;
      }
      if (hash === handledCitation.current) return;
      const linkedId = hash.slice(evidenceAnchor.length);
      const linkedCase = [incident, ...cases].find((item) => item?.evidence.some((event) => event.id === linkedId));
      if (!linkedCase) return;
      handledCitation.current = hash;
      openCase(linkedCase.id);
    }
    if (!panel) openLinkedCase();
    window.addEventListener('hashchange', openLinkedCase);
    return () => window.removeEventListener('hashchange', openLinkedCase);
  }, [cases, incident, panel]);

  useEffect(() => {
    if (cloud || desktopLocal) {
      const controller = new AbortController();
      let timer: number | undefined;
      async function update() {
        try {
          const response = await fetch('/api/cases' + sourceQuery, { signal: controller.signal });
          if (!response.ok) throw new Error('Cloud case feed unavailable');
          const items: Case[] = await response.json();
          if (!controller.signal.aborted) {
            setCases(items); setLoaded(true); setOnline(true); setLoadError(false);
          }
        } catch {
          if (!controller.signal.aborted) { setOnline(false); setLoadError(true); }
        } finally {
          if (!controller.signal.aborted) timer = window.setTimeout(update, 15000);
        }
      }
      void update();
      return () => { controller.abort(); window.clearTimeout(timer); };
    }
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
  }, [sourceQuery]);

  return (
    <div className="shell">
      <div className="window-heading">NORTH</div>
      <nav className="console-nav" aria-label="Console">
        {navigation.map((item) => <button key={item.id} type="button" className="nav-item"
          aria-current={!panel && view === item.id ? 'page' : undefined} onClick={() => setView(item.id)}>
          <span className={`nav-icon nav-icon-${item.id}`} aria-hidden="true" />
          <span><strong>{item.label}</strong><small>{item.detail}</small></span>
        </button>)}
      </nav>
      <div className="shell-content">
      {controls}
      <header className="topbar">
        <span className="topbar-location">{panel?.title ?? navigation.find((item) => item.id === view)?.detail}</span>
        <QuickNavigation view={panel ? undefined : view} open={setView} />
        <Appearance />
        <InstallApp />
        <span role="status" className={online || portfolio ? 'status online' : 'status'}>
          {desktopLocal ? 'This computer · Local data' : cloud ? (online ? 'Cloud connection ready' : 'Connecting to cloud') :
            portfolio ? 'Portfolio demo · Synthetic telemetry' : online ? (publicDemo ? 'Live demo · Synthetic telemetry' : 'Live feed connected') : 'Connecting to live feed'}
        </span>
      </header>
      <div className="view-content" ref={viewContent}>
      {panel?.content}
      <div className="workspace-pages" hidden={Boolean(panel)}>
      {view === 'dashboard' && <Dashboard endpoint={networkEndpoint} cases={cases} loaded={loaded}
        demo={publicDemo} local={desktopLocal} open={setView} openCase={openCase} connect={cloud && !source ? openCollectors : undefined} />}
      <div hidden={view !== 'network'}>
        <Network endpoint={view === 'network' ? networkEndpoint : ''} openCase={openCase} demo={publicDemo} readOnly={publicDemo || cloud} />
      </div>
      {view === 'events' && <Events portfolio={portfolio} source={source} initialSearch={eventSearch}
        canSave={cloud} openNetwork={() => setView('network')} />}
      {view === 'cases' && <div className="workspace">
        <aside className="echo-case-list" aria-label="Investigations">
          <h2>Investigations <span>{loaded ? cases.length : ''}</span></h2>
          {cases.map((item) => (
            <button key={item.id} className="case" aria-pressed={item.id === incident?.id}
              onClick={() => setSelected(item.id)}>
              <strong>{item.title}</strong>
              <small>{item.host} · {item.evidence.length} {item.evidence.length === 1 ? 'event' : 'events'}</small>
            </button>
          ))}
        </aside>
        <main className="echo-workspace">
          {incident ? <Investigation key={incident.id} incident={incident} sourceQuery={sourceQuery} visible={!panel}
            openEvents={(search) => { setEventSearch(search); setView('events'); }} /> :
            <section className="panel"><h1>{loadError ? 'Cases could not load' : loaded ? 'No investigations yet' : 'Waiting for telemetry'}</h1>
              {loaded && !loadError && <p>Investigations appear when NORTH links related events. You can inspect individual events in IRIS.</p>}
              {(loaded || loadError) && <button onClick={() => setView('events')}>Open IRIS events</button>}
            </section>}
        </main>
      </div>}
      </div>
      </div>
      </div>
    </div>
  );
}

function Investigation({ incident, sourceQuery, openEvents, visible }: {
  incident: Case; sourceQuery: string; openEvents: (search: string) => void; visible: boolean;
}) {
  const [cursor, setCursor] = useState<number | null>(null);
  const [playing, setPlaying] = useState(false);
  const [speed, setSpeed] = useState(1);
  const [claims, setClaims] = useState<Claim[]>([]);
  const [message, setMessage] = useState('');
  const [busy, setBusy] = useState(false);
  const [related, setRelated] = useState<RelatedEvent[] | null>(null);
  const [relatedError, setRelatedError] = useState(false);
  const [draftProvider, setDraftProvider] = useState('');
  const revealedCitation = useRef('');
  const last = incident.evidence.length - 1;
  const active = Math.min(cursor ?? last, last);

  function seek(index: number) {
    setPlaying(false);
    setCursor(index);
  }

  function revealEvidence(id: string) {
    const index = incident.evidence.findIndex((item) => item.id === id);
    const row = document.getElementById('event-' + id);
    const raw = row?.querySelector('details');
    if (index < 0 || !row || !raw) return;
    seek(index);
    raw.open = true;
    window.requestAnimationFrame(() => {
      row.scrollIntoView({ block: 'nearest' });
      raw.querySelector('summary')?.focus({ preventScroll: true });
    });
  }

  useEffect(() => {
    if (!visible) return;
    function openCitation() {
      const hash = location.hash;
      if (!hash.startsWith(evidenceAnchor)) {
        revealedCitation.current = '';
        return;
      }
      if (revealedCitation.current === hash) return;
      const id = hash.slice(evidenceAnchor.length);
      if (!incident.evidence.some((event) => event.id === id)) return;
      revealedCitation.current = hash;
      revealEvidence(id);
    }
    openCitation();
    window.addEventListener('hashchange', openCitation);
    return () => window.removeEventListener('hashchange', openCitation);
  }, [incident.evidence, visible]);

  function reopenCitation(event: React.MouseEvent<HTMLAnchorElement>, id: string) {
    if (event.metaKey || event.ctrlKey || event.altKey || event.shiftKey) return;
    if (location.hash === evidenceAnchor + id) {
      event.preventDefault();
      revealEvidence(id);
    }
  }

  useEffect(() => {
    if (!cloud) return;
    const controller = new AbortController();
    void fetch('/api/cases/' + incident.id + '/related' + sourceQuery, { signal: controller.signal })
      .then((response) => {
        if (!response.ok) throw new Error('Could not load related events');
        return response.json();
      })
      .then((body) => setRelated(body.matches))
      .catch(() => { if (!controller.signal.aborted) setRelatedError(true); });
    return () => controller.abort();
  }, [incident.id, sourceQuery]);

  useEffect(() => {
    if (!playing) return;
    const timer = window.setTimeout(() => {
      if (active >= last) setPlaying(false);
      else setCursor(active + 1);
    }, 900 / speed);
    return () => window.clearTimeout(timer);
  }, [playing, active, last, speed]);

  async function requestDraft() {
    setBusy(true);
    setMessage('');
    setClaims([]);
    setDraftProvider('');
    try {
      const response = await fetch('/api/cases/' + incident.id + '/draft' + sourceQuery, { method: 'POST' });
      const body = await response.json();
      if (!response.ok) throw new Error(body.detail || 'Draft request failed.');
      setClaims(body.claims);
      setDraftProvider(body.reason ?? body.provider ?? '');
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
        <h1>{incident.title}</h1>
        <p className="echo-case-host">{incident.host}</p>
      </div>
      <div className="case-links">
        <button onClick={() => openEvents(incident.host)}>Find host events in IRIS</button>
        <a className="button" download={portfolio ? 'north-' + incident.id + '.md' : undefined}
          href={portfolio ? '/demo/' + incident.id + '.md' : '/api/cases/' + incident.id + '/report' + sourceQuery}>Export report</a>
      </div>
      <p className="echo-case-summary">{incident.summary}</p>
    </section>
    <div className="echo-evidence-grid">
      <section className="panel echo-timeline">
        <h2>Evidence timeline</h2>
        {last < 0 ? <p>No evidence events in this case.</p> :
          <div className="replay" role="group" aria-label="Timeline playback">
            <div className="replay-actions">
              <button disabled={active <= 0} onClick={() => seek(active - 1)} aria-label="Previous event">‹</button>
              <button disabled={last === 0} onClick={() => {
                if (!playing && active === last) setCursor(0);
                setPlaying(!playing);
              }}>{playing ? 'Pause' : 'Play'}</button>
              <button disabled={active >= last} onClick={() => seek(active + 1)} aria-label="Next event">›</button>
              <select aria-label="Replay speed" value={speed} onChange={(event) => setSpeed(Number(event.target.value))}>
                <option value={0.5}>0.5×</option><option value={1}>1×</option><option value={2}>2×</option>
              </select>
            </div>
            <div className="replay-position">
              <input aria-label="Timeline position" aria-valuetext={`Event ${active + 1} of ${last + 1}`}
                type="range" min="0" max={last} value={active} disabled={last === 0}
                onChange={(event) => seek(Number(event.target.value))} />
              <span>Event {active + 1} of {last + 1}</span>
            </div>
          </div>}
        <ol className="timeline">
          {incident.evidence.map((item, index) => (
            <li id={'event-' + item.id} key={item.id} aria-current={index === active ? 'step' : undefined}>
              <time dateTime={item.timestamp}>{item.timestamp.slice(11, 19)} UTC</time>
              <strong>{eventNames[item.kind] ?? 'Event ' + item.kind}</strong>
              <small>{item.target || item.destination || item.source_ip || item.process}</small>
              <details><summary>Raw evidence</summary><pre>{JSON.stringify(item.raw, null, 2)}</pre></details>
            </li>
          ))}
        </ol>
      </section>
      <section className="panel echo-connections">
        <h2>Observed connections</h2>
        {incident.links.length > 0 && <div className="graph">
          <ReactFlow key={destinations.join(',')} nodes={nodes} edges={edges}
            fitView fitViewOptions={{ maxZoom: 1 }} nodesDraggable={false} nodesConnectable={false}>
            <Background gap={18} /><Controls showInteractive={false} />
          </ReactFlow>
        </div>}
        {incident.links.map((link) => <p key={link.evidence_id} className="reference">
          {link.destination}{' '}<a href={evidenceAnchor + link.evidence_id}
            onClick={(event) => reopenCitation(event, link.evidence_id)}>View evidence</a>
        </p>)}
        {incident.links.length === 0 && <p>No connection events for this case.</p>}
      </section>
    </div>
    {cloud && <CaseReview endpoint={'/api/cases/' + incident.id + '/review' + sourceQuery} />}
    {cloud && <section className="panel">
      <h2>Related events across collectors</h2>
      <p>Matches share an IP address within five minutes of the case’s latest event. Shared addresses alone cannot establish that events are part of the same incident.</p>
      {relatedError && <p role="status">Related events are unavailable.</p>}
      {!relatedError && !related && <p>Checking other collectors…</p>}
      {related?.length === 0 && <p>No matching events from another collector.</p>}
      <ul className="network-list">{related?.map((event) => <li key={event.source_id + '/' + event.id + '/' + event.address}>
        <strong>{eventNames[event.kind] ?? 'Event ' + event.kind}</strong>
        <small>{event.collector}{event.host ? ' · ' + event.host : ''} · {event.address} · {new Date(event.timestamp).toLocaleString()}</small>
        <RelatedEvidence event={event} />
      </li>)}</ul>
    </section>}
    <section className="panel">
      <span className="module">IRIS / ANALYST REVIEW</span>
      <h2>{publicDemo || desktopLocal ? 'Review case evidence' : cloud ? 'Evidence brief' : 'Local AI draft'}</h2>
      {desktopLocal ? <p>Open any event in the timeline to review the original record.</p> :
        publicDemo ? <p>This demo uses a bundled case. Open the original events in ECHO to verify the findings. Live AI drafts are available when running NORTH with Ollama.</p> : <>
        <p>{cloud ? 'Summarize recorded activity and open the cited events to verify each observation.' :
          'Ollama ranks observations that NORTH derives from case evidence. The available events do not establish intent.'}</p>
        <button type="button" disabled={busy} onClick={requestDraft}>{busy ? 'Drafting…' : 'Generate draft'}</button>
      </>}
      {draftProvider && <p role="status">{draftProvider === 'cloud-ai' ? 'Prioritized by cloud AI' :
        draftProvider === 'ai_limit' ? 'The workspace reached its hourly AI limit. This brief uses recorded evidence.' :
          draftProvider === 'ai_capacity' ? 'Cloud AI is at capacity. This brief uses recorded evidence.' :
          draftProvider === 'ai_disabled' ? 'Cloud AI is disabled. This brief uses recorded evidence.' :
          draftProvider === 'ai_output' ? 'Cloud AI returned an invalid ranking. This brief uses recorded evidence.' :
          draftProvider === 'ai_unavailable' ? 'Cloud AI did not complete the request. This brief uses recorded evidence.' :
          'Generated from recorded evidence'}</p>}
      {message && <p role="status">{message}</p>}
      {claims.length > 0 && <ul>{claims.map((claim, index) => (
        <li key={index}>{claim.text}{' '}{claim.evidence_ids.map((id, position) => (
          <a className="citation" key={id + position} href={evidenceAnchor + id}
            onClick={(event) => reopenCitation(event, id)}>{id.slice(0, 8)}</a>
        ))}</li>
      ))}</ul>}
    </section>
  </>;
}

function RelatedEvidence({ event }: { event: RelatedEvent }) {
  const [open, setOpen] = useState(false);
  const [body, setBody] = useState<Evidence | null>(null);
  const [failed, setFailed] = useState(false);
  useEffect(() => {
    if (!open || body) return;
    const request = new AbortController();
    fetch('/api/events/' + event.id + '?source=' + encodeURIComponent(event.source_id),
      { signal: request.signal }).then((response) => {
      if (!response.ok) throw new Error('Evidence unavailable');
      return response.json();
    }).then(setBody).catch(() => { if (!request.signal.aborted) setFailed(true); });
    return () => request.abort();
  }, [open, body, event.id, event.source_id]);

  return <details onToggle={(toggle) => {
    setOpen(toggle.currentTarget.open);
    if (toggle.currentTarget.open) setFailed(false);
  }}>
    <summary>Open evidence</summary>
    {body ? <pre>{JSON.stringify(body.raw ?? body, null, 2)}</pre> :
      <p>{failed ? 'Evidence is unavailable.' : 'Loading evidence…'}</p>}
  </details>;
}

createRoot(document.getElementById('root')!).render(cloud ?
  <CloudGate>{(source, openCollectors, controls, panel) =>
    <App key={source ?? ''} source={source} openCollectors={openCollectors} controls={controls} panel={panel} />}</CloudGate> : <App />);
