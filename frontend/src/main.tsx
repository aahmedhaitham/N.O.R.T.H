import { feedbackMessages } from './messages';
import { clientMessages } from './messages';
import { mainMessages as strings, formatMessage } from './messages';
import { TimeDisplay } from './TimeDisplay';
import { useCallback, useEffect, useRef, useState, type CSSProperties } from 'react';
import { createRoot } from 'react-dom/client';
import { Background, Controls, ReactFlow } from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import './style.css';
import './shell.css';
import { Network, type AtlasTarget } from './Network';
import { Events } from './Events';
import { eventNames } from './messages';
import { Dashboard } from './Dashboard';
import { Detections } from './Detections';
import { ProcessTree } from './ProcessTree';
import { DisplayModeControl, DisplayModeProvider } from './DisplayMode';
import { simpleMessages as simpleText } from './messages';
import { InstallApp } from './InstallApp';
import { CloudGate, type CloudToolbar, type CollectorFleet, type WorkspacePanel } from './CloudGate';
import { CaseReview } from './CaseReview';
import { AccountMenu } from './ShellControls';
import { PageMotion } from './InterfaceMotion';
import type { ChartSelection } from './OverviewCharts';
import { SelectControl } from './SelectControl';
import * as Tooltip from '@radix-ui/react-tooltip';
import { Activity, FolderSearch, LayoutDashboard, Network as NetworkIcon, Search, ShieldCheck } from 'lucide-react';
import { pollVisible } from './pollVisible';
import { readWorkspacePreference, writeWorkspacePreference } from './workspaceSession';

type Evidence = {
  id: string; timestamp: string; kind: number; process: string;
  target: string; destination: string; source_ip?: string; raw: unknown;
  process_guid?: string; parent_guid?: string;
};
type Case = {
  id: string; title: string; host: string; asset_id: string; summary: string;
  review_status?: 'open' | 'investigating' | 'resolved';
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
if (desktopLocal) document.title = feedbackMessages.northThisComputer;

const allNavigation = [
  { id: 'dashboard', label: strings.overview, detail: strings.securityDashboard },
  { id: 'network', label: strings.atlas, detail: strings.networkInventory },
  { id: 'events', label: strings.iris, detail: strings.eventExplorer },
  { id: 'cases', label: strings.echo, detail: strings.investigations },
  { id: 'detections', label: strings.detections, detail: strings.rulesAndAttCkCoverage },
] as const;

type View = (typeof allNavigation)[number]['id'];
const navigation = allNavigation.filter(({ id }) => id !== 'detections' || (!cloud && !publicDemo));

const navigationIcons = { dashboard: LayoutDashboard, network: NetworkIcon, events: Activity, cases: FolderSearch,
  detections: ShieldCheck };

function NavigationIcon({ view }: { view: View }) {
  const Icon = navigationIcons[view];
  return <Icon className="nav-icon" aria-hidden="true" strokeWidth={1.65} />;
}

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
      <Search size={15} aria-hidden="true" /><span>{strings.searchNorth}</span><kbd aria-hidden="true">{apple ? strings.k : strings.ctrlK}</kbd>
    </button>
    <dialog ref={dialog} className="quick-nav" aria-labelledby="quick-nav-title" onClose={() => setQuery('')}>
      <div className="quick-nav-heading">
        <h2 id="quick-nav-title">{strings.goToAPage}</h2>
        <button type="button" onClick={() => dialog.current?.close()}>{strings.close}</button>
      </div>
      <form className="quick-nav-search" onSubmit={(event) => {
        event.preventDefault();
        if (matches[0]) goTo(matches[0].id);
      }}>
        <input ref={searchInput} type="search" aria-label={strings.findAPage} placeholder={strings.findAPage}
          value={query} onChange={(event) => setQuery(event.target.value)} />
      </form>
      <ul className="quick-nav-results">
        {matches.map((item) => <li key={item.id}>
          <button type="button" aria-current={item.id === view ? 'page' : undefined} onClick={() => goTo(item.id)}>
            <NavigationIcon view={item.id} />
            <strong>{item.label}</strong><small>{item.detail}</small>
          </button>
        </li>)}
      </ul>
      {matches.length === 0 && <p role="status">{strings.noMatchingPages}</p>}
    </dialog>
  </>;
}

function App({ source = null, openCollectors, controls, fleet, panel }: {
  source?: string | null;
  openCollectors?: () => void;
  controls?: CloudToolbar;
  fleet?: CollectorFleet;
  panel?: WorkspacePanel;
}) {
  const [view, updateView] = useState<View>(() => {
    const saved = readWorkspacePreference('view');
    return navigation.find((item) => item.id === saved)?.id ?? 'dashboard';
  });
  const handledCitation = useRef('');
  const viewContent = useRef<HTMLDivElement>(null);
  const [eventSearch, setEventSearch] = useState('');
  const [chartSelection, setChartSelection] = useState<ChartSelection | null>(null);
  const [networkTarget, setNetworkTarget] = useState<AtlasTarget | null>(null);
  const [cases, setCases] = useState<Case[]>([]);
  const [caseSearch, setCaseSearch] = useState('');
  const [selected, updateSelected] = useState(() => {
    const saved = readWorkspacePreference('case');
    const prefix = (source ?? '') + ':';
    return saved.startsWith(prefix) ? saved.slice(prefix.length) : '';
  });
  const [online, setOnline] = useState(false);
  const [loaded, setLoaded] = useState(false);
  const [loadError, setLoadError] = useState(false);
  const [localSettings, setLocalSettings] = useState(false);
  const incident = cases.find((item) => item.id === selected) ?? cases[0];
  const caseQuery = caseSearch.trim().toLowerCase();
  const matchingCases = caseQuery ? cases.filter((item) =>
    [item.title, item.host].some((value) => value.toLowerCase().includes(caseQuery))) : cases;
  const sourceQuery = source ? '?source=' + encodeURIComponent(source) : '';
  const networkEndpoint = portfolio ? '/demo/network.json' : '/api/network' + sourceQuery;

  useEffect(() => {
    if (viewContent.current) viewContent.current.scrollTop = 0;
  }, [view, panel?.title]);

  function setView(next: View) {
    panel?.close();
    setLocalSettings(false);
    setNetworkTarget(null);
    updateView(next);
    writeWorkspacePreference('view', next);
  }

  function setSelected(id: string) {
    updateSelected(id);
    writeWorkspacePreference('case', (source ?? '') + ':' + id);
  }

  function openCase(id: string) {
    setCaseSearch('');
    setSelected(id);
    setView('cases');
  }

  function openEvents(search: string) {
    setChartSelection(null);
    setEventSearch(search.slice(0, 200));
    setView('events');
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
      async function update() {
        try {
          const response = await fetch('/api/cases' + sourceQuery, { signal: controller.signal, cache: 'no-store' });
          if (!response.ok) throw new Error(clientMessages.cloudCaseFeedUnavailable);
          const items: Case[] = await response.json();
          if (!controller.signal.aborted) {
            setCases(items); setLoaded(true); setOnline(true); setLoadError(false);
          }
        } catch {
          if (!controller.signal.aborted) { setOnline(false); setLoadError(true); }
        }
      }
      const stop = pollVisible(update, 10000);
      return () => { controller.abort(); stop(); };
    }
    if (portfolio) {
      const controller = new AbortController();
      fetch('/demo/cases.json', { signal: controller.signal })
        .then((response) => {
          if (!response.ok) throw new Error(clientMessages.demoCaseDataUnavailable);
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
      <header className="topbar">
        <div className="toolbar-left">{controls?.collector ?? <strong className="toolbar-brand">{strings.north}</strong>}</div>
        <QuickNavigation view={panel || localSettings ? undefined : view} open={setView} />
        <div className="toolbar-right">
          <InstallApp />
          <span role="status" title={controls?.notice || undefined}
            aria-label={desktopLocal ? strings.localData : cloud ? controls?.interrupted ? strings.cloudConnectionInterrupted :
              online ? strings.cloudReady : strings.connectingToCloud : strings.feedStatus}
            className={(online || portfolio) && !controls?.interrupted ? 'status online' : 'status'}>
            <span>{desktopLocal ? strings.localData : cloud ? (controls?.interrupted ? strings.cloudInterrupted : online ? strings.cloudReady : strings.connecting) :
              portfolio || publicDemo ? strings.sampleData : online ? strings.liveFeed : strings.connecting}</span>
          </span>
          <AccountMenu actions={controls?.actions} localSettings={!controls?.actions ? () => setLocalSettings(true) : undefined} />
        </div>
      </header>
      <Tooltip.Provider delayDuration={220}>
        <nav className="console-nav" aria-label={strings.console}
          style={{ '--nav-position': Math.max(0, navigation.findIndex((item) => item.id === view)) } as CSSProperties}>
          {!panel && !localSettings && <span className="rail-indicator" aria-hidden="true" />}
          {navigation.map((item) => {
            const count = item.id === 'cases' && loaded ? cases.length : 0;
            return <Tooltip.Root key={item.id}>
              <Tooltip.Trigger asChild><button type="button" className="nav-item"
                aria-label={item.label + (count ? ', ' + count + ' investigations' : '')}
                aria-current={!panel && !localSettings && view === item.id ? 'page' : undefined} onClick={() => setView(item.id)}>
                <NavigationIcon view={item.id} />
                {count > 0 && <span className="rail-badge" aria-hidden="true">{count > 99 ? '99+' : count}</span>}
              </button></Tooltip.Trigger>
              <Tooltip.Portal><Tooltip.Content className="rail-tooltip" side="right" sideOffset={9}>
                <strong>{item.label}</strong><span>{item.detail}</span>
              </Tooltip.Content></Tooltip.Portal>
            </Tooltip.Root>;
          })}
        </nav>
      </Tooltip.Provider>
      <div className="shell-content">
      <div className="view-content" ref={viewContent}>
      {controls?.notice && <p role="status" className="toolbar-notice">{controls.notice}</p>}
      <PageMotion page={panel?.title ?? (localSettings ? 'settings' : view)}>
      {panel?.content}
      {localSettings && <main className="dashboard"><header className="dashboard-heading">
        <h1>{simpleText.settings}</h1><button type="button" onClick={() => setLocalSettings(false)}>{simpleText.back}</button>
      </header><section className="panel"><DisplayModeControl /></section></main>}
      <div className="workspace-pages" hidden={Boolean(panel) || localSettings}>
      {view === 'dashboard' && <Dashboard endpoint={networkEndpoint} cases={cases} loaded={loaded}
        demo={publicDemo} local={desktopLocal} localFindings={!cloud && !publicDemo}
        open={setView} openCase={openCase}
        openDetections={() => setView('detections')}
        fleet={fleet} source={source} manageCollectors={openCollectors}
        openAtlas={(target) => { setView('network'); setNetworkTarget(target); }}
        connect={cloud && !source ? openCollectors : undefined}
        openChart={(selection) => { setEventSearch(''); setChartSelection(selection); setView('events'); }} />}
      {view === 'detections' && <Detections />}
      <div hidden={view !== 'network'}>
        <Network endpoint={view === 'network' ? networkEndpoint : ''} openCase={openCase} openEvents={openEvents}
          target={networkTarget} onTarget={setNetworkTarget} demo={publicDemo} readOnly={publicDemo || cloud}
          labelSource={cloud ? source : null} visible={view === 'network' && !panel} />
      </div>
      {view === 'events' && <Events portfolio={portfolio} source={source} initialSearch={eventSearch}
        chartSelection={chartSelection} clearChartSelection={() => setChartSelection(null)}
        canSave={cloud} openNetwork={() => setView('network')} />}
      {view === 'cases' && <div className="workspace">
        <aside className="echo-case-list" aria-label={strings.investigations}>
          <h2>{strings.investigations2}<span>{loaded ? (caseQuery ? `${matchingCases.length} / ${cases.length}` : cases.length) : ''}</span></h2>
          <label className="echo-case-search">
            <span>{strings.findAnInvestigation}</span>
            <input type="search" placeholder={strings.titleOrHost} value={caseSearch}
              onChange={(event) => setCaseSearch(event.target.value)} />
          </label>
          {caseQuery && !matchingCases.length && <p className="echo-case-empty" role="status">{strings.noInvestigationsMatch}</p>}
          {caseQuery && incident && !matchingCases.includes(incident) &&
            <p className="echo-case-empty">{strings.theOpenInvestigationIsOutsideThisFilter}</p>}
          {matchingCases.map((item) => (
            <button type="button" key={item.id} className="case" aria-pressed={item.id === incident?.id}
              onClick={() => setSelected(item.id)}>
              <strong>{item.title}</strong>
              <small>{item.host} · {item.evidence.length} {item.evidence.length === 1 ? strings.event : strings.events}</small>
            </button>
          ))}
        </aside>
        <main className="echo-workspace">
          {incident ? <Investigation key={incident.id} incident={incident} sourceQuery={sourceQuery} visible={!panel}
            openEvents={openEvents} /> :
            <section className="panel"><h1>{loadError ? strings.casesCouldNotLoad : loaded ? strings.noInvestigationsYet : strings.waitingForTelemetry}</h1>
              {loaded && !loadError && <p>{strings.investigationsAppearWhenNorthLinksRelatedEvents}</p>}
              {(loaded || loadError) && <button onClick={() => setView('events')}>{strings.openIrisEvents}</button>}
            </section>}
        </main>
      </div>}
      </div>
      </PageMotion>
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
        if (!response.ok) throw new Error(clientMessages.couldNotLoadRelatedEvents);
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
      if (!response.ok) throw new Error(body.detail || feedbackMessages.draftRequestFailed);
      setClaims(body.claims);
      setDraftProvider(body.reason ?? body.provider ?? '');
    } catch (error) {
      setMessage(error instanceof Error ? error.message : strings.draftRequestFailed);
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
        <button onClick={() => openEvents(incident.host)}>{strings.findHostEventsInIris}</button>
        <a className="button" download={portfolio ? 'north-' + incident.id + '.md' : undefined}
          href={portfolio ? '/demo/' + incident.id + '.md' : '/api/cases/' + incident.id + '/report' + sourceQuery}>{strings.exportReport}</a>
      </div>
      <p className="echo-case-summary">{incident.summary}</p>
    </section>
    <div className="echo-evidence-grid">
      <section className="panel echo-timeline">
        <h2>{strings.evidenceTimeline}</h2>
        {last < 0 ? <p>{strings.noEvidenceEventsInThisCase}</p> :
          <div className="replay" role="group" aria-label={strings.timelinePlayback}>
            <div className="replay-actions">
              <button disabled={active <= 0} onClick={() => seek(active - 1)} aria-label={strings.previousEvent}>‹</button>
              <button disabled={last === 0} onClick={() => {
                if (!playing && active === last) setCursor(0);
                setPlaying(!playing);
              }}>{playing ? strings.pause : strings.play}</button>
              <button disabled={active >= last} onClick={() => seek(active + 1)} aria-label={strings.nextEvent}>›</button>
              <SelectControl label={strings.replaySpeed} value={String(speed)} onChange={(value) => setSpeed(Number(value))}
                options={[0.5, 1, 2].map((value) => ({ value: String(value), label: value + '×' }))} />
            </div>
            <div className="replay-position">
              <input aria-label={strings.timelinePosition} aria-valuetext={formatMessage(strings.event0Of1, active + 1, last + 1)}
                type="range" min="0" max={last} value={active} disabled={last === 0}
                onChange={(event) => seek(Number(event.target.value))} />
              <span>{strings.event2}{active + 1}{strings.of}{last + 1}</span>
            </div>
          </div>}
        <ol className="timeline">
          {incident.evidence.map((item, index) => (
            <li id={'event-' + item.id} key={item.id} aria-current={index === active ? 'step' : undefined}>
              <TimeDisplay value={item.timestamp} />
              <strong>{eventNames[item.kind] ?? formatMessage(strings.event3, item.kind)}</strong>
              <small>{item.target || item.destination || item.source_ip || item.process}</small>
              <details><summary>{strings.rawEvidence}</summary><pre>{JSON.stringify(item.raw, null, 2)}</pre></details>
            </li>
          ))}
        </ol>
      </section>
      <section className="panel echo-connections">
        <ProcessTree evidence={incident.evidence} reveal={revealEvidence} />
        <h2>{strings.observedConnections}</h2>
        {incident.links.length > 0 && <div className="graph">
          <ReactFlow key={destinations.join(',')} nodes={nodes} edges={edges}
            fitView fitViewOptions={{ maxZoom: 1 }} nodesDraggable={false} nodesConnectable={false}>
            <Background gap={18} /><Controls showInteractive={false} />
          </ReactFlow>
        </div>}
        {incident.links.map((link) => <p key={link.evidence_id} className="reference">
          {link.destination}{' '}<a href={evidenceAnchor + link.evidence_id}
            onClick={(event) => reopenCitation(event, link.evidence_id)}>{strings.viewEvidence}</a>
        </p>)}
        {incident.links.length === 0 && <p>{strings.noConnectionEventsForThisCase}</p>}
      </section>
    </div>
    {cloud && <CaseReview endpoint={'/api/cases/' + incident.id + '/review' + sourceQuery} />}
    {cloud && <section className="panel">
      <h2>{strings.relatedEventsAcrossCollectors}</h2>
      <p>{strings.matchesShareAnIpAddressWithinFive}</p>
      {relatedError && <p role="status">{strings.relatedEventsAreUnavailable}</p>}
      {!relatedError && !related && <p>{strings.checkingOtherCollectors}</p>}
      {related?.length === 0 && <p>{strings.noMatchingEventsFromAnotherCollector}</p>}
      <ul className="network-list">{related?.map((event) => <li key={event.source_id + '/' + event.id + '/' + event.address}>
        <strong>{eventNames[event.kind] ?? formatMessage(strings.event3, event.kind)}</strong>
        <small>{event.collector}{event.host ? ' · ' + event.host : ''} · {event.address} · <TimeDisplay value={event.timestamp} /></small>
        <RelatedEvidence event={event} />
      </li>)}</ul>
    </section>}
    <section className="panel">
      <span className="module">{strings.irisAnalystReview}</span>
      <h2>{publicDemo || desktopLocal ? strings.reviewCaseEvidence : cloud ? strings.evidenceBrief : strings.localAiDraft}</h2>
      {desktopLocal ? <p>{strings.openAnyEventInTheTimelineTo}</p> :
        publicDemo ? <p>{strings.thisDemoUsesABundledCaseOpen}</p> : <>
        <p>{cloud ? strings.summarizeRecordedActivityAndOpenTheCited :
          strings.ollamaRanksObservationsThatNorthDerivesFrom}</p>
        <button type="button" disabled={busy} onClick={requestDraft}>{busy ? strings.drafting : strings.generateDraft}</button>
      </>}
      {draftProvider && <p role="status">{draftProvider === 'cloud-ai' ? strings.prioritizedByCloudAi :
        draftProvider === 'ai_limit' ? strings.theWorkspaceReachedItsHourlyAiLimit :
          draftProvider === 'ai_capacity' ? strings.cloudAiIsAtCapacityThisBrief :
          draftProvider === 'ai_disabled' ? strings.cloudAiIsDisabledThisBriefUses :
          draftProvider === 'ai_output' ? strings.cloudAiReturnedAnInvalidRankingThis :
          draftProvider === 'ai_unavailable' ? strings.cloudAiDidNotCompleteTheRequest :
          strings.generatedFromRecordedEvidence}</p>}
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
      if (!response.ok) throw new Error(clientMessages.evidenceUnavailable);
      return response.json();
    }).then(setBody).catch(() => { if (!request.signal.aborted) setFailed(true); });
    return () => request.abort();
  }, [open, body, event.id, event.source_id]);

  return <details onToggle={(toggle) => {
    setOpen(toggle.currentTarget.open);
    if (toggle.currentTarget.open) setFailed(false);
  }}>
    <summary>{strings.openEvidence}</summary>
    {body ? <pre>{JSON.stringify(body.raw ?? body, null, 2)}</pre> :
      <p>{failed ? strings.evidenceIsUnavailable : strings.loadingEvidence}</p>}
  </details>;
}

const root = createRoot(document.getElementById('root')!);
async function startApp() {
  if (!desktop && !cloud && !publicDemo) {
    try {
      const response = await fetch('/api/local-session', {
        method: 'POST', headers: { 'X-North-Local-Session': 'start' }, cache: 'no-store',
      });
      if (!response.ok) throw new Error(clientMessages.localSessionUnavailable);
    } catch {
      root.render(<main><h1>{strings.localNorthIsUnavailable}</h1>
        <p>{strings.startTheLocalNorthServiceThenReload}</p>
        <button type="button" onClick={() => location.reload()}>{strings.reload}</button></main>);
      return;
    }
  }
  root.render(<DisplayModeProvider>{cloud ?
    <CloudGate>{(source, openCollectors, controls, fleet, panel) =>
      <App key={source ?? ''} source={source} openCollectors={openCollectors} controls={controls} fleet={fleet} panel={panel} />}</CloudGate> : <App />}</DisplayModeProvider>);
}
void startApp();
