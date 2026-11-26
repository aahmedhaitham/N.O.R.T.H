import { TimeDisplay } from './TimeDisplay';
import { SelectControl } from './SelectControl';
import { useEffect, useState } from 'react';
import { eventNames } from './eventNames';
import { SavedSearches } from './SavedSearches';
import { pollVisible } from './pollVisible';
import type { ChartSelection } from './OverviewCharts';

type Event = {
  id: string; timestamp: string; kind: number; host: string; process: string;
  target: string; destination: string; source_ip?: string; raw: unknown;
};
type Page = { events: Event[]; next: string | null; coverage?: 'sysmon_unavailable' };
const pageSize = 25;

function cursor(event: Event) {
  return event.timestamp + '|' + event.id;
}

type Criteria = { search: string; kind: string };
type Filter = Criteria & { before: string | null };

function staticPage(events: Event[], filter: Filter): Page {
  const needle = filter.search.toLowerCase();
  const ordered = events.filter((event) =>
    (!filter.kind || String(event.kind) === filter.kind) &&
    (!needle || JSON.stringify(event).toLowerCase().includes(needle)) &&
    (!filter.before || cursor(event) < filter.before)
  ).sort((a, b) => cursor(a) === cursor(b) ? 0 : cursor(a) < cursor(b) ? 1 : -1);
  return {
    events: ordered.slice(0, pageSize),
    next: ordered.length > pageSize ? cursor(ordered[pageSize - 1]) : null,
  };
}

export function Events({ portfolio, source, initialSearch, openNetwork, canSave, chartSelection, clearChartSelection }: {
  portfolio: boolean; source: string | null; initialSearch: string; openNetwork: () => void; canSave: boolean;
  chartSelection?: ChartSelection | null;
  clearChartSelection?: () => void;
}) {
  const [search, setSearch] = useState(initialSearch);
  const [kind, setKind] = useState('');
  const [criteria, setCriteria] = useState<Criteria>({ search: initialSearch, kind: '' });
  const [cursors, setCursors] = useState<string[]>([]);
  const [attempt, setAttempt] = useState(0);
  const before = cursors.at(-1) ?? null;
  const [page, setPage] = useState<Page | null>(null);
  const [error, setError] = useState(false);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const selected = page?.events.find((item) => item.id === selectedId) ?? page?.events[0];

  useEffect(() => {
    const filter = { ...criteria, before };
    if (chartSelection) {
      setPage(staticPage(chartSelection.events, filter));
      setError(false);
      return;
    }
    const controller = new AbortController();
    async function load() {
      try {
        const query = new URLSearchParams({ limit: String(pageSize) });
        if (source) query.set('source', source);
        if (filter.search) query.set('q', filter.search);
        if (filter.kind) query.set('kind', filter.kind);
        if (filter.before) query.set('before', filter.before);
        const response = await fetch(portfolio ? '/demo/events.json' : '/api/events?' + query, {
          signal: controller.signal, cache: 'no-store',
        });
        if (!response.ok) throw new Error('Event request failed');
        const data = await response.json();
        if (!controller.signal.aborted) {
          setPage(portfolio ? staticPage(data, filter) : data);
          setError(false);
        }
      } catch {
        if (!controller.signal.aborted) setError(true);
      }
    }
    const stop = pollVisible(load, portfolio || before ? 0 : 10000);
    return () => {
      controller.abort();
      stop();
    };
  }, [criteria, before, attempt, portfolio, source, chartSelection]);

  function resetResults() {
    setPage(null);
    setError(false);
    setSelectedId(null);
  }

  function goToPage(next: string[]) {
    resetResults();
    setCursors(next);
  }

  function applyCriteria(query: string, eventType: string) {
    setSearch(query);
    setKind(eventType);
    resetResults();
    setCursors([]);
    setCriteria({ search: query, kind: eventType });
  }

  function pivot(value: string) {
    applyCriteria(value.slice(0, 200), '');
  }

  return <main className="event-explorer">
    <header className="dashboard-heading">
      <h1>IRIS <span className="workspace-title">Event explorer</span></h1>
    </header>
    {chartSelection && <div className="panel chart-filter"><span>Chart filter: {chartSelection.label}</span>
      <button type="button" onClick={() => { applyCriteria('', ''); clearChartSelection?.(); }}>Clear chart filter</button></div>}
    <section className="panel iris-filters">
      <form className="event-filters" aria-label="Filter events" onSubmit={(event) => {
        event.preventDefault();
        applyCriteria(search.trim(), kind);
      }}>
        <label>Search event data
          <input type="search" placeholder="Hostname, process, IP address, or keyword"
            maxLength={200} value={search} onChange={(event) => setSearch(event.target.value)} />
        </label>
        <label>Event type
          <SelectControl label="Event type" value={kind} onChange={setKind}
            options={[{ value: '', label: 'All types' }, ...Object.entries(eventNames).map(([value, label]) => ({ value, label }))]} />
        </label>
        <button type="submit">Apply filters</button>
      </form>
    </section>
    {canSave && <SavedSearches query={criteria.search} kind={criteria.kind} apply={(item) => applyCriteria(item.query, item.kind)} />}
    <section className="panel" aria-labelledby="event-results">
      <header className="event-results-heading">
        <h2 id="event-results">Event results</h2>
        {page && page.coverage !== 'sysmon_unavailable' && <span className="reference">
          {page.events.length} {page.events.length === 1 ? 'event' : 'events'} shown
        </span>}
      </header>
      {(criteria.search || criteria.kind) && <div className="event-active-filters" aria-label="Applied filters" role="group">
        {criteria.search && <button type="button" aria-label={`Remove search filter: ${criteria.search}`}
          onClick={() => applyCriteria('', criteria.kind)}>{criteria.search} <span aria-hidden="true">×</span></button>}
        {criteria.kind && <button type="button" aria-label="Remove event type filter"
          onClick={() => applyCriteria(criteria.search, '')}>{eventNames[Number(criteria.kind)] ?? 'Event ' + criteria.kind} <span aria-hidden="true">×</span></button>}
      </div>}
      {error && <div className="event-pagination">
        <p role="status">The event feed is temporarily unavailable.</p>
        <button type="button" onClick={() => { setError(false); setAttempt((value) => value + 1); }}>Retry</button>
      </div>}
      {!error && !page && <p role="status">Loading events…</p>}
      {page?.coverage === 'sysmon_unavailable' ? <div>
        <h2>Windows events are unavailable</h2>
        <p>NORTH needs a readable Sysmon event log. The network view is still available.</p>
        <button onClick={openNetwork}>Open ATLAS network inventory</button>
      </div> : page?.events.length === 0 && <p>{criteria.kind || criteria.search ? 'No events match these filters.' : 'No events are available yet.'}</p>}
      {selected && <div className="iris-split">
        <ul className="event-list" aria-label="Collected events">{page?.events.map((event) => {
          const observed = event.target || event.destination || event.source_ip || event.process;
          return <li key={event.id}>
            <button type="button" className="event-row" aria-pressed={selected.id === event.id}
              aria-controls="iris-evidence" onClick={() => setSelectedId(event.id)}>
              <span><strong>{eventNames[event.kind] ?? 'Event ' + event.kind}</strong>
                {observed && <span className="event-observation" title={observed}>{observed}</span>}
              </span>
              <span className="event-host">{event.host}</span>
              <TimeDisplay value={event.timestamp} />
            </button>
          </li>;
        })}</ul>
        <section className="iris-evidence" id="iris-evidence" aria-labelledby="iris-evidence-title">
          <h3 id="iris-evidence-title">{eventNames[selected.kind] ?? 'Event ' + selected.kind}</h3>
          <dl>
            <dt>Host</dt><dd>{selected.host || 'Unavailable'}</dd>
            <dt>Observed value</dt><dd>{selected.target || selected.destination || selected.source_ip || selected.process || 'Unavailable'}</dd>
            <dt>Evidence ID</dt><dd><code>{selected.id}</code></dd>
          </dl>
          <div className="case-links" aria-label="Find related events">
            {selected.host && <button type="button" onClick={() => pivot(selected.host)}>Find host events</button>}
            {selected.process && <button type="button" onClick={() => pivot(selected.process)}>Find this process</button>}
            {(selected.destination || selected.source_ip) && <button type="button" onClick={() => pivot(selected.destination || selected.source_ip || '')}>Find this address</button>}
          </div>
          <h4>Raw evidence</h4>
          <pre tabIndex={0}>{JSON.stringify(selected.raw, null, 2)}</pre>
        </section>
      </div>}
      {(before || page?.next) && <nav className="event-pagination" aria-label="Event pages">
        <button type="button" disabled={!before} onClick={() => goToPage(cursors.slice(0, -1))}>Newer events</button>
        <span className="reference" aria-live="polite">Page {cursors.length + 1}</span>
        <button type="button" disabled={!page?.next}
          onClick={() => { if (page?.next) goToPage([...cursors, page.next]); }}>Older events</button>
        {cursors.length > 1 && <button type="button" onClick={() => goToPage([])}>Back to newest</button>}
      </nav>}
    </section>
  </main>;
}
