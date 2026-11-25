import { useEffect, useState } from 'react';
import { eventNames } from './eventNames';
import { SavedSearches } from './SavedSearches';

type Event = {
  id: string; timestamp: string; kind: number; host: string; process: string;
  target: string; destination: string; source_ip?: string; raw: unknown;
};
type Page = { events: Event[]; next: string | null; coverage?: 'sysmon_unavailable' };
const pageSize = 25;

function cursor(event: Event) {
  return event.timestamp + '|' + event.id;
}

type Filter = { search: string; kind: string; before: string | null };

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

export function Events({ portfolio, source, initialSearch, openNetwork, canSave }: {
  portfolio: boolean; source: string | null; initialSearch: string; openNetwork: () => void; canSave: boolean;
}) {
  const [search, setSearch] = useState(initialSearch);
  const [kind, setKind] = useState('');
  const [filter, setFilter] = useState<Filter>({ search: initialSearch, kind: '', before: null });
  const [page, setPage] = useState<Page | null>(null);
  const [error, setError] = useState(false);

  useEffect(() => {
    const controller = new AbortController();
    let timer: number | undefined;
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
      } finally {
        if (!controller.signal.aborted && !portfolio && !filter.before) {
          timer = window.setTimeout(load, 10000);
        }
      }
    }
    void load();
    return () => {
      controller.abort();
      window.clearTimeout(timer);
    };
  }, [filter, portfolio, source]);

  function changeFilter(next: Filter) {
    setPage(null);
    setError(false);
    setFilter(next);
  }

  function applyCriteria(query: string, eventType: string) {
    setSearch(query);
    setKind(eventType);
    changeFilter({ search: query, kind: eventType, before: null });
  }

  function pivot(value: string) {
    applyCriteria(value.slice(0, 200), '');
  }

  return <main className="event-explorer">
    <section className="panel iris-filters">
      <h1>IRIS <span className="workspace-title">Event explorer</span></h1>
      <p>Search collected telemetry and inspect the original records behind alerts.</p>
      <form className="event-filters" onSubmit={(event) => {
        event.preventDefault();
        changeFilter({ search: search.trim(), kind, before: null });
      }}>
        <label>Search event data
          <input type="search" placeholder="Hostname, process, IP address, or keyword"
            maxLength={200} value={search} onChange={(event) => setSearch(event.target.value)} />
        </label>
        <label>Event type
          <select value={kind} onChange={(event) => setKind(event.target.value)}>
            <option value="">All types</option>
            {Object.entries(eventNames).map(([value, label]) => <option key={value} value={value}>{label}</option>)}
          </select>
        </label>
        <button type="submit">Apply filters</button>
      </form>
    </section>
    {canSave && <SavedSearches query={filter.search} kind={filter.kind} apply={(item) => applyCriteria(item.query, item.kind)} />}
    <section className="panel" aria-labelledby="event-results">
      <header className="event-results-heading">
        <h2 id="event-results">Event results</h2>
        {page && page.coverage !== 'sysmon_unavailable' && <span className="reference">
          {page.events.length} {page.events.length === 1 ? 'event' : 'events'} shown
        </span>}
      </header>
      {(filter.search || filter.kind) && <div className="event-active-filters" aria-label="Applied filters" role="group">
        {filter.search && <button type="button" aria-label={`Remove search filter: ${filter.search}`}
          onClick={() => applyCriteria('', filter.kind)}>{filter.search} <span aria-hidden="true">×</span></button>}
        {filter.kind && <button type="button" aria-label="Remove event type filter"
          onClick={() => applyCriteria(filter.search, '')}>{eventNames[Number(filter.kind)] ?? 'Event ' + filter.kind} <span aria-hidden="true">×</span></button>}
      </div>}
      {error && <p role="status">The event feed is temporarily unavailable.</p>}
      {!error && !page && <p role="status">Loading events…</p>}
      {page?.coverage === 'sysmon_unavailable' ? <div>
        <h2>Windows events are unavailable</h2>
        <p>NORTH needs a readable Sysmon event log. The network view is still available.</p>
        <button onClick={openNetwork}>Open ATLAS network inventory</button>
      </div> : page?.events.length === 0 && <p>{filter.kind || filter.search ? 'No events match these filters.' : 'No events are available yet.'}</p>}
      <ul className="event-list">{page?.events.map((event) => {
        const observed = event.target || event.destination || event.source_ip || event.process;
        return (
        <li key={event.id}>
          <details>
            <summary>
              <span className="event-row">
                <span><strong>{eventNames[event.kind] ?? 'Event ' + event.kind}</strong>
                  {observed && <span className="event-observation" title={observed}>{observed}</span>}
                </span>
                <span className="event-host">{event.host}</span>
                <time dateTime={event.timestamp}>{new Date(event.timestamp).toLocaleString()}</time>
              </span>
            </summary>
            {observed && <p>{observed}</p>}
            <div className="case-links" aria-label="Find related events">
              {event.host && <button onClick={() => pivot(event.host)}>Find host events</button>}
              {event.process && <button onClick={() => pivot(event.process)}>Find this process</button>}
              {(event.destination || event.source_ip) && <button onClick={() => pivot(event.destination || event.source_ip || '')}>Find this address</button>}
            </div>
            <pre>{JSON.stringify(event.raw, null, 2)}</pre>
            <small>Evidence ID {event.id}</small>
          </details>
        </li>
        );
      })}</ul>
      <div className="event-pagination">
        {filter.before && <button onClick={() => changeFilter({ ...filter, before: null })}>Back to newest</button>}
        {page?.next && <button onClick={() => changeFilter({ ...filter, before: page.next })}>Older events</button>}
      </div>
    </section>
  </main>;
}
