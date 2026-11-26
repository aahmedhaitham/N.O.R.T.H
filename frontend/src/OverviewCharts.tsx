import { useEffect, useState } from 'react';
import { ChartBar } from './InterfaceMotion';
import { investigationSeverity } from './investigationSeverity';
import { formatAbsolute } from './TimeDisplay';
import './analytics.css';

export type ChartEvent = {
  id: string; timestamp: string; kind: number; host: string; process: string;
  target: string; destination: string; source_ip?: string; raw: unknown;
};
export type ChartSelection = { label: string; events: ChartEvent[] };
type CaseEvidence = { evidence: { id: string; kind: number }[] };
type Bucket = ChartSelection;
const limit = 100;
const hour = 3600000;
const levels = ['critical', 'high', 'medium', 'low', 'info'] as const;
const weekdays = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];

function grouped(events: ChartEvent[], key: (event: ChartEvent) => string) {
  const groups = new Map<string, ChartEvent[]>();
  for (const event of events) {
    const label = key(event);
    if (!label) continue;
    const bucket = groups.get(label) ?? [];
    bucket.push(event);
    groups.set(label, bucket);
  }
  return groups;
}

function Ranked({ title, items, open }: { title: string; items: Bucket[]; open: (value: Bucket) => void }) {
  return <section className="analytics-chart"><h3>{title}</h3>
    {items.length ? <ul>{items.map((item) => <li key={item.label}><button type="button" onClick={() => open(item)}>
      <span>{item.label}</span><strong>{item.events.length}</strong>
      <span className="analytics-track" style={{ '--ratio': item.events.length / items[0].events.length } as React.CSSProperties} aria-hidden="true" />
    </button></li>)}</ul> : <p className="reference">No matching fields in this event sample.</p>}
  </section>;
}

export function OverviewCharts({ endpoint, source, demo, cases, open }: {
  endpoint: string; source?: string | null; demo: boolean; cases: CaseEvidence[]; open: (value: ChartSelection) => void;
}) {
  const [events, setEvents] = useState<ChartEvent[] | null>(null);
  const [error, setError] = useState(false);
  const [retry, setRetry] = useState(0);
  const [brush, setBrush] = useState([0, 11]);
  useEffect(() => {
    if (!endpoint) { setEvents([]); return; }
    const request = new AbortController();
    const query = new URLSearchParams({ limit: String(limit) });
    if (source) query.set('source', source);
    fetch(endpoint.startsWith('/demo/') ? '/demo/events.json' : '/api/events?' + query,
      { signal: request.signal, cache: 'no-store' }).then(async (response) => {
      if (!response.ok) throw new Error();
      const value = await response.json();
      if (!request.signal.aborted) {
        setError(false);
        setEvents((Array.isArray(value) ? value : value.events).slice(0, limit));
      }
    }).catch(() => { if (!request.signal.aborted) setError(true); });
    return () => request.abort();
  }, [endpoint, retry, source]);

  if (error) return <div role="status">Chart data could not load. <button type="button" onClick={() => { setError(false); setRetry(retry + 1); }}>Retry</button></div>;
  if (!events) return <p role="status"><span className="loading-skeleton" /> Loading chart data…</p>;
  const sample = events.filter((event) => Number.isFinite(Date.parse(event.timestamp)));
  if (!sample.length) return <p className="reference">Charts appear once a collector reports timestamped events.</p>;

  const times = sample.map((event) => Date.parse(event.timestamp));
  const start = Math.floor(Math.min(...times) / hour) * hour;
  const duration = Math.max(hour, Math.ceil((Math.max(...times) - start + 1) / (hour * 12)) * hour);
  const timeline = Array.from({ length: 12 }, (_, index) => ({
    label: formatAbsolute(new Date(start + index * duration).toISOString()),
    events: sample.filter((event) => Math.floor((Date.parse(event.timestamp) - start) / duration) === index),
  }));
  const maxBucket = Math.max(1, ...timeline.map((item) => item.events.length));
  const brushEvents = timeline.slice(brush[0], brush[1] + 1).flatMap((item) => item.events);
  const top = (key: (event: ChartEvent) => string) => [...grouped(sample, key)]
    .map(([label, events]) => ({ label, events })).sort((a, b) => b.events.length - a.events.length).slice(0, 5);
  const evidence = new Map<string, (typeof levels)[number]>();
  for (const incident of cases) {
    const severity = investigationSeverity(incident.evidence);
    for (const item of incident.evidence) {
      const current = evidence.get(item.id) ?? 'info';
      if (levels.indexOf(severity) < levels.indexOf(current)) evidence.set(item.id, severity);
    }
  }
  const severity = grouped(sample, (event) => evidence.get(event.id) ?? 'info');
  let offset = 0;
  const arcs = levels.flatMap((label) => {
    const events = severity.get(label);
    if (!events?.length) return [];
    const length = events.length / sample.length * 100;
    const segment = { label, events, offset, length };
    offset += length;
    return [segment];
  });
  const heat = grouped(sample, (event) => {
    const date = new Date(event.timestamp);
    return date.getUTCDay() + '|' + date.getUTCHours();
  });
  const heatMax = Math.max(1, ...[...heat.values()].map((items) => items.length));

  return <div className="analytics">
    <p className="reference">Latest {sample.length} {demo ? 'available' : 'recorded'} events · Up to {limit} per view</p>
    <section className="analytics-chart">
      <h3>Events over time</h3>
      <div className="analytics-timeline" aria-label="Events over time">
        {timeline.map((item, index) => <button type="button" key={item.label} disabled={!item.events.length}
          data-brushed={index >= brush[0] && index <= brush[1]}
          title={item.label + ' · ' + item.events.length + ' events'} aria-label={item.label + ', ' + item.events.length + ' events'}
          onClick={() => open(item)}><ChartBar ratio={item.events.length / maxBucket} /></button>)}
      </div>
      <div className="analytics-brush">
        <label>From <input type="range" min={0} max={11} value={brush[0]} aria-valuetext={timeline[brush[0]].label}
          onChange={(event) => { const value = Number(event.target.value); setBrush([value, Math.max(value, brush[1])]); }} /></label>
        <label>Through <input type="range" min={0} max={11} value={brush[1]} aria-valuetext={timeline[brush[1]].label}
          onChange={(event) => { const value = Number(event.target.value); setBrush([Math.min(brush[0], value), value]); }} /></label>
        <button type="button" disabled={!brushEvents.length} onClick={() => open({
          label: timeline[brush[0]].label + ' – ' + timeline[brush[1]].label, events: brushEvents,
        })}>Open range in IRIS</button>
      </div>
    </section>
    <div className="analytics-columns">
      <Ranked title="Top processes" items={top((event) => event.process)} open={open} />
      <Ranked title="Top destinations" items={top((event) => event.destination)} open={open} />
      <section className="analytics-chart">
        <h3>Evidence severity</h3>
        <p className="reference">Events outside investigations are shown as informational.</p>
        <div className="analytics-severity">
          <svg className="analytics-donut" viewBox="0 0 72 72" role="group" aria-label="Severity segments">
            {arcs.map((item) => {
              const select = () => open({ label: item.label + ' severity', events: item.events });
              return <circle key={item.label} role="button" tabIndex={0}
                aria-label={item.label + ', ' + item.events.length + ' events'} cx={36} cy={36} r={27}
                pathLength={100} strokeDasharray={item.length + ' ' + (100 - item.length)}
                strokeDashoffset={-item.offset} stroke={'var(--severity-' + item.label + ')'} onClick={select}
                onKeyDown={(event) => { if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); select(); } }}>
                <title>{item.label + ' · ' + item.events.length + ' events'}</title>
              </circle>;
            })}
          </svg>
          <ul>{levels.map((label) => {
            const events = severity.get(label) ?? [];
            return <li key={label}><button type="button" className="severity-label" data-severity={label}
              disabled={!events.length} onClick={() => open({ label: label + ' severity', events })}>{label} <strong>{events.length}</strong></button></li>;
          })}</ul>
        </div>
      </section>
    </div>
    <section className="analytics-chart">
      <h3>Activity by day and hour <small>UTC</small></h3>
      <div className="analytics-heat" role="group" aria-label="Activity by day and hour UTC">
        {weekdays.map((day, row) => <div className="analytics-heat-row" key={day}><span>{day}</span>
          {Array.from({ length: 24 }, (_, hour) => {
            const events = heat.get(row + '|' + hour) ?? [];
            const label = day + ' ' + String(hour).padStart(2, '0') + ':00 UTC';
            return <button type="button" key={hour} disabled={!events.length} title={label + ' · ' + events.length}
              aria-label={label + ', ' + events.length + ' events'} style={{ '--heat': events.length ? 22 + 78 * events.length / heatMax + '%' : '0%' } as React.CSSProperties}
              onClick={() => open({ label, events })} />;
          })}
        </div>)}
      </div>
    </section>
  </div>;
}
