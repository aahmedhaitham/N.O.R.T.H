import { useNetworkInventory } from './Network';

type CaseSummary = { id: string; title: string; host: string; evidence: { timestamp: string }[] };
type Section = 'cases' | 'network' | 'events';

const collectorStatus = {
  starting: 'Connecting',
  ready: 'Collecting',
  unavailable: 'Needs attention',
  disabled: 'Disabled',
};

export function Dashboard({ endpoint, cases, loaded, demo, open, openCase }: {
  endpoint: string;
  cases: CaseSummary[];
  loaded: boolean;
  demo: boolean;
  open: (section: Section) => void;
  openCase: (id: string) => void;
}) {
  const { inventory, fetchError } = useNetworkInventory(endpoint);
  const total = inventory?.assets.reduce((count, asset) => count + asset.events, 0);
  const metrics: { label: string; count?: number; section: Section }[] = [
    { label: 'Reporting devices', count: inventory?.assets.length, section: 'network' },
    { label: 'Collected events', count: total, section: 'events' },
    { label: 'Investigations', count: loaded ? cases.length : undefined, section: 'cases' },
    { label: 'Observed connections', count: inventory?.links.length, section: 'network' },
  ];
  const latest = cases.map((item) => ({
    ...item, timestamp: item.evidence.at(-1)?.timestamp ?? '',
  })).sort((a, b) => b.timestamp.localeCompare(a.timestamp)).slice(0, 5);
  const collectors = [
    { label: 'Network inventory', status: inventory?.neighbors },
    { label: 'Windows events', status: inventory?.sysmon },
  ].filter((item) => item.status && item.status.state !== 'disabled');

  return <main className="dashboard">
    <header className="panel dashboard-heading">
      <h1>Security overview</h1>
      <p>{demo ? 'Explore the sample telemetry and follow it into an investigation.' :
        'See what NORTH has collected, which investigations it opened, and whether your collectors are running.'}</p>
    </header>
    {fetchError && <p role="status">The device and event counts could not refresh.</p>}
    <section className="dashboard-metrics" aria-label="Security overview counts">
      {metrics.map((metric) => <button className="panel dashboard-metric" key={metric.label}
        onClick={() => open(metric.section)}>
        <span>{metric.label}</span>
        <strong>{metric.count?.toLocaleString() ?? '…'}</strong>
        <small>Open {metric.section === 'cases' ? 'investigations' : metric.section}</small>
      </button>)}
    </section>
    <div className="columns">
      <section className="panel dashboard-recent">
        <h2>Recent investigations</h2>
        {!latest.length && <p>{loaded ? 'There are no investigations yet.' : 'Waiting for investigations…'}</p>}
        <ul className="network-list">{latest.map((item) => <li key={item.id}>
          <button onClick={() => openCase(item.id)}>{item.title}</button>
          <small>{item.host}{item.timestamp && ' · ' + new Date(item.timestamp).toLocaleString()}</small>
        </li>)}</ul>
      </section>
      <section className="panel">
        <h2>Collectors</h2>
        {demo && <p>This demo uses synthetic evidence.</p>}
        {!demo && !collectors.length && <p>{inventory ? 'No automatic collectors are active.' : 'Checking collector status…'}</p>}
        <ul className="network-list">{collectors.map(({ label, status }) => status && <li key={label}>
          <strong>{label}</strong>
          <small>{collectorStatus[status.state]}{status.updated_at && ' · Last checked ' + new Date(status.updated_at).toLocaleTimeString()}</small>
        </li>)}</ul>
      </section>
    </div>
  </main>;
}
