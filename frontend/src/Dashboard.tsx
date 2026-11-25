import { groupNeighbors, useNetworkInventory } from './Network';
import { eventNames } from './eventNames';

type CaseSummary = { id: string; title: string; host: string; evidence: { timestamp: string }[] };
type Section = 'cases' | 'network' | 'events';

const collectorStatus = {
  starting: 'Connecting',
  ready: 'Collecting',
  unavailable: 'Needs attention',
  disabled: 'Disabled',
};

export function Dashboard({ endpoint, cases, loaded, demo, local, open, openCase, connect }: {
  endpoint: string;
  cases: CaseSummary[];
  loaded: boolean;
  demo: boolean;
  local: boolean;
  open: (section: Section) => void;
  openCase: (id: string) => void;
  connect?: () => void;
}) {
  const { inventory, fetchError } = useNetworkInventory(endpoint);
  const total = inventory?.assets.reduce((count, asset) => count + asset.events, 0);
  const nearby = inventory?.neighbors?.state === 'ready' ? groupNeighbors(inventory.neighbors.records).length : undefined;
  const sysmonUnavailable = inventory?.sysmon?.state === 'unavailable';
  const metrics: { label: string; count?: number; section: Section }[] = [
    { label: local ? 'Nearby devices' : 'Reporting devices',
      count: local ? nearby : inventory?.assets.length, section: 'network' },
    { label: local ? 'Recent Windows events' : 'Collected events', count: local && sysmonUnavailable ? undefined : total, section: 'events' },
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
  const newDevices = inventory?.device_findings?.unreviewed ?? 0;
  const coverageIssue = collectors.some((item) => item.status?.state === 'unavailable');
  const activity = inventory?.activity;
  const buckets = activity?.buckets ?? [];
  const highest = Math.max(1, ...buckets.map((item) => item.count));
  const eventTypes = activity?.types ?? [];
  const eventMax = Math.max(1, ...eventTypes.map((item) => item.count));
  const axisLabel = (value: string) => new Date(value).toLocaleString(undefined,
    activity?.interval === 'day' ? { month: 'short', day: 'numeric', timeZone: 'UTC' } :
      { hour: '2-digit', minute: '2-digit', hour12: false, timeZone: 'UTC' });

  return <main className="dashboard">
    <header className="dashboard-heading">
      <h1>Security overview</h1>
    </header>
    {connect && <section className="panel dashboard-connect">
      <div><h2>Connect your first collector</h2>
        <p>Pair a Windows device to start receiving network observations and security events.</p></div>
      <button className="primary-action" onClick={connect}>Set up collector</button>
    </section>}
    {!connect && <>
    {fetchError && <p role="status">The device and event counts could not refresh.</p>}
    <section className="dashboard-metrics" aria-label="Security overview counts">
      {metrics.map((metric) => <button type="button" className="dashboard-metric" key={metric.label}
        onClick={() => open(metric.section)}>
        <span>{metric.label}</span>
        <strong>{metric.count?.toLocaleString() ?? (inventory || fetchError ? '—' : '…')}</strong>
      </button>)}
    </section>
    <div className="dashboard-console">
      <section className="panel dashboard-activity">
        <header className="dashboard-section-heading">
          <h2>Telemetry activity</h2>
          {activity && <span>Events per {activity.interval} · UTC</span>}
        </header>
        {buckets.length ? <>
          <div className="activity-plot">
          <div className="activity-scale" aria-hidden="true">
            <span>{highest}</span><span>{highest >= 2 && Number.isInteger(highest / 2) ? highest / 2 : ''}</span><span>0</span>
          </div>
          <div className="activity-chart" aria-label="Collected events by time" role="list">
            {buckets.map((item) => <div className="activity-slot" role="listitem" key={item.start}
              aria-label={axisLabel(item.start) + ' UTC: ' + item.count + ' events'}
              title={axisLabel(item.start) + ' UTC · ' + item.count + ' events'}>
              <div className="activity-bar" style={{ height: item.count ? `${item.count / highest * 100}%` : '2px' }} />
            </div>)}
          </div>
          </div>
          <div className="activity-axis">
            <span>{axisLabel(buckets[0].start)} UTC</span>
            <span>{axisLabel(buckets[buckets.length - 1].start)} UTC</span>
          </div>
        </> : <p>{inventory ? 'Activity appears after NORTH receives events.' : 'Loading activity…'}</p>}
      </section>
      <div className="dashboard-monitor">
      <section className="panel">
        <h2>Events by type</h2>
        <ul className="event-breakdown">{eventTypes.map((item) => <li key={item.kind}>
          <div><span>{eventNames[item.kind] ?? 'Event ' + item.kind}</span><strong>{item.count.toLocaleString()}</strong></div>
          <div className="breakdown-track" aria-hidden="true"><span style={{ width: `${item.count / eventMax * 100}%` }} /></div>
        </li>)}</ul>
        {!eventTypes.length && <p>{inventory ? 'No event types recorded yet.' : 'Loading event types…'}</p>}
      </section>
      <section className="panel">
        <h2>Needs attention</h2>
        {newDevices > 0 && <p><button className="network-case" onClick={() => open('network')}>
          Review {newDevices} newly observed {newDevices === 1 ? 'device' : 'devices'}
        </button></p>}
        {coverageIssue && <p><button className="network-case" onClick={() => open('network')}>
          Check data source access
        </button></p>}
        {!newDevices && !coverageIssue && <p>{inventory ? 'No device reviews or data source issues reported.' : 'Checking available data sources…'}</p>}
      </section>
      </div>
    </div>
      <section className="panel dashboard-recent">
        <header className="dashboard-section-heading">
          <h2>Recent investigations</h2>
          {latest.length > 0 && <button type="button" onClick={() => open('cases')}>Open ECHO</button>}
        </header>
        {!latest.length && <p>{loaded ? 'No investigations have been recorded yet.' : 'Checking for recent investigations…'}</p>}
        {latest.length > 0 && <table className="investigation-table" aria-label="Recent investigations">
          <thead><tr><th scope="col">Investigation</th><th scope="col">Host</th><th scope="col">Latest event</th></tr></thead>
          <tbody>{latest.map((item) => <tr key={item.id}>
            <td><button onClick={() => openCase(item.id)}>{item.title}</button></td>
            <td>{item.host || '—'}</td>
            <td>{item.timestamp ? <time dateTime={item.timestamp}>{new Date(item.timestamp).toLocaleString()}</time> : '—'}</td>
          </tr>)}</tbody>
        </table>}
      </section>
      <section className="panel dashboard-sources">
        <h2>{local ? 'What NORTH can see on this PC' : 'Data sources'}</h2>
        {local && <p>Nearby devices come from the Windows neighbor cache. Event history comes from the Sysmon log when readable.</p>}
        {demo && <p>This demo uses synthetic evidence.</p>}
        {!local && !demo && !collectors.length && <p>{inventory ? 'No collector health details are available for this feed.' : 'Checking collector status…'}</p>}
        <ul className="coverage-list">{collectors.map(({ label, status }) => status && <li key={label}>
          <span>{label}</span><strong data-state={status.state}>{collectorStatus[status.state]}</strong>
        </li>)}</ul>
      </section>
    {inventory?.device_findings?.baseline_at && (
      <section className="panel">
        <h2>Device history</h2>
        <p>Review devices first observed after the baseline was saved.</p>
        <button onClick={() => open('network')}>Open ATLAS</button>
      </section>
    )}
    </>}
  </main>;
}
