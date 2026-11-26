import { Activity, CircleAlert, Clock3, Network, Server } from 'lucide-react';
import { groupNeighbors, useNetworkInventory, type AtlasTarget } from './Network';
import type { CollectorFleet } from './CloudGate';
import { AnimatedCount, MotionCard } from './InterfaceMotion';
import { TimeDisplay } from './TimeDisplay';
import { investigationSeverity } from './investigationSeverity';
import { OverviewCharts, type ChartSelection } from './OverviewCharts';
import { LocalFindings } from './LocalFindings';

type CaseSummary = {
  id: string; title: string; host: string; evidence: { id: string; timestamp: string; kind: number }[];
  review_status?: 'open' | 'investigating' | 'resolved';
};
type Section = 'cases' | 'network' | 'events';

const collectorStatus = { starting: 'Connecting', ready: 'Collecting', unavailable: 'Needs attention', disabled: 'Disabled' };

export function Dashboard({ endpoint, cases, loaded, demo, local, localFindings, open, openCase, openAtlas, connect, fleet, source, manageCollectors, openChart }: {
  endpoint: string;
  cases: CaseSummary[];
  loaded: boolean;
  demo: boolean;
  local: boolean;
  localFindings: boolean;
  open: (section: Section) => void;
  openCase: (id: string) => void;
  openAtlas: (target: AtlasTarget) => void;
  connect?: () => void;
  fleet?: CollectorFleet;
  source?: string | null;
  manageCollectors?: () => void;
  openChart: (selection: ChartSelection) => void;
}) {
  const { inventory, fetchError } = useNetworkInventory(endpoint);
  const newDevices = inventory?.device_findings?.unreviewed ?? 0;
  const openCases = cases.filter((item) => item.review_status !== 'resolved');
  const recent = [...cases].sort((a, b) =>
    (b.evidence.at(-1)?.timestamp ?? '').localeCompare(a.evidence.at(-1)?.timestamp ?? ''));
  const tableCases = [...recent.filter((item) => item.review_status !== 'resolved'),
    ...recent.filter((item) => item.review_status === 'resolved')];
  const sources = [
    { label: 'Network observations', status: inventory?.neighbors, Icon: Network, target: 'atlas-local-devices' },
    { label: 'Windows events', status: inventory?.sysmon, Icon: Activity, target: 'atlas-windows-events' },
    { label: 'Linux journal', status: inventory?.linux_journal, Icon: Server, target: 'atlas-linux-events' },
  ] as const;
  const observedSources = sources.filter((item) => item.status && item.status.state !== 'disabled');
  const metrics = [
    { label: local ? 'Nearby devices' : 'Reporting devices', count: local && inventory?.neighbors ?
      groupNeighbors(inventory.neighbors.records).length : inventory?.assets.length, to: 'network' },
    { label: 'Collected events', count: inventory?.assets.reduce((sum, asset) => sum + asset.events, 0), to: 'events' },
    { label: 'Observed connections', count: inventory?.links.length, to: 'network' },
  ] as const;

  return <main className="dashboard overview-grid">
    <header className="dashboard-heading"><h1>Security overview</h1>{demo && <p className="reference">Synthetic telemetry</p>}</header>
    <MotionCard index={0} label="Needs attention">
      <header className="overview-heading"><CircleAlert size={18} /><h2>Needs attention</h2></header>
      {localFindings && <LocalFindings desktop={local} />}
      {newDevices > 0 && <button type="button" onClick={() => openAtlas('atlas-new-devices')}>
        Review {newDevices} newly observed {newDevices === 1 ? 'device' : 'devices'}
      </button>}
      {inventory?.device_findings?.items.filter((item) => !item.reviewed_at).map((item) =>
        <div className="overview-source-row" key={item.id}>
          <Network size={16} /><span><code>{item.addresses[0] ?? item.mac}</code><small>{item.interface}</small></span>
          <TimeDisplay value={item.first_seen} />
          <button type="button" onClick={() => openAtlas('atlas-new-devices')}>Review</button>
        </div>)}
      {openCases.length === 0 && <p className="reference">{loaded ? 'No open investigations.' : 'Checking investigations…'}</p>}
      {tableCases.length > 0 && <div className="router-traffic-table-wrap">
        <table className="investigation-table" aria-label="Investigations">
          <thead><tr><th>Investigation</th><th>Severity</th><th>Status</th><th>Latest event</th><th>Action</th></tr></thead>
          <tbody>{tableCases.map((item) => {
            const severity = investigationSeverity(item.evidence);
            return <tr key={item.id}>
              <th scope="row">{item.title}<small>{item.host}</small></th>
              <td><span className="severity-label" data-severity={severity}>{severity}</span></td>
              <td className="review-status">{item.review_status ?? 'open'}</td>
              <td><TimeDisplay value={item.evidence.at(-1)?.timestamp} /></td>
              <td><button type="button" onClick={() => openCase(item.id)}>Open</button></td>
            </tr>;
          })}</tbody>
        </table>
      </div>}
    </MotionCard>
    <MotionCard index={1} label="What changed">
      <header className="overview-heading"><Clock3 size={18} /><h2>What changed</h2></header>
      {fetchError && <p role="status">Network totals could not refresh.</p>}
      <div className="overview-metrics">{metrics.map(({ label, count, to }) => <button type="button" key={label} onClick={() => open(to)}>
        <span>{label}</span><strong>{count === undefined ? (fetchError ? '—' : <span className="loading-skeleton" aria-label="Loading" />) :
          <AnimatedCount value={count} />}</strong>
      </button>)}</div>
      {inventory?.device_findings?.baseline_at && <div className="overview-source-row">
        <Network size={16} /><span>Device history</span><TimeDisplay value={inventory.device_findings.baseline_at} />
        <button type="button" onClick={() => openAtlas('atlas-new-devices')}>Review</button>
      </div>}
      <OverviewCharts endpoint={endpoint} source={source} demo={demo} cases={cases} open={openChart} />
    </MotionCard>
    <MotionCard index={2} label="What NORTH can see">
      <header className="overview-heading"><Server size={18} /><h2>What NORTH can see</h2></header>
      {connect && <button className="primary-action" onClick={connect}>Set up first collector</button>}
      {!observedSources.length && !connect && <p className="reference">{inventory ? 'This feed has no collector health details.' : 'Waiting for source health.'}</p>}
      {observedSources.map(({ label, status, Icon, target }) => status && <div className="overview-source-row" key={label}>
        <Icon size={16} /><span>{label}<small>{collectorStatus[status.state]}</small></span><TimeDisplay value={status.updated_at} />
        <button type="button" onClick={() => openAtlas(target)}>{status.state === 'unavailable' ? 'Fix access' : 'Inspect'}</button>
      </div>)}
      {fleet?.sources.map((item) => <div className="overview-source-row" key={item.id}>
        <Server size={16} /><span>{item.label}<small>{item.revoked_at ? 'Revoked' :
          Date.now() - Date.parse(item.updated_at) < 180000 ? 'Synced recently' : 'No recent snapshot'}</small></span>
        <TimeDisplay value={item.updated_at} />
        {source !== item.id ? <button type="button" onClick={() => fleet.select(item.id)}>View</button> :
          manageCollectors && <button type="button" onClick={manageCollectors}>Manage</button>}
      </div>)}
      {fleet?.waiting.map((item) => <div className="overview-source-row" key={item.id}>
        <Server size={16} /><span>{item.label}<small>Waiting for first sync</small></span><TimeDisplay />
        {manageCollectors && <button type="button" onClick={manageCollectors}>Set up</button>}
      </div>)}
    </MotionCard>
  </main>;
}
