import { useState } from 'react';
import { Activity, CircleAlert, Clock3, Laptop, Network, Server, ShieldCheck } from 'lucide-react';
import { groupNeighbors, useNetworkInventory, type AtlasTarget } from './Network';
import type { CollectorFleet } from './CloudGate';
import { AnimatedCount, MotionCard } from './InterfaceMotion';
import { TimeDisplay } from './TimeDisplay';
import { investigationSeverity } from './investigationSeverity';
import { OverviewCharts, type ChartSelection } from './OverviewCharts';
import { LocalFindings, type FindingHealth } from './LocalFindings';
import { LocalCoverage } from './Detections';
import { useDisplayMode } from './DisplayMode';
import { simpleMessages as t } from './simpleMessages';
import { simpleStatus } from './simpleStatus';

type CaseSummary = {
  id: string; title: string; host: string; evidence: { id: string; timestamp: string; kind: number }[];
  review_status?: 'open' | 'investigating' | 'resolved';
};
type Section = 'cases' | 'network' | 'events';

const collectorStatus = { starting: 'Connecting', ready: 'Collecting', unavailable: 'Needs attention', disabled: 'Disabled' };
type Trust = 'yes' | 'no' | 'unsure';
const appNames: Record<string, string> = {
  'chrome.exe': 'Google Chrome', 'msedge.exe': 'Microsoft Edge', 'firefox.exe': 'Firefox',
  'powershell.exe': 'Windows PowerShell', 'pwsh.exe': 'PowerShell', 'svchost.exe': 'Windows Service Host',
};

export function Dashboard({ endpoint, cases, loaded, demo, local, localFindings, open, openCase, openAtlas, connect, fleet, source, manageCollectors, openChart, openDetections }: {
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
  openDetections: () => void;
}) {
  const { inventory, fetchError } = useNetworkInventory(endpoint);
  const { mode, setMode } = useDisplayMode();
  const [findingHealth, setFindingHealth] = useState<FindingHealth>();
  const trustKey = 'north.device-trust.' + (source ?? (local ? 'desktop' : 'workspace'));
  const [trust, setTrust] = useState<Record<string, Trust>>(() => {
    try { return JSON.parse(localStorage.getItem(trustKey) || '{}') ?? {}; } catch { return {}; }
  });

  function decide(id: string, answer: Trust) {
    const next = { ...trust, [id]: answer };
    setTrust(next);
    try { localStorage.setItem(trustKey, JSON.stringify(next)); } catch { /* Keep the current session decision. */ }
  }
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

  if (mode === 'simple') {
    const fresh = (date?: string | null) => !!date && Date.now() - Date.parse(date) < 180_000;
    const currentEvents = [inventory?.sysmon, inventory?.linux_journal]
      .some((item) => item?.state === 'ready' && fresh(item.updated_at));
    const activeDevices = inventory?.device_findings?.items.filter((item) => !item.reviewed_at) ?? [];
    const status = simpleStatus({
      ready: !demo && loaded && !fetchError && (currentEvents || fresh(inventory?.collector_synced_at)) &&
        (!localFindings || findingHealth?.current === true),
      openCases: openCases.length,
      unreviewed: findingHealth?.unreviewed ?? 0,
      severe: findingHealth?.severe ?? false,
      unknownDevices: Math.max(0, newDevices - activeDevices.filter((item) => trust[item.id] === 'yes').length),
    });
    const nearby = groupNeighbors(inventory?.neighbors?.records ?? []).map(([, records]) => records);
    const routerNames = new Map(inventory?.router_usage?.devices
      .filter((device) => device.router_name)
      .map((device) => [device.mac.replace(/[:-]/g, '').toLowerCase(), device.router_name]));
    const deviceName = (group: typeof nearby[number]) => group.find((item) => item.name)?.name ||
      routerNames.get(group[0].mac.replace(/[:-]/g, '').toLowerCase());
    const destinationNames = new Map<string, string>();
    for (const device of nearby) {
      const name = deviceName(device);
      if (name) for (const item of device) destinationNames.set(item.address, name);
    }
    const destinations = [...new Set(inventory?.links.filter((link) => link.direction === 'outbound')
      .map((link) => link.address) ?? [])].slice(0, 5);
    const apps = inventory?.app_connections?.slice(0, 5) ?? [];
    return <main className="dashboard simple-grid">
      <header className="dashboard-heading"><h1>{t.overview}</h1>{demo && <p className="reference">{t.synthetic}</p>}</header>
      <section className="panel simple-hero" data-level={status.level}>
        <ShieldCheck size={28} aria-hidden="true" />
        <div><h2>{t.pc}</h2><strong>{t[status.level]}</strong><p>{t[status.reason]}</p></div>
        <button type="button" onClick={() => setMode('analyst')}>{t.details}</button>
      </section>
      <section className="panel">
        <h2>{t.devices}</h2>
        {!nearby.length && !activeDevices.length && <p>{t.noDevices}</p>}
        <ul className="simple-list">{nearby.slice(0, 6).map((device) => <li key={device[0].network + ':' + device[0].address}>
          <Laptop size={16} aria-hidden="true" />
          <span><strong>{deviceName(device) || t.unknownDevice}</strong><small>{device[0].address}</small></span>
        </li>)}</ul>
        {activeDevices.slice(0, 5).map((item) => {
          const device = nearby.find((group) => group.some((row) => item.addresses.includes(row.address)));
          return <div className="simple-device" key={item.id}>
            <strong>{(device && deviceName(device)) || item.addresses[0] || t.unknownDevice}</strong>
            <p>{t.isThisYou}</p>
            <div className="finding-actions">{(['yes', 'no', 'unsure'] as const).map((answer) =>
              <button key={answer} type="button" aria-pressed={trust[item.id] === answer}
                onClick={() => decide(item.id, answer)}>{t[answer]}</button>)}</div>
          </div>;
        })}
        <button type="button" onClick={() => openAtlas(activeDevices.length ? 'atlas-new-devices' : 'atlas-local-devices')}>{t.deviceList}</button>
      </section>
      <section className="panel">
        <h2>{t.connections}</h2>
        {apps.length > 0 && <><h3>{t.apps}</h3><ul>{apps.map(({ process }) => {
          const name = process.split(/[\\/]/).at(-1) || process;
          return <li key={process} title={process}>{appNames[name.toLowerCase()] ?? name}</li>;
        })}</ul></>}
        {destinations.length > 0 && <><h3>{t.destinations}</h3><ul>{destinations.map((address) =>
          <li key={address}>{destinationNames.get(address) && <>{destinationNames.get(address)} · </>}<code>{address}</code></li>)}</ul></>}
        {!destinations.length && <p>{t.noConnections}</p>}
        <button type="button" onClick={() => open('network')}>{t.details}</button>
      </section>
      <section className="panel simple-next">
        <h2>{t.actions}</h2>
        {connect && <button type="button" onClick={connect}>{t.setup}</button>}
        {!openCases.length && loaded && <p>{t.noActions}</p>}
        {openCases.map((item) => <div className="simple-case" key={item.id}>
          <span>{item.title} · {item.host}</span><button type="button" onClick={() => openCase(item.id)}>{t.investigate}</button>
        </div>)}
        {localFindings && <LocalFindings desktop={local} onHealth={setFindingHealth} />}
      </section>
    </main>;
  }

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
      {localFindings && <LocalCoverage open={openDetections} />}
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
