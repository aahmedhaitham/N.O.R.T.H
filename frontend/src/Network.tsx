import { useEffect, useRef, useState } from 'react';
import { explainAddress } from './deviceExplanation';
import { AtlasMap } from './AtlasMap';
import { pollVisible } from './pollVisible';
import { PacketTrace } from './PacketTrace';
import { readRouterCsv } from './routerCsv';
import { formatTraffic, type TrafficTotals } from './formatTraffic';

type CaseReference = { id: string; title: string };
type Host = { id: string; host: string; events: number; last_seen: string; cases: CaseReference[] };
type Connection = {
  asset_id: string; address: string; direction: 'inbound' | 'outbound';
  events: number; last_seen: string; cases: CaseReference[]; source: string;
};
type Collector = { state: 'starting' | 'disabled' | 'ready' | 'unavailable'; updated_at: string | null };
type HealthSample = { checked_at: string; gateway?: 'responded' | 'no_reply' | 'unknown';
  dns_ms: number | null; https_ms: number | null; http_status: number | null;
  cloud_probe?: boolean; https_error?: 'tls' | 'timeout' | 'network' | null };
type Finding = { id: string; first_seen: string; last_seen: string; reviewed_at: string | null;
  mac: string; interface: string; addresses: string[] };
type Snapshot = {
  assets: Host[]; links: Connection[];
  local_device?: { host: string; addresses: { interface: string; address: string }[] };
  activity?: { interval: 'minute' | 'hour' | 'day' | null; buckets: { start: string; count: number }[];
    types: { kind: number; count: number }[] };
  neighbors?: Collector & { records: Neighbor[] };
  sysmon?: Collector & { session_events: number; recent?: boolean; problem?: 'access_denied' | 'channel_missing' | 'read_failed' | null };
  device_findings?: { baseline_at: string | null; unreviewed: number; items: Finding[] };
  router_usage?: Collector & { devices: ({
    mac: string; router_name?: string; router_ips?: string[]; wifi_associated?: boolean;
  } & TrafficTotals)[] };
  app_connections?: { process: string; events: number; destinations: number }[];
  adapter_traffic?: Collector & { adapters: { name: string; received_bytes: number; sent_bytes: number;
    receive_rate: number | null; send_rate: number | null }[] };
  internet_health?: HealthSample[];
};
type Neighbor = { address: string; mac: string; network: string; state: string; name: string };
export type AtlasTarget = 'atlas-new-devices' | 'atlas-windows-events' | 'atlas-local-devices';
const atlasViews = [
  { id: 'devices', label: 'Devices' }, { id: 'traffic', label: 'Traffic' },
  { id: 'health', label: 'Diagnostics' }, { id: 'traces', label: 'Packet traces' },
] as const;
type AtlasView = (typeof atlasViews)[number]['id'];
const coverageFilters = [
  { id: 'all', label: 'Observed groups' }, { id: 'named', label: 'Named groups' },
  { id: 'unnamed', label: 'Unnamed groups' }, { id: 'wifi', label: 'Router Wi-Fi confirmed' },
  { id: 'usage', label: 'With router byte totals' },
] as const;
type CoverageFilter = (typeof coverageFilters)[number]['id'];

const sysmonProblems = {
  access_denied: 'Windows denied this account access to the Sysmon event log.',
  channel_missing: 'The Sysmon event log was not found.',
  read_failed: 'NORTH could not read the Sysmon event log. It will retry.',
};

function httpsResult(sample: HealthSample) {
  if (sample.https_error === 'tls') return 'TLS failed';
  if (sample.https_error === 'timeout') return 'Timed out';
  if (sample.https_ms === null) return 'No response';
  if (sample.cloud_probe && sample.http_status === 204) return 'Cloud reached';
  if (sample.http_status === 401 || sample.http_status === 403) return 'Reached · access denied';
  if (sample.http_status !== null && sample.http_status >= 500) return 'Reached · service error';
  return 'Response received';
}

function healthIsStale(sample: HealthSample) {
  return Date.now() - Date.parse(sample.checked_at) > 12 * 60 * 1000;
}

function readNeighbors(value: unknown): Neighbor[] {
  if (!Array.isArray(value)) throw new Error('Choose a JSON array of device records.');
  if (value.length > 5000) throw new Error('Choose a file with at most 5,000 device records.');
  return value.map((row, index) => {
    const address = row?.address ?? row?.dst;
    if (typeof address !== 'string' || !address.trim()) {
      throw new Error('Device record ' + (index + 1) + ' is missing an address.');
    }
    return {
      address: address.trim(),
      mac: String(row.mac ?? row.lladdr ?? ''),
      network: String(row.interface ?? row.dev ?? ''),
      state: Array.isArray(row.state) ? row.state.join(', ') : String(row.state ?? ''),
      name: String(row.name ?? ''),
    };
  });
}

export function groupNeighbors(records: Neighbor[]) {
  const devices = new Map<string, Neighbor[]>();
  for (const record of records) {
    const mac = record.mac.replace(/[:-]/g, '').toLowerCase();
    const identity = /^[0-9a-f]{12}$/.test(mac) && mac !== '000000000000'
      ? 'mac:' + mac : 'ip:' + record.address;
    const key = record.network + ':' + identity;
    const device = devices.get(key) ?? [];
    if (!device.some((item) => item.address === record.address)) device.push(record);
    devices.set(key, device);
  }
  return [...devices];
}

export function useNetworkInventory(endpoint: string, interval = 5000) {
  const [inventory, setInventory] = useState<Snapshot | null>(null);
  const [fetchError, setFetchError] = useState(false);
  const [revision, setRevision] = useState(0);
  const [refreshing, setRefreshing] = useState(false);
  const [lastRefresh, setLastRefresh] = useState<string>();
  const manual = useRef(false);

  useEffect(() => {
    if (!endpoint) return;
    const controller = new AbortController();
    async function refresh() {
      setRefreshing(true);
      try {
        const requested = manual.current && location.protocol === 'north:' && location.pathname === '/';
        manual.current = false;
        const response = await fetch(requested ? endpoint + '?refresh=1' : endpoint,
          { signal: controller.signal, cache: 'no-store' });
        if (!response.ok) throw new Error('Inventory unavailable');
        const result: Snapshot = await response.json();
        if (result.neighbors) result.neighbors.records = readNeighbors(result.neighbors.records);
        if (!controller.signal.aborted) {
          setInventory(result);
          setFetchError(false);
          setLastRefresh(new Date().toLocaleTimeString());
        }
      } catch {
        if (!controller.signal.aborted) setFetchError(true);
      } finally {
        if (!controller.signal.aborted) {
          setRefreshing(false);
        }
      }
    }
    const stop = pollVisible(refresh, endpoint.startsWith('/api/') ? interval : 0);
    return () => {
      controller.abort();
      stop();
    };
  }, [endpoint, revision, interval]);

  return { inventory, fetchError, refreshing, lastRefresh, refresh: () => {
    manual.current = true;
    setRevision((value) => value + 1);
  } };
}

export function Network({ endpoint, openCase, openEvents, target, onTarget, demo, readOnly, labelSource }: {
  endpoint: string; openCase: (id: string) => void; openEvents: (search: string) => void;
  target: AtlasTarget | null; onTarget: (target: null) => void; demo: boolean; readOnly: boolean;
  labelSource: string | null;
}) {
  const [interval, setInterval] = useState(15000);
  const { inventory, fetchError, refresh, refreshing, lastRefresh } = useNetworkInventory(endpoint, interval);
  const [neighbors, setNeighbors] = useState<Neighbor[]>([]);
  const [fileMessage, setFileMessage] = useState('');
  const [search, setSearch] = useState('');
  const [wifiOnly, setWifiOnly] = useState(false);
  const [healthWindow, setHealthWindow] = useState(12);
  const [atlasView, setAtlasView] = useState<AtlasView>('devices');
  const [coverageFilter, setCoverageFilter] = useState<CoverageFilter>('all');
  const activeView = target ? (target === 'atlas-windows-events' ? 'health' : 'devices') : atlasView;
  const [reviewing, setReviewing] = useState('');
  const [reviewError, setReviewError] = useState(false);
  const [deviceLabels, setDeviceLabels] = useState<Map<string, string> | null>(null);
  const [labelError, setLabelError] = useState(false);
  const labelsEndpoint = labelSource ? '/api/network/device-labels?source=' + encodeURIComponent(labelSource) : '';

  useEffect(() => {
    if (!labelsEndpoint) return;
    const controller = new AbortController();
    void fetch(labelsEndpoint, { signal: controller.signal }).then(async (response) => {
      if (!response.ok) throw new Error();
      const data: { labels: { mac: string; label: string }[] } = await response.json();
      if (!controller.signal.aborted) setDeviceLabels(new Map(data.labels.map(({ mac, label }) => [mac, label])));
    }).catch(() => { if (!controller.signal.aborted) setLabelError(true); });
    return () => controller.abort();
  }, [labelsEndpoint]);

  async function saveDeviceLabel(mac: string, label: string) {
    const response = await fetch(labelsEndpoint, {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ mac, label }),
    });
    if (!response.ok) throw new Error('Device label could not be saved.');
    const saved: { mac: string; label: string } = await response.json();
    setDeviceLabels((current) => {
      const next = new Map(current);
      if (saved.label) next.set(saved.mac, saved.label);
      else next.delete(saved.mac);
      return next;
    });
  }
  const hasInventory = Boolean(inventory);

  useEffect(() => {
    if (!endpoint || !target || refreshing || (!hasInventory && !fetchError)) return;
    const frame = window.requestAnimationFrame(() => {
      const heading = document.getElementById(target) ?? document.getElementById('atlas-heading');
      heading?.scrollIntoView({ block: 'start' });
      heading?.focus({ preventScroll: true });
      if (target === 'atlas-new-devices') setSearch('');
      setAtlasView(target === 'atlas-windows-events' ? 'health' : 'devices');
      onTarget(null);
    });
    return () => window.cancelAnimationFrame(frame);
  }, [endpoint, target, hasInventory, fetchError, refreshing, onTarget]);
  const query = search.trim().toLowerCase();
  const fits = (...values: string[]) => values.some((value) => value.toLowerCase().includes(query));
  const localDevice = inventory?.local_device;
  const adapters = new Map<string, Set<string>>();
  for (const { interface: name, address } of localDevice?.addresses ?? []) {
    const addresses = adapters.get(name) ?? new Set<string>();
    addresses.add(address);
    adapters.set(name, addresses);
  }
  const matchingAdapters = [...adapters].filter(([name, addresses]) => fits(name, localDevice?.host ?? '', ...addresses));
  const hosts = new Map(inventory?.assets.map((asset) => [asset.id, asset.host]));
  const matchingHosts = inventory?.assets.filter((asset) => fits(asset.host)) ?? [];
  const matchingLinks = inventory?.links.filter((link) => fits(link.address, hosts.get(link.asset_id) ?? '')) ?? [];
  const collector = inventory?.neighbors;
  const windowsEvents = inventory?.sysmon;
  const latestHealth = Array.isArray(inventory?.internet_health) ? inventory.internet_health.at(-1) : undefined;
  const healthHistory = Array.isArray(inventory?.internet_health) ? inventory.internet_health.slice(-healthWindow) : [];
  const respondingChecks = healthHistory.filter((sample) => sample.https_ms !== null).length;
  const peakLatency = Math.max(1, ...healthHistory.map((sample) => sample.https_ms ?? 0));
  const matchingApps = inventory?.app_connections?.filter((app) => fits(app.process)) ?? [];
  const adapterTraffic = inventory?.adapter_traffic;
  const adapterRows = (adapterTraffic?.adapters ?? []).filter((item) => fits(item.name))
    .sort((a, b) => ((b.receive_rate ?? 0) + (b.send_rate ?? 0)) - ((a.receive_rate ?? 0) + (a.send_rate ?? 0)) ||
      a.name.localeCompare(b.name));
  const matchesDevice = ([, records]: [string, Neighbor[]]) => records.some((record) =>
    fits(record.address, record.name, record.mac, record.network));
  const liveDevices = groupNeighbors(collector?.records ?? []);
  const importedDevices = groupNeighbors(neighbors);
  const watch = inventory?.device_findings;
  const router = inventory?.router_usage;
  const macKey = (mac: string) => mac.replace(/[:-]/g, '').toLowerCase();
  const trafficByMac = new Map(router?.devices.map((device) => [macKey(device.mac), device]));
  const importedNames = new Map<string, Set<string>>();
  for (const record of neighbors) {
    const mac = macKey(record.mac);
    const name = record.name.trim();
    if (!/^[0-9a-f]{12}$/.test(mac) || mac === '000000000000' || !name) continue;
    const labels = importedNames.get(mac) ?? new Set<string>();
    labels.add(name);
    importedNames.set(mac, labels);
  }
  function describeDevice(records: Neighbor[], withRouter: boolean) {
    const mac = macKey(records[0].mac);
    const traffic = withRouter ? trafficByMac.get(mac) : undefined;
    const imported = withRouter ? importedNames.get(mac) : undefined;
    const observedName = records.find((record) => record.name.trim())?.name.trim();
    const importedName = imported?.size === 1 ? [...imported][0] : undefined;
    const savedLabel = withRouter ? deviceLabels?.get(mac) : undefined;
    const name = savedLabel || traffic?.router_name || observedName || importedName;
    const nameSource = savedLabel ? 'Workspace label' : traffic?.router_name ? 'Router DHCP' : observedName ? (withRouter ? 'Collector observation' : 'Imported list') :
      importedName ? 'Imported router list' : undefined;
    return { traffic, name, nameSource, savedLabel };
  }
  const observedByMac = new Map<string, Neighbor[]>();
  for (const record of collector?.records ?? []) {
    if (!record.mac) continue;
    const key = macKey(record.mac);
    const observations = observedByMac.get(key) ?? [];
    observations.push(record);
    observedByMac.set(key, observations);
  }
  const routerDevices = (router?.devices ?? []).map((device) => {
    const observations = observedByMac.get(macKey(device.mac)) ?? [];
    const names = new Set(observations.map((record) => record.name).filter(Boolean));
    const leaseIPs = Array.isArray(device.router_ips) ? device.router_ips : [];
    const observedIPs = [...new Set(observations.map((record) => record.address))];
    return {
      ...device, observations, leaseIPs, observedIPs, name: names.size === 1 ? [...names][0] : '',
      savedLabel: deviceLabels?.get(macKey(device.mac)),
      total: device.download_bytes + device.upload_bytes,
    };
  }).filter((device) => (!wifiOnly || device.wifi_associated === true) &&
    (fits(device.mac, device.router_name ?? '', device.savedLabel ?? '', ...device.leaseIPs) ||
      device.observations.some((record) => fits(record.name, record.address, record.network))))
    .sort((a, b) => b.total - a.total || a.mac.localeCompare(b.mac));
  const largestTrafficTotal = Math.max(1, routerDevices[0]?.total ?? 0);
  const observedDevices = liveDevices.map(([id, records]) => {
    const first = records[0];
    const { name, nameSource, savedLabel, traffic } = describeDevice(records, true);
    const label = name || records.find((record) => !record.address.includes(':'))?.address || first.address;
    return { id, label, observedName: name, nameSource, savedLabel, network: first.network || 'Unknown interface', mac: first.mac,
      addresses: records.map((record) => record.address), states: [...new Set(records.map((record) => record.state).filter(Boolean))],
      traffic };
  });
  function matchesCoverage(device: (typeof observedDevices)[number], filter: CoverageFilter) {
    switch (filter) {
      case 'named': return Boolean(device.observedName);
      case 'unnamed': return !device.observedName;
      case 'wifi': return device.traffic?.wifi_associated === true;
      case 'usage': return Boolean(device.traffic);
      default: return true;
    }
  }
  const mapDevices = observedDevices.filter((device, index) => matchesCoverage(device, coverageFilter) &&
    (matchesDevice(liveDevices[index]) || fits(device.observedName ?? '', ...(device.traffic?.router_ips ?? []))));
  const visibleIds = new Set(mapDevices.map((device) => device.id));

  function exportInventory() {
    const rows = [
      ['Device', 'Name source', 'Observed IP addresses', 'MAC address', 'Interface', 'Router Wi-Fi confirmed',
        'Router download bytes', 'Router upload bytes', 'Router sample time'],
      ...mapDevices.map((item) => [
        item.label, item.nameSource ?? '', item.addresses.join(' | '), item.mac, item.network,
        item.traffic?.wifi_associated ? 'Yes' : '', item.traffic?.download_bytes ?? '',
        item.traffic?.upload_bytes ?? '', item.traffic ? router?.updated_at ?? '' : '',
      ]),
    ];
    const csv = rows.map((row) => row.map((value) => {
      const raw = String(value);
      const cell = /^[\s]*[=+@-]|^[\t\r\n]/.test(raw) ? "'" + raw : raw;
      return '"' + cell.replaceAll('"', '""') + '"';
    }).join(',')).join('\r\n');
    const url = URL.createObjectURL(new Blob(['\uFEFF', csv], { type: 'text/csv;charset=utf-8' }));
    const link = document.createElement('a');
    link.href = url;
    link.download = 'north-device-inventory.csv';
    link.click();
    window.setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  async function review(id: string) {
    setReviewError(false);
    setReviewing(id);
    try {
      const response = await fetch('/api/network/devices/' + encodeURIComponent(id) + '/review', {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ reviewed: true }),
      });
      if (!response.ok) throw new Error('Review failed');
      refresh();
    } catch {
      setReviewError(true);
    } finally {
      setReviewing('');
    }
  }

  async function importNeighbors(file: File) {
    try {
      if (file.size > 2_000_000) throw new Error('Choose a device file smaller than 2 MB.');
      const text = (await file.text()).replace(/^\uFEFF/, '');
      const records = readNeighbors(/\.json$/i.test(file.name) || text.trimStart().startsWith('[') ?
        JSON.parse(text) : readRouterCsv(text.trimStart()));
      setNeighbors(records);
      setFileMessage(records.length + ' device records loaded in this tab.');
    } catch (error) {
      setFileMessage(error instanceof Error ? error.message : 'Could not read that file.');
    }
  }

  function caseButtons(cases: CaseReference[]) {
    return cases.map((item) => (
      <button type="button" className="network-case" key={item.id} onClick={() => openCase(item.id)}>{item.title}</button>
    ));
  }

  function devicesList(devices: [string, Neighbor[]][], includeRouter = false) {
    const matching = devices.map(([key, records]) => ({
      key, records, ...describeDevice(records, includeRouter),
    })).filter(({ key, records, name, traffic }) => matchesDevice([key, records]) ||
      fits(name ?? '', ...(traffic?.router_ips ?? [])));
    return <>
      {matching.length > 0 && <div className="router-traffic-table-wrap">
        <table className="investigation-table device-inventory-table" aria-label="Observed devices">
          <thead><tr><th scope="col">Device</th><th scope="col">IP addresses</th><th scope="col">MAC address</th>
            <th scope="col">Observed on</th>{includeRouter && <th scope="col">Router usage</th>}</tr></thead>
          <tbody>{matching.map(({ key, records, traffic, name, nameSource }) => {
            const { address, mac, network } = records[0];
            return <tr key={key}>
              <th scope="row">{name || address}
                <small>{nameSource || 'Name unavailable'}</small>
              </th>
              <td>{records.map((record) => <div key={record.address}>
                <button type="button" className="atlas-address-button" onClick={() => openEvents(record.address)}
                  aria-label={`Search IRIS for ${record.address}`}>{record.address}</button>
                {record.state && <small>{record.state}</small>}
              </div>)}
              <details className="device-explanation">
                <summary>Explain addresses</summary>
                {records.map((record) => <p key={record.address}><strong>{record.address}</strong> · {explainAddress(record.address)}</p>)}
              </details></td>
              <td>{mac ? <code>{mac}</code> : 'Unavailable'}</td>
              <td>{network || 'Unknown interface'}{traffic?.wifi_associated && <small>Seen on router Wi-Fi</small>}</td>
              {includeRouter && <td>{traffic ? <>
                <span>↓ {formatTraffic(traffic.download_bytes)} · ↑ {formatTraffic(traffic.upload_bytes)}</span>
                {router?.state === 'unavailable' && <small>Last available totals</small>}
              </> : <small>Unavailable</small>}</td>}
            </tr>;
          })}</tbody>
        </table>
      </div>}
      {devices.length > 0 && !matching.length && <p>No devices match this search.</p>}
    </>;
  }

  return <main className="network atlas-workspace">
    <header className="dashboard-heading">
      <h1 id="atlas-heading" tabIndex={-1}>ATLAS <span className="workspace-title">Network inventory</span></h1>
    </header>
    <nav className="atlas-view-bar" aria-label="ATLAS tools">
      {atlasViews.map(({ id, label }) => <button key={id} type="button"
        aria-current={activeView === id ? 'page' : undefined} onClick={() => { setAtlasView(id); onTarget(null); }}>{label}</button>)}
    </nav>
    {fetchError && <p role="status">The telemetry inventory is temporarily unavailable.</p>}
    {endpoint && !inventory && !fetchError && activeView !== 'traces' && <p role="status">Loading network observations…</p>}
    <section className="panel atlas-toolbar" aria-label="Network inventory controls">
      <label className="network-search">Find device
        <input type="search" placeholder="Host, IP or MAC address" value={search} onChange={(event) => setSearch(event.target.value)} />
      </label>
      <button type="button" className="primary-action" disabled={refreshing} onClick={refresh}>{refreshing ? 'Refreshing…' : 'Refresh observations'}</button>
      {endpoint.startsWith('/api/') && <label>Auto refresh <select value={interval} onChange={(event) => setInterval(Number(event.target.value))}>
        <option value={0}>Off</option><option value={15000}>Every 15 seconds</option>
        <option value={30000}>Every 30 seconds</option><option value={60000}>Every minute</option>
      </select></label>}
      {lastRefresh && <small>View updated {lastRefresh}</small>}
    </section>
    <div className="atlas-section-stack" hidden={activeView !== 'devices'}>
    {observedDevices.length > 0 && <section className="panel" aria-labelledby="atlas-coverage">
      <h2 id="atlas-coverage">Device coverage</h2>
      <div className="health-summary device-coverage-actions" role="group" aria-label="Filter observed devices">
        {coverageFilters.map(({ id, label }) => <button key={id} type="button" aria-pressed={coverageFilter === id}
          onClick={() => setCoverageFilter(id)}>
          <span>{label}</span><strong>{observedDevices.filter((device) => matchesCoverage(device, id)).length.toLocaleString()}</strong>
        </button>)}
      </div>
      <button type="button" disabled={!mapDevices.length} onClick={exportInventory}>Export filtered inventory</button>
    </section>}
    {labelError && <p role="status">Saved device labels are temporarily unavailable.</p>}
    <AtlasMap devices={mapDevices} staleTraffic={router?.state === 'unavailable'} openEvents={openEvents}
      saveLabel={deviceLabels ? saveDeviceLabel : undefined} />
    {localDevice && <section className="panel">
      <h2>This computer</h2>
      <p>{localDevice.host} · {adapters.size} {adapters.size === 1 ? 'network adapter' : 'network adapters'}</p>
      <ul className="network-list">{matchingAdapters.map(([name, addresses]) => <li key={name}>
        <strong>{name}</strong>
        <ul className="adapter-addresses">{[...addresses].sort((a, b) =>
          Number(a.includes(':')) - Number(b.includes(':')) || a.localeCompare(b),
        ).map((address) => <li key={address}><small>{address.includes(':') ? 'IPv6' : 'IPv4'} <code>{address}</code></small></li>)}</ul>
      </li>)}</ul>
      {!matchingAdapters.length && <p>{query ? 'No local adapters match this search.' : 'No network adapters with addresses were found.'}</p>}
    </section>}
    {watch && (watch.baseline_at || collector?.state === 'starting') && <section className="panel">
      <h2 id="atlas-new-devices" tabIndex={-1}>Newly observed devices</h2>
      <p>{watch.baseline_at ? `${watch.unreviewed} awaiting review · Baseline started ${new Date(watch.baseline_at).toLocaleString()}` :
        'Waiting for the first usable device snapshot.'}</p>
      {demo && <p>Sample finding from a synthetic network.</p>}
      {reviewError && <p role="alert">That finding could not be marked as reviewed.</p>}
      {!watch.items.length && watch.baseline_at && <p>No new devices have appeared since the first snapshot.</p>}
      <ul className="network-list">{watch.items.filter((item) => fits(item.mac, item.interface, ...item.addresses)).map((item) => (
        <li key={item.id}>
          <strong>{item.addresses.join(', ')}</strong>
          <small>{item.mac} · {item.interface} · First seen {new Date(item.first_seen).toLocaleString()}</small>
          <small>{item.reviewed_at ? 'Reviewed' : 'Needs review'} · Last seen {new Date(item.last_seen).toLocaleString()}</small>
          <details className="device-explanation">
            <summary>Why did this appear?</summary>
            <p>NORTH saw this hardware address on this interface after the first snapshot. A new device or a randomized hardware address can produce this finding.</p>
            {item.addresses.map((address) => <p key={address}><strong>{address}</strong> · {explainAddress(address)}</p>)}
          </details>
          {!readOnly && !item.reviewed_at && <button className="network-case" disabled={Boolean(reviewing)}
            onClick={() => void review(item.id)}>{reviewing === item.id ? 'Saving…' : 'Mark reviewed'}</button>}
        </li>
      ))}</ul>
    </section>}
    {collector && collector.state !== 'disabled' && <section className="panel">
      <h2 id="atlas-local-devices" tabIndex={-1}>Local network devices</h2>
      <p role="status">{collector.state === 'starting' ? 'Reading the local neighbor cache…' :
        collector.state === 'unavailable' ? 'The collector could not read the cache. It will retry automatically.' :
        `${liveDevices.length} device groups · Last refreshed ${new Date(collector.updated_at ?? '').toLocaleTimeString()}`}</p>
      <p>Addresses are grouped by interface and MAC. Router usage appears when the router reports byte totals for that MAC.</p>
      {mapDevices.length ? devicesList(liveDevices.filter(([id]) => visibleIds.has(id)), true) :
        liveDevices.length > 0 && <p>No observed devices match the current filters.</p>}
    </section>}
    <div className="columns">
      <section className="panel">
        <h2>Reporting devices</h2>
        <ul className="network-list">{matchingHosts.map((asset) => <li key={asset.id}>
          <strong>{asset.host}</strong>
          <small>{asset.events} events · Last seen {new Date(asset.last_seen).toLocaleString()}</small>
          <div className="case-links">
            {asset.host && <button type="button" className="network-case" onClick={() => openEvents(asset.host)}>Search host in IRIS</button>}
            {caseButtons(asset.cases)}
          </div>
        </li>)}</ul>
        {!matchingHosts.length && <p>{inventory ? 'No reporting devices match.' : 'Loading reporting devices…'}</p>}
      </section>
      <section className="panel">
        <h2>Observed connections</h2>
        <ul className="network-list">{matchingLinks.map((link) => <li key={link.asset_id + link.address + link.direction}>
          <strong>{link.address}</strong>
          <small>{link.direction === 'inbound' ? 'Inbound to' : 'Outbound from'} {hosts.get(link.asset_id)} · {link.source} · {link.events} {link.events === 1 ? 'event' : 'events'}</small>
          <details className="device-explanation">
            <summary>Explain this address</summary>
            <p>{explainAddress(link.address)}</p>
          </details>
          <div className="case-links">
            <button type="button" className="network-case" onClick={() => openEvents(link.address)}>Search address in IRIS</button>
            {caseButtons(link.cases)}
          </div>
        </li>)}</ul>
        {!matchingLinks.length && <p>{inventory ? 'No observed connections match.' : 'Loading connections…'}</p>}
      </section>
    </div>
    <details className="panel">
      <summary>Import a device list</summary>
      <p>Open a device export from this network as JSON or CSV. Include IP Address and, to match observed devices, Device Name and MAC Address. Imported names are used only when the MAC matches and the name is unambiguous.</p>
      <input type="file" accept=".json,.csv,.tsv" aria-label="Import device inventory"
        onChange={(event) => { const file = event.target.files?.[0]; if (file) void importNeighbors(file); event.target.value = ''; }} />
      {fileMessage && <p role="status">{fileMessage}</p>}
      {neighbors.length > 0 && <p><button type="button" onClick={() => {
        setNeighbors([]); setFileMessage('Imported device records cleared.');
      }}>Clear imported devices</button></p>}
      {devicesList(importedDevices)}
    </details>
    </div>
    <div className="atlas-section-stack" hidden={activeView !== 'traffic'}>
    {adapterTraffic && <section className="panel">
      <h2>Windows adapter traffic</h2>
      <p>Traffic through the selected endpoint’s network adapters. Rates are averages between samples.</p>
      {adapterTraffic.updated_at && <p className="reference">Last sample {new Date(adapterTraffic.updated_at).toLocaleString()}</p>}
      {adapterTraffic.state === 'unavailable' && <p role="status">Adapter counters could not refresh. Any rows shown are from the last successful sample.</p>}
      {adapterTraffic.state === 'starting' && <p>Waiting for the first adapter sample…</p>}
      {adapterTraffic.state === 'ready' && !adapterRows.length && <p>{query ? 'No adapters match the search.' : 'No adapter counters were reported.'}</p>}
      {adapterRows.length > 0 && <div className="router-traffic-table-wrap">
        <table className="investigation-table router-traffic-table" aria-label="Windows adapter traffic">
          <thead><tr><th scope="col">Adapter</th><th scope="col">Receive rate</th><th scope="col">Send rate</th><th scope="col">Received total</th><th scope="col">Sent total</th></tr></thead>
          <tbody>{adapterRows.map((item) => <tr key={item.name}>
            <th scope="row">{item.name}</th>
            <td>{item.receive_rate === null ? '—' : formatTraffic(item.receive_rate) + '/s'}</td>
            <td>{item.send_rate === null ? '—' : formatTraffic(item.send_rate) + '/s'}</td>
            <td>{formatTraffic(item.received_bytes)}</td><td>{formatTraffic(item.sent_bytes)}</td>
          </tr>)}</tbody>
        </table>
        {adapterRows.some((item) => item.receive_rate === null) && <p className="reference">Rates appear after two successful samples with increasing or unchanged counters.</p>}
      </div>}
    </section>}
    {router && <section className="panel">
      <h2>Router traffic by device</h2>
      <p>OpenWrt accounting-period totals per MAC, sorted by combined traffic. The Wi-Fi column shows association reported by the router.</p>
      {router.devices.length > 0 && <label className="router-wifi-filter">
        <input type="checkbox" checked={wifiOnly} onChange={(event) => setWifiOnly(event.target.checked)} />
        Only devices seen on router Wi-Fi
      </label>}
      {router.state === 'unavailable' && <p role="status">Router data is unavailable. Any figures below are from the last successful refresh.</p>}
      {router.state === 'starting' && <p>Waiting for the first router update…</p>}
      {router.updated_at && <p className="reference">Last updated {new Date(router.updated_at).toLocaleString()}</p>}
      {router.state === 'ready' && !routerDevices.length && <p>No matching device totals.</p>}
      {routerDevices.length > 0 && <div className="router-traffic-table-wrap">
        <table className="investigation-table router-traffic-table" aria-label="Router traffic by device">
          <thead><tr><th scope="col">Device</th><th scope="col">IP addresses</th><th scope="col" className="router-download">Download</th><th scope="col" className="router-upload">Upload</th><th scope="col">Total</th><th scope="col">Wi-Fi</th></tr></thead>
          <tbody>{routerDevices.map((device) => <tr key={device.mac}>
            <th scope="row">
              {device.savedLabel || device.router_name || device.name || device.mac}
              {(device.savedLabel || device.router_name || device.name) &&
                <small>{device.mac} · {device.savedLabel ? 'Workspace label' : device.router_name ? 'DHCP lease' : 'Collector record'}</small>}
            </th>
            <td>{(device.leaseIPs.length ? device.leaseIPs : device.observedIPs).map((address) =>
              <button key={address} type="button" className="atlas-address-button" onClick={() => openEvents(address)}
                aria-label={`Search IRIS for ${address}`}>{address}</button>)}
              {device.leaseIPs.length ? <small>DHCP lease</small> : device.observedIPs.length ? <small>Collector observation</small> : '—'}
            </td>
            <td>{formatTraffic(device.download_bytes)}</td>
            <td>{formatTraffic(device.upload_bytes)}</td>
            <td>
              {formatTraffic(device.total)}
              <div className="router-traffic-track" aria-hidden="true">
                <span style={{ width: `${device.download_bytes / largestTrafficTotal * 100}%` }} />
                <span style={{ width: `${device.upload_bytes / largestTrafficTotal * 100}%` }} />
              </div>
            </td>
            <td>{device.wifi_associated === true ? 'Seen on router Wi-Fi' : '—'}</td>
          </tr>)}</tbody>
        </table>
      </div>}
    </section>}
    {(inventory?.local_device || Array.isArray(inventory?.app_connections)) && <section className="panel">
      <h2>App network activity</h2>
      <p>Connection counts from the selected endpoint’s recorded Sysmon events. Byte totals come from separate traffic telemetry.</p>
      {!inventory.app_connections?.length && <p>{windowsEvents?.state === 'unavailable' ?
        'Allow this Windows account to read the Sysmon event log to see app network activity.' : 'No app connections in the available event history.'}</p>}
      {inventory.app_connections?.length ? (matchingApps.length ? <div className="router-traffic-table-wrap">
        <table className="investigation-table" aria-label="App connections">
          <thead><tr><th scope="col">Process</th><th scope="col">Connections</th><th scope="col">Destinations</th></tr></thead>
          <tbody>{matchingApps.map((app) => <tr key={app.process}>
            <td><button type="button" className="atlas-address-button" onClick={() => openEvents(app.process)}
              aria-label={`Search IRIS for ${app.process}`}>{app.process}</button></td>
            <td>{app.events.toLocaleString()}</td><td>{app.destinations.toLocaleString()}</td>
          </tr>)}</tbody>
        </table>
      </div> : <p>No processes match the search.</p>) : null}
    </section>}
    {inventory && !router && !adapterTraffic && !inventory.local_device && !inventory.app_connections && <p>No traffic source is reporting to this collector.</p>}
    </div>
    <div className="atlas-section-stack" hidden={activeView !== 'health'}>
    {Array.isArray(inventory?.internet_health) && <section className="panel">
      <h2>Internet health from the collector</h2>
      <p>Default IPv4 gateway response, plus DNS lookup and HTTPS response time for NORTH Cloud. Some gateways block ping replies.</p>
      {latestHealth && <>
        <p className="reference">Last checked <time dateTime={latestHealth.checked_at}>{new Date(latestHealth.checked_at).toLocaleString()}</time>
          {!demo && healthIsStale(latestHealth) && <strong className="health-stale"> Older than 12 minutes</strong>}</p>
        <dl className="health-summary">
          <div><dt>Gateway</dt><dd>{latestHealth.gateway === 'responded' ? 'Replied' : latestHealth.gateway === 'no_reply' ? 'No reply' : 'Unavailable'}</dd></div>
          <div><dt>DNS lookup</dt><dd>{latestHealth.dns_ms === null ? 'Failed' : latestHealth.dns_ms + ' ms'}</dd></div>
          <div><dt>HTTPS response</dt><dd>{httpsResult(latestHealth)}
            {latestHealth.https_ms !== null && <small>{latestHealth.https_ms} ms · HTTP {latestHealth.http_status}</small>}</dd></div>
        </dl>
      </>}
      {!inventory.internet_health.length && <p>Waiting for the first check.</p>}
      {inventory.internet_health.length > 0 && <details>
        <summary>Recent check history</summary>
        <label className="router-wifi-filter">Show <select value={healthWindow} onChange={(event) => setHealthWindow(Number(event.target.value))}>
          <option value={12}>Last 12 checks</option><option value={72}>Last 72 checks</option>
        </select></label>
        <p className="reference">HTTPS responded in {respondingChecks} of {healthHistory.length} sampled checks.</p>
        <div className="diagnostic-history-chart" role="list" aria-label="HTTPS response times">
          {healthHistory.map((sample) => <div key={sample.checked_at} role="listitem"
            aria-label={`${new Date(sample.checked_at).toLocaleString()}, ${httpsResult(sample)}${sample.https_ms === null ? '' : ', ' + sample.https_ms + ' ms'}`}
            title={`${httpsResult(sample)}${sample.https_ms === null ? '' : ' · ' + sample.https_ms + ' ms'}`}>
            <span data-missed={sample.https_ms === null || undefined}
              style={{ height: sample.https_ms === null ? '4px' : `max(2px, ${sample.https_ms / peakLatency * 100}%)` }} />
          </div>)}
        </div>
        <div className="router-traffic-table-wrap">
        <table className="investigation-table router-traffic-table" aria-label="Collector internet checks">
          <thead><tr><th scope="col">Checked</th><th scope="col">Gateway</th><th scope="col">DNS</th><th scope="col">HTTPS</th><th scope="col">Response</th></tr></thead>
          <tbody>{[...healthHistory].reverse().map((sample) => <tr key={sample.checked_at}>
            <td><time dateTime={sample.checked_at}>{new Date(sample.checked_at).toLocaleString()}</time></td>
            <td>{sample.gateway === 'responded' ? 'Replied' : sample.gateway === 'no_reply' ? 'No reply' : 'Unavailable'}</td>
            <td>{sample.dns_ms === null ? 'Lookup failed' : sample.dns_ms + ' ms'}</td>
            <td>{sample.https_ms === null ? 'No response' : sample.https_ms + ' ms'}</td>
            <td>{sample.http_status === null ? httpsResult(sample) : `${httpsResult(sample)} (HTTP ${sample.http_status})`}</td>
          </tr>)}</tbody>
        </table>
        </div>
      </details>}
    </section>}
    {windowsEvents && windowsEvents.state !== 'disabled' && <section className="panel">
      <h2 id="atlas-windows-events" tabIndex={-1}>Windows event collection</h2>
      <p role="status">{windowsEvents.state === 'starting' ? 'Connecting to the Sysmon log…' :
        windowsEvents.state === 'unavailable' ? sysmonProblems[windowsEvents.problem ?? 'read_failed'] :
        `${windowsEvents.session_events} ${windowsEvents.recent ? 'recent events available' : 'new events since launch'} · Last checked ${new Date(windowsEvents.updated_at ?? '').toLocaleTimeString()}`}</p>
    </section>}
    {inventory && !inventory.internet_health && (!windowsEvents || windowsEvents.state === 'disabled') && <p>This collector has not supplied diagnostics.</p>}
    </div>
    <div className="atlas-section-stack" hidden={activeView !== 'traces'}>
    <PacketTrace />
    </div>
  </main>;
}
