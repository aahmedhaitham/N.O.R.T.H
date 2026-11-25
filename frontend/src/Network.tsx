import { useEffect, useRef, useState } from 'react';
import { explainAddress } from './deviceExplanation';
import { AtlasMap } from './AtlasMap';
import { pollVisible } from './pollVisible';
import { PacketTrace } from './PacketTrace';
import { formatTraffic, type TrafficTotals } from './formatTraffic';

type CaseReference = { id: string; title: string };
type Host = { id: string; host: string; events: number; last_seen: string; cases: CaseReference[] };
type Connection = {
  asset_id: string; address: string; direction: 'inbound' | 'outbound';
  events: number; last_seen: string; cases: CaseReference[]; source: string;
};
type Collector = { state: 'starting' | 'disabled' | 'ready' | 'unavailable'; updated_at: string | null };
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
  router_usage?: Collector & { devices: ({ mac: string; router_name?: string; wifi_associated?: boolean } & TrafficTotals)[] };
  app_connections?: { process: string; events: number; destinations: number }[];
  internet_health?: { checked_at: string; gateway?: 'responded' | 'no_reply' | 'unknown';
    dns_ms: number | null; https_ms: number | null; http_status: number | null }[];
};
type Neighbor = { address: string; mac: string; network: string; state: string; name: string };
export type AtlasTarget = 'atlas-new-devices' | 'atlas-windows-events' | 'atlas-local-devices';
const atlasViews = [
  { id: 'devices', label: 'Devices' }, { id: 'traffic', label: 'Traffic' },
  { id: 'health', label: 'Diagnostics' }, { id: 'traces', label: 'Packet traces' },
] as const;
type AtlasView = (typeof atlasViews)[number]['id'];

const sysmonProblems = {
  access_denied: 'Windows denied this account access to the Sysmon event log.',
  channel_missing: 'The Sysmon event log was not found.',
  read_failed: 'NORTH could not read the Sysmon event log. It will retry.',
};

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

export function Network({ endpoint, openCase, openEvents, target, onTarget, demo, readOnly }: {
  endpoint: string; openCase: (id: string) => void; openEvents: (search: string) => void;
  target: AtlasTarget | null; onTarget: (target: null) => void; demo: boolean; readOnly: boolean;
}) {
  const [interval, setInterval] = useState(15000);
  const { inventory, fetchError, refresh, refreshing, lastRefresh } = useNetworkInventory(endpoint, interval);
  const [neighbors, setNeighbors] = useState<Neighbor[]>([]);
  const [fileMessage, setFileMessage] = useState('');
  const [search, setSearch] = useState('');
  const [wifiOnly, setWifiOnly] = useState(false);
  const [atlasView, setAtlasView] = useState<AtlasView>('devices');
  const activeView = target ? (target === 'atlas-windows-events' ? 'health' : 'devices') : atlasView;
  const [reviewing, setReviewing] = useState('');
  const [reviewError, setReviewError] = useState(false);
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
  const matchingApps = inventory?.app_connections?.filter((app) => fits(app.process)) ?? [];
  const matchesDevice = ([, records]: [string, Neighbor[]]) => records.some((record) =>
    fits(record.address, record.name, record.mac, record.network));
  const liveDevices = groupNeighbors(collector?.records ?? []);
  const importedDevices = groupNeighbors(neighbors);
  const watch = inventory?.device_findings;
  const router = inventory?.router_usage;
  const macKey = (mac: string) => mac.replace(/[:-]/g, '').toLowerCase();
  const trafficByMac = new Map(router?.devices.map((device) => [macKey(device.mac), device]));
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
    return {
      ...device, observations, name: names.size === 1 ? [...names][0] : '',
      total: device.download_bytes + device.upload_bytes,
    };
  }).filter((device) => (!wifiOnly || device.wifi_associated === true) &&
    (fits(device.mac, device.router_name ?? '') ||
      device.observations.some((record) => fits(record.name, record.address, record.network))))
    .sort((a, b) => b.total - a.total || a.mac.localeCompare(b.mac));
  const largestTrafficTotal = Math.max(1, routerDevices[0]?.total ?? 0);
  const mapDevices = liveDevices.filter(matchesDevice).map(([id, records]) => {
    const first = records[0];
    const observedName = records.find((record) => record.name)?.name;
    const label = observedName || records.find((record) => !record.address.includes(':'))?.address || first.address;
    return { id, label, observedName, network: first.network || 'Unknown interface', mac: first.mac,
      addresses: records.map((record) => record.address), states: [...new Set(records.map((record) => record.state).filter(Boolean))],
      traffic: trafficByMac.get(macKey(first.mac)) };
  });

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
      if (file.size > 2_000_000) throw new Error('Choose a JSON file smaller than 2 MB.');
      const records = readNeighbors(JSON.parse((await file.text()).replace(/^\uFEFF/, '')));
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

  function devicesList(devices: [string, Neighbor[]][]) {
    const matching = devices.filter(matchesDevice);
    return <>
      <ul className="network-list">{matching.map(([key, records]) => {
        const { address, name, mac, network } = records[0];
        return <li key={key}>
          <strong>{name || address}</strong>
          <small>{[mac, network, /VMware|VirtualBox|vEthernet/i.test(network) && 'Virtual adapter'].filter(Boolean).join(' · ')}</small>
          <small>{records.map((record) => [record.address, record.state].filter(Boolean).join(' · ')).join(' / ')}</small>
          <details className="device-explanation">
            <summary>Explain this device</summary>
            <p>{name ? 'The source supplied the label “' + name + '”.' : 'The available records do not identify the device model.'}
              {' '}Addresses here were grouped by interface and hardware address when both were available.</p>
            {records.map((record) => <p key={record.address}><strong>{record.address}</strong> · {explainAddress(record.address)}</p>)}
          </details>
        </li>;
      })}</ul>
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
    <AtlasMap devices={mapDevices} staleTraffic={router?.state === 'unavailable'} openEvents={openEvents} />
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
      <p>Addresses on the same interface with the same MAC are grouped. This is the PC’s recent view of the network.</p>
      {devicesList(liveDevices)}
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
      <p>Choose a Windows or Linux neighbor-cache export, or a router export formatted as JSON device records. A cache is a partial list of devices seen recently. The file stays in this browser tab.</p>
      <input type="file" accept=".json,application/json" aria-label="Import device inventory JSON"
        onChange={(event) => { const file = event.target.files?.[0]; if (file) void importNeighbors(file); event.target.value = ''; }} />
      {fileMessage && <p role="status">{fileMessage}</p>}
      {devicesList(importedDevices)}
    </details>
    </div>
    <div className="atlas-section-stack" hidden={activeView !== 'traffic'}>
    {router && <section className="panel">
      <h2>Router traffic by device</h2>
      <p>OpenWrt accounting-period totals, sorted by combined traffic.</p>
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
          <thead><tr><th scope="col">Device</th><th scope="col">Download</th><th scope="col">Upload</th><th scope="col">Total</th><th scope="col">Wi-Fi</th></tr></thead>
          <tbody>{routerDevices.map((device) => <tr key={device.mac}>
            <th scope="row">
              {device.router_name || device.name || device.mac}
              {(device.router_name || device.name) && <small>{device.mac} · {device.router_name ? 'DHCP lease' : 'Collector record'}</small>}
            </th>
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
    {inventory && !router && !inventory.local_device && !inventory.app_connections && <p>No traffic source is reporting to this collector.</p>}
    </div>
    <div className="atlas-section-stack" hidden={activeView !== 'health'}>
    {Array.isArray(inventory?.internet_health) && <section className="panel">
      <h2>Internet health from the collector</h2>
      <p>Default IPv4 gateway response, plus DNS lookup and HTTPS response time for NORTH Cloud. Some gateways block ping replies.</p>
      {latestHealth && <>
        <p className="reference">Last checked <time dateTime={latestHealth.checked_at}>{new Date(latestHealth.checked_at).toLocaleString()}</time></p>
        <dl className="health-summary">
          <div><dt>Gateway</dt><dd>{latestHealth.gateway === 'responded' ? 'Replied' : latestHealth.gateway === 'no_reply' ? 'No reply' : 'Unavailable'}</dd></div>
          <div><dt>DNS lookup</dt><dd>{latestHealth.dns_ms === null ? 'Failed' : latestHealth.dns_ms + ' ms'}</dd></div>
          <div><dt>HTTPS response</dt><dd>{latestHealth.https_ms === null ? 'No response' : latestHealth.https_ms + ' ms'}
            {latestHealth.http_status !== null && <small>HTTP {latestHealth.http_status}</small>}</dd></div>
        </dl>
      </>}
      {!inventory.internet_health.length && <p>Waiting for the first check.</p>}
      {inventory.internet_health.length > 0 && <details>
        <summary>Recent check history</summary>
        <div className="router-traffic-table-wrap">
        <table className="investigation-table router-traffic-table" aria-label="Collector internet checks">
          <thead><tr><th scope="col">Checked</th><th scope="col">Gateway</th><th scope="col">DNS</th><th scope="col">HTTPS</th><th scope="col">Response</th></tr></thead>
          <tbody>{inventory.internet_health.slice(-12).reverse().map((sample) => <tr key={sample.checked_at}>
            <td><time dateTime={sample.checked_at}>{new Date(sample.checked_at).toLocaleString()}</time></td>
            <td>{sample.gateway === 'responded' ? 'Replied' : sample.gateway === 'no_reply' ? 'No reply' : 'Unavailable'}</td>
            <td>{sample.dns_ms === null ? 'Lookup failed' : sample.dns_ms + ' ms'}</td>
            <td>{sample.https_ms === null ? 'No response' : sample.https_ms + ' ms'}</td>
            <td>{sample.http_status ?? '—'}</td>
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
