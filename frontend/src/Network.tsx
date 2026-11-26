import { feedbackMessages } from './messages';
import { clientMessages } from './messages';
import { NetworkMessages as strings, formatMessage } from './messages';
import { TimeDisplay, formatAbsolute } from './TimeDisplay';
import { SelectControl } from './SelectControl';
import { useEffect, useState } from 'react';
import { explainAddress } from './deviceExplanation';
import { AtlasMap } from './AtlasMap';
import { pollVisible } from './pollVisible';
import { PacketTrace } from './PacketTrace';
import { RemoteEndpointMap } from './RemoteEndpointMap';
import { LocalTcp } from './LocalTcp';
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
type AdapterRate = { sampled_at: string; receive_rate: number; send_rate: number };
type Finding = { id: string; first_seen: string; last_seen: string; reviewed_at: string | null;
  mac: string; interface: string; addresses: string[] };
type Snapshot = {
  assets: Host[]; links: Connection[];
  collector_synced_at?: string;
  local_device?: { host: string; addresses: { interface: string; address: string }[] };
  activity?: { interval: 'minute' | 'hour' | 'day' | null; buckets: { start: string; count: number }[];
    types: { kind: number; count: number }[] };
  neighbors?: Collector & { records: Neighbor[] };
  sysmon?: Collector & { session_events: number; recent?: boolean; problem?: 'access_denied' | 'channel_missing' | 'read_failed' | null };
  linux_journal?: Collector & { session_events: number };
  device_findings?: { baseline_at: string | null; unreviewed: number; items: Finding[] };
  router_usage?: Collector & { devices: ({
    mac: string; router_name?: string; router_ips?: string[]; wifi_associated?: boolean;
  } & TrafficTotals)[] };
  app_connections?: { process: string; events: number; destinations: number }[];
  adapter_traffic?: Collector & { adapters: { name: string; received_bytes: number; sent_bytes: number;
    receive_rate: number | null; send_rate: number | null; recent_rates?: AdapterRate[] }[] };
  internet_health?: HealthSample[];
};
type Neighbor = { address: string; mac: string; network: string; state: string; name: string };
export type AtlasTarget = 'atlas-new-devices' | 'atlas-windows-events' | 'atlas-linux-events' | 'atlas-local-devices';
const atlasViews = [
  { id: 'devices', label: strings.devices }, { id: 'traffic', label: strings.traffic },
  { id: 'health', label: strings.diagnostics }, { id: 'traces', label: strings.packetTraces },
  { id: 'remote', label: strings.remoteEndpoints },
] as const;
type AtlasView = (typeof atlasViews)[number]['id'];
const coverageFilters = [
  { id: 'all', label: strings.observedGroups }, { id: 'named', label: strings.namedGroups },
  { id: 'unnamed', label: strings.unnamedGroups }, { id: 'wifi', label: strings.routerWiFiConfirmed },
  { id: 'usage', label: strings.withRouterByteTotals },
] as const;
type CoverageFilter = (typeof coverageFilters)[number]['id'];

const sysmonProblems = {
  access_denied: feedbackMessages.windowsDeniedThisAccountAccessToThe,
  channel_missing: feedbackMessages.theSysmonEventLogWasNotFound,
  read_failed: feedbackMessages.northCouldNotReadTheSysmonEvent,
};

function httpsResult(sample: HealthSample) {
  if (sample.https_error === 'tls') return feedbackMessages.tlsFailed;
  if (sample.https_error === 'timeout') return feedbackMessages.timedOut;
  if (sample.https_ms === null) return feedbackMessages.noResponse;
  if (sample.cloud_probe && sample.http_status === 204) return feedbackMessages.cloudReached;
  if (sample.http_status === 401 || sample.http_status === 403) return feedbackMessages.reachedAccessDenied;
  if (sample.http_status !== null && sample.http_status >= 500) return feedbackMessages.reachedServiceError;
  return feedbackMessages.responseReceived;
}

function healthIsStale(sample: HealthSample) {
  return Date.now() - Date.parse(sample.checked_at) > 12 * 60 * 1000;
}

function readNeighbors(value: unknown): Neighbor[] {
  if (!Array.isArray(value)) throw new Error(clientMessages.chooseAJsonArrayOfDeviceRecords);
  if (value.length > 5000) throw new Error(clientMessages.chooseAFileWithAtMostDevice);
  return value.map((row, index) => {
    const address = row?.address ?? row?.dst;
    if (typeof address !== 'string' || !address.trim()) {
      throw new Error(feedbackMessages.deviceRecord + (index + 1) + feedbackMessages.isMissingAnAddress);
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

export function useNetworkInventory(endpoint: string) {
  const [inventory, setInventory] = useState<Snapshot | null>(null);
  const [fetchError, setFetchError] = useState(false);
  const [revision, setRevision] = useState(0);
  const [refreshing, setRefreshing] = useState(false);
  const [lastRefresh, setLastRefresh] = useState<string>();

  useEffect(() => {
    if (!endpoint) return;
    const controller = new AbortController();
    async function refresh() {
      setRefreshing(true);
      try {
        const response = await fetch(endpoint, { signal: controller.signal, cache: 'no-store' });
        if (!response.ok) throw new Error(clientMessages.inventoryUnavailable);
        const result: Snapshot = await response.json();
        if (result.neighbors) result.neighbors.records = readNeighbors(result.neighbors.records);
        if (!controller.signal.aborted) {
          setInventory(result);
          setFetchError(false);
          setLastRefresh(new Date().toISOString());
        }
      } catch {
        if (!controller.signal.aborted) setFetchError(true);
      } finally {
        if (!controller.signal.aborted) {
          setRefreshing(false);
        }
      }
    }
    const stop = pollVisible(refresh, endpoint.startsWith('/api/') ? 10000 : 0);
    return () => {
      controller.abort();
      stop();
    };
  }, [endpoint, revision]);

  return { inventory, fetchError, refreshing, lastRefresh, reloadAfterChange: () => setRevision((value) => value + 1) };
}

export function Network({ endpoint, openCase, openEvents, target, onTarget, demo, readOnly, labelSource, visible }: {
  endpoint: string; openCase: (id: string) => void; openEvents: (search: string) => void;
  target: AtlasTarget | null; onTarget: (target: null) => void; demo: boolean; readOnly: boolean;
  labelSource: string | null;
  visible: boolean;
}) {
  const { inventory, fetchError, refreshing, lastRefresh, reloadAfterChange } = useNetworkInventory(endpoint);
  const oldSnapshot = Boolean(inventory?.collector_synced_at &&
    Date.now() - Date.parse(inventory.collector_synced_at) > 3 * 60 * 1000);
  const [neighbors, setNeighbors] = useState<Neighbor[]>([]);
  const [fileMessage, setFileMessage] = useState('');
  const [search, setSearch] = useState('');
  const [wifiOnly, setWifiOnly] = useState(false);
  const [healthWindow, setHealthWindow] = useState(12);
  const [adapterSelection, setAdapterSelection] = useState('');
  const [atlasView, setAtlasView] = useState<AtlasView>('devices');
  const [traceLinks, setTraceLinks] = useState<{ source: string; destination: string }[]>([]);
  const [coverageFilter, setCoverageFilter] = useState<CoverageFilter>('all');
  const targetView = target === 'atlas-windows-events' || target === 'atlas-linux-events' ? 'health' : 'devices';
  const activeView = target ? targetView : atlasView;
  const showLocalTcp = activeView === 'traffic' && location.protocol === 'north:' && location.pathname === '/';
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
    if (!response.ok) throw new Error(clientMessages.deviceLabelCouldNotBeSaved);
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
      setAtlasView(targetView);
      onTarget(null);
    });
    return () => window.cancelAnimationFrame(frame);
  }, [endpoint, target, targetView, hasInventory, fetchError, refreshing, onTarget]);
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
  const selectedAdapter = adapterRows.find((item) => item.name === adapterSelection) ?? adapterRows[0];
  const adapterRates = selectedAdapter?.recent_rates?.slice(-12) ?? [];
  const maxAdapterRate = Math.max(1, ...adapterRates.map((sample) => sample.receive_rate + sample.send_rate));
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
    const nameSource = savedLabel ? feedbackMessages.workspaceLabel : traffic?.router_name ? feedbackMessages.routerDhcp : observedName ? (withRouter ? feedbackMessages.collectorObservation : feedbackMessages.importedList) :
      importedName ? feedbackMessages.importedRouterList : undefined;
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
    return { id, label, observedName: name, nameSource, savedLabel, network: first.network || feedbackMessages.unknownInterface, mac: first.mac,
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
      ['Device', feedbackMessages.nameSource, feedbackMessages.observedIpAddresses, feedbackMessages.macAddress, 'Interface', feedbackMessages.routerWiFiConfirmed,
        feedbackMessages.routerDownloadBytes, feedbackMessages.routerUploadBytes, feedbackMessages.routerSampleTime],
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
      if (!response.ok) throw new Error(clientMessages.reviewFailed);
      reloadAfterChange();
    } catch {
      setReviewError(true);
    } finally {
      setReviewing('');
    }
  }

  async function importNeighbors(file: File) {
    try {
      if (file.size > 2_000_000) throw new Error(clientMessages.chooseADeviceFileSmallerThanMb);
      const text = (await file.text()).replace(/^\uFEFF/, '');
      const records = readNeighbors(/\.json$/i.test(file.name) || text.trimStart().startsWith('[') ?
        JSON.parse(text) : readRouterCsv(text.trimStart()));
      setNeighbors(records);
      setFileMessage(records.length + feedbackMessages.deviceRecordsLoadedInThisTab);
    } catch (error) {
      setFileMessage(error instanceof Error ? error.message : feedbackMessages.couldNotReadThatFile);
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
        <table className="investigation-table device-inventory-table" aria-label={strings.observedDevices}>
          <thead><tr><th scope="col">{strings.device}</th><th scope="col">{strings.ipAddresses}</th><th scope="col">{strings.macAddress}</th>
            <th scope="col">{strings.observedOn}</th>{includeRouter && <th scope="col">{strings.routerUsage}</th>}</tr></thead>
          <tbody>{matching.map(({ key, records, traffic, name, nameSource }) => {
            const { address, mac, network } = records[0];
            return <tr key={key}>
              <th scope="row">{name || address}
                <small>{nameSource || strings.nameUnavailable}</small>
              </th>
              <td>{records.map((record) => <div key={record.address}>
                <button type="button" className="atlas-address-button" onClick={() => openEvents(record.address)}
                  aria-label={formatMessage(strings.searchIrisFor0, record.address)}>{record.address}</button>
                {record.state && <small>{record.state}</small>}
              </div>)}
              <details className="device-explanation">
                <summary>{strings.explainAddresses}</summary>
                {records.map((record) => <p key={record.address}><strong>{record.address}</strong> · {explainAddress(record.address)}</p>)}
              </details></td>
              <td>{mac ? <code>{mac}</code> : strings.unavailable}</td>
              <td>{network || strings.unknownInterface}{traffic?.wifi_associated && <small>{strings.seenOnRouterWiFi}</small>}</td>
              {includeRouter && <td>{traffic ? <>
                <span>↓ {formatTraffic(traffic.download_bytes)} · ↑ {formatTraffic(traffic.upload_bytes)}</span>
                {router?.state === 'unavailable' && <small>{strings.lastAvailableTotals}</small>}
              </> : <small>{strings.unavailable}</small>}</td>}
            </tr>;
          })}</tbody>
        </table>
      </div>}
      {devices.length > 0 && !matching.length && <p>{strings.noDevicesMatchThisSearch}</p>}
    </>;
  }

  return <main className="network atlas-workspace">
    <header className="dashboard-heading">
      <h1 id="atlas-heading" tabIndex={-1}>{strings.atlas}<span className="workspace-title">{strings.networkInventory}</span></h1>
    </header>
    <nav className="atlas-view-bar" aria-label={strings.atlasTools}>
      {atlasViews.map(({ id, label }) => <button key={id} type="button"
        aria-current={activeView === id ? 'page' : undefined} onClick={() => { setAtlasView(id); onTarget(null); }}>{label}</button>)}
    </nav>
    {fetchError && activeView !== 'traces' && <p role="status">{strings.theTelemetryInventoryIsTemporarilyUnavailable}</p>}
    {endpoint && !inventory && !fetchError && activeView !== 'traces' && <p role="status">{strings.loadingNetworkObservations}</p>}
    {activeView !== 'traces' && activeView !== 'remote' && <section className="panel atlas-toolbar" aria-label={strings.networkInventoryControls}>
      <label className="network-search">{showLocalTcp ? strings.findProcessOrAddress : strings.findDevice}
        <input type="search" placeholder={showLocalTcp ? strings.processPidIpOrPort : strings.hostIpOrMacAddress}
          value={search} onChange={(event) => setSearch(event.target.value)} />
      </label>
      {endpoint.startsWith('/api/') && <span className="atlas-live-state" data-state={fetchError || oldSnapshot ? 'waiting' : 'automatic'}>
        {fetchError ? strings.connectionInterruptedRetrying : oldSnapshot ? strings.automaticUpdatesNoNewSnapshotIn3 : strings.automaticUpdates}
      </span>}
      {inventory?.collector_synced_at ? <small>{strings.collectorSynced}<TimeDisplay value={inventory.collector_synced_at} /></small> :
        lastRefresh && <small>{demo ? strings.sampleDataLoaded : <>{strings.lastChecked}<TimeDisplay value={lastRefresh} /></>}</small>}
    </section>}
    <div className="atlas-section-stack" hidden={activeView !== 'devices'}>
    {observedDevices.length > 0 && <section className="panel" aria-labelledby="atlas-coverage">
      <h2 id="atlas-coverage">{strings.deviceCoverage}</h2>
      <div className="health-summary device-coverage-actions" role="group" aria-label={strings.filterObservedDevices}>
        {coverageFilters.map(({ id, label }) => <button key={id} type="button" aria-pressed={coverageFilter === id}
          onClick={() => setCoverageFilter(id)}>
          <span>{label}</span><strong>{observedDevices.filter((device) => matchesCoverage(device, id)).length.toLocaleString()}</strong>
        </button>)}
      </div>
      <button type="button" disabled={!mapDevices.length} onClick={exportInventory}>{strings.exportFilteredInventory}</button>
    </section>}
    {labelError && <p role="status">{strings.savedDeviceLabelsAreTemporarilyUnavailable}</p>}
    <AtlasMap devices={mapDevices} staleTraffic={router?.state === 'unavailable'} openEvents={openEvents}
      saveLabel={deviceLabels ? saveDeviceLabel : undefined} />
    {localDevice && <section className="panel">
      <h2>{strings.thisComputer}</h2>
      <p>{localDevice.host} · {adapters.size} {adapters.size === 1 ? strings.networkAdapter : strings.networkAdapters}</p>
      <ul className="network-list">{matchingAdapters.map(([name, addresses]) => <li key={name}>
        <strong>{name}</strong>
        <ul className="adapter-addresses">{[...addresses].sort((a, b) =>
          Number(a.includes(':')) - Number(b.includes(':')) || a.localeCompare(b),
        ).map((address) => <li key={address}><small>{address.includes(':') ? strings.ipv6 : strings.ipv4} <code>{address}</code></small></li>)}</ul>
      </li>)}</ul>
      {!matchingAdapters.length && <p>{query ? strings.noLocalAdaptersMatchThisSearch : strings.noNetworkAdaptersWithAddressesWereFound}</p>}
    </section>}
    {watch && (watch.baseline_at || collector?.state === 'starting') && <section className="panel">
      <h2 id="atlas-new-devices" tabIndex={-1}>{strings.newlyObservedDevices}</h2>
      <p>{watch.baseline_at ? <>{watch.unreviewed}{strings.awaitingReviewBaselineStarted}<TimeDisplay value={watch.baseline_at} /></> :
        strings.waitingForTheFirstUsableDeviceSnapshot}</p>
      {demo && <p>{strings.sampleFindingFromASyntheticNetwork}</p>}
      {reviewError && <p role="alert">{strings.thatFindingCouldNotBeMarkedAs}</p>}
      {!watch.items.length && watch.baseline_at && <p>{strings.noNewDevicesHaveAppearedSinceThe}</p>}
      <ul className="network-list">{watch.items.filter((item) => fits(item.mac, item.interface, ...item.addresses)).map((item) => (
        <li key={item.id}>
          <strong>{item.addresses.join(', ')}</strong>
          <small><code>{item.mac}</code> · {item.interface}{strings.firstSeen}<TimeDisplay value={item.first_seen} /></small>
          <small>{item.reviewed_at ? strings.reviewed : strings.needsReview}{strings.lastSeen}<TimeDisplay value={item.last_seen} /></small>
          <details className="device-explanation">
            <summary>{strings.whyDidThisAppear}</summary>
            <p>{strings.northSawThisHardwareAddressOnThis}</p>
            {item.addresses.map((address) => <p key={address}><strong>{address}</strong> · {explainAddress(address)}</p>)}
          </details>
          {!readOnly && !item.reviewed_at && <button className="network-case" disabled={Boolean(reviewing)}
            onClick={() => void review(item.id)}>{reviewing === item.id ? strings.saving : strings.markReviewed}</button>}
        </li>
      ))}</ul>
    </section>}
    {collector && collector.state !== 'disabled' && <section className="panel">
      <h2 id="atlas-local-devices" tabIndex={-1}>{strings.localNetworkDevices}</h2>
      <p role="status">{collector.state === 'starting' ? strings.readingTheLocalNeighborCache :
        collector.state === 'unavailable' ? strings.theCollectorCouldNotReadTheCache :
        <>{liveDevices.length}{strings.deviceGroupsLastRefreshed}<TimeDisplay value={collector.updated_at} /></>}</p>
      <p>{strings.addressesAreGroupedByInterfaceAndMac}</p>
      {mapDevices.length ? devicesList(liveDevices.filter(([id]) => visibleIds.has(id)), true) :
        liveDevices.length > 0 && <p>{strings.noObservedDevicesMatchTheCurrentFilters}</p>}
    </section>}
    <div className="columns">
      <section className="panel">
        <h2>{strings.reportingDevices}</h2>
        <ul className="network-list">{matchingHosts.map((asset) => <li key={asset.id}>
          <strong>{asset.host}</strong>
          <small>{asset.events}{strings.eventsLastSeen}<TimeDisplay value={asset.last_seen} /></small>
          <div className="case-links">
            {asset.host && <button type="button" className="network-case" onClick={() => openEvents(asset.host)}>{strings.searchHostInIris}</button>}
            {caseButtons(asset.cases)}
          </div>
        </li>)}</ul>
        {!matchingHosts.length && <p>{inventory ? strings.noReportingDevicesMatch : strings.loadingReportingDevices}</p>}
      </section>
      <section className="panel">
        <h2>{strings.observedConnections}</h2>
        <ul className="network-list">{matchingLinks.map((link) => <li key={link.asset_id + link.address + link.direction}>
          <strong>{link.address}</strong>
          <small>{link.direction === 'inbound' ? strings.inboundTo : strings.outboundFrom} {hosts.get(link.asset_id)} · {link.source} · {link.events} {link.events === 1 ? strings.event : strings.events}</small>
          <details className="device-explanation">
            <summary>{strings.explainThisAddress}</summary>
            <p>{explainAddress(link.address)}</p>
          </details>
          <div className="case-links">
            <button type="button" className="network-case" onClick={() => openEvents(link.address)}>{strings.searchAddressInIris}</button>
            {caseButtons(link.cases)}
          </div>
        </li>)}</ul>
        {!matchingLinks.length && <p>{inventory ? strings.noObservedConnectionsMatch : strings.loadingConnections}</p>}
      </section>
    </div>
    <details className="panel">
      <summary>{strings.importADeviceList}</summary>
      <p>{strings.openADeviceExportFromThisNetwork}</p>
      <input type="file" accept=".json,.csv,.tsv" aria-label={strings.importDeviceInventory}
        onChange={(event) => { const file = event.target.files?.[0]; if (file) void importNeighbors(file); event.target.value = ''; }} />
      {fileMessage && <p role="status">{fileMessage}</p>}
      {neighbors.length > 0 && <p><button type="button" onClick={() => {
        setNeighbors([]); setFileMessage(feedbackMessages.importedDeviceRecordsCleared);
      }}>{strings.clearImportedDevices}</button></p>}
      {devicesList(importedDevices)}
    </details>
    </div>
    <div className="atlas-section-stack" hidden={activeView !== 'traffic'}>
    {visible && showLocalTcp && <LocalTcp query={query} />}
    {adapterTraffic && <section className="panel">
      <h2>{strings.windowsAdapterTraffic}</h2>
      <p>{strings.trafficThroughTheSelectedEndpointSNetwork}</p>
      {adapterTraffic.updated_at && <p className="reference">{strings.lastSample}<TimeDisplay value={adapterTraffic.updated_at} /></p>}
      {adapterTraffic.state === 'unavailable' && <p role="status">{strings.adapterCountersCouldNotRefreshAnyRows}</p>}
      {adapterTraffic.state === 'starting' && <p>{strings.waitingForTheFirstAdapterSample}</p>}
      {adapterTraffic.state === 'ready' && !adapterRows.length && <p>{query ? strings.noAdaptersMatchTheSearch : strings.noAdapterCountersWereReported}</p>}
      {adapterRows.length > 0 && <div className="router-traffic-table-wrap">
        <table className="investigation-table router-traffic-table" aria-label={strings.windowsAdapterTraffic}>
          <thead><tr><th scope="col">{strings.adapter}</th><th scope="col">{strings.receiveRate}</th><th scope="col">{strings.sendRate}</th><th scope="col">{strings.receivedTotal}</th><th scope="col">{strings.sentTotal}</th></tr></thead>
          <tbody>{adapterRows.map((item) => <tr key={item.name}>
            <th scope="row"><button type="button" className="atlas-address-button" aria-pressed={item.name === selectedAdapter?.name}
              onClick={() => setAdapterSelection(item.name)}>{item.name}</button></th>
            <td>{item.receive_rate === null ? '—' : formatTraffic(item.receive_rate) + '/s'}</td>
            <td>{item.send_rate === null ? '—' : formatTraffic(item.send_rate) + '/s'}</td>
            <td>{formatTraffic(item.received_bytes)}</td><td>{formatTraffic(item.sent_bytes)}</td>
          </tr>)}</tbody>
        </table>
        {adapterRows.some((item) => item.receive_rate === null) && <p className="reference">{strings.ratesAppearAfterTwoSuccessfulSamplesWith}</p>}
      </div>}
      {selectedAdapter && <section className="adapter-rate-history" aria-label={formatMessage(strings.message0RateHistory, selectedAdapter.name)}>
        <h3>{selectedAdapter.name}{strings.rateHistory}</h3>
        {adapterRates.length === 0 ? <p>{strings.historyAppearsAfterTheAdapterReportsA}</p> : <>
          <p className="reference">{strings.receivedAndSentPerSecondBetweenSamples}</p>
          <div className="atlas-usage-chart" role="list" aria-label={strings.adapterRates}>
            {adapterRates.map((sample) => {
              const description = `${formatAbsolute(sample.sampled_at)} · ${formatTraffic(sample.receive_rate)}/s received · ${formatTraffic(sample.send_rate)}/s sent`;
              return <div className="atlas-usage-column" role="listitem" aria-label={description} title={description} key={sample.sampled_at}>
                <span style={{ height: `${sample.send_rate / maxAdapterRate * 100}%` }} />
                <span style={{ height: `${sample.receive_rate / maxAdapterRate * 100}%` }} />
              </div>;
            })}
          </div>
        </>}
      </section>}
    </section>}
    {router && <section className="panel">
      <h2>{strings.routerTrafficByDevice}</h2>
      <p>{strings.openwrtAccountingPeriodTotalsPerMacSorted}</p>
      {router.devices.length > 0 && <label className="router-wifi-filter">
        <input type="checkbox" checked={wifiOnly} onChange={(event) => setWifiOnly(event.target.checked)} />
        {strings.onlyDevicesSeenOnRouterWiFi}
      </label>}
      {router.state === 'unavailable' && <p role="status">{strings.routerDataIsUnavailableAnyFiguresBelow}</p>}
      {router.state === 'starting' && <p>{strings.waitingForTheFirstRouterUpdate}</p>}
      {router.updated_at && <p className="reference">{strings.lastUpdated}<TimeDisplay value={router.updated_at} /></p>}
      {router.state === 'ready' && !routerDevices.length && <p>{strings.noMatchingDeviceTotals}</p>}
      {routerDevices.length > 0 && <div className="router-traffic-table-wrap">
        <table className="investigation-table router-traffic-table" aria-label={strings.routerTrafficByDevice}>
          <thead><tr><th scope="col">{strings.device}</th><th scope="col">{strings.ipAddresses}</th><th scope="col" className="router-download">{strings.download}</th><th scope="col" className="router-upload">{strings.upload}</th><th scope="col">{strings.total}</th><th scope="col">{strings.wiFi}</th></tr></thead>
          <tbody>{routerDevices.map((device) => <tr key={device.mac}>
            <th scope="row">
              {device.savedLabel || device.router_name || device.name || device.mac}
              {(device.savedLabel || device.router_name || device.name) &&
                <small>{device.mac} · {device.savedLabel ? strings.workspaceLabel : device.router_name ? strings.dhcpLease : strings.collectorRecord}</small>}
            </th>
            <td>{(device.leaseIPs.length ? device.leaseIPs : device.observedIPs).map((address) =>
              <button key={address} type="button" className="atlas-address-button" onClick={() => openEvents(address)}
                aria-label={formatMessage(strings.searchIrisFor0, address)}>{address}</button>)}
              {device.leaseIPs.length ? <small>{strings.dhcpLease}</small> : device.observedIPs.length ? <small>{strings.collectorObservation}</small> : '—'}
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
            <td>{device.wifi_associated === true ? strings.seenOnRouterWiFi : '—'}</td>
          </tr>)}</tbody>
        </table>
      </div>}
    </section>}
    {(inventory?.local_device || Array.isArray(inventory?.app_connections)) && <section className="panel">
      <h2>{strings.appNetworkActivity}</h2>
      <p>{strings.connectionCountsFromTheSelectedEndpointS}</p>
      {!inventory.app_connections?.length && <p>{windowsEvents?.state === 'unavailable' ?
        strings.allowThisWindowsAccountToReadThe : strings.noAppConnectionsInTheAvailableEvent}</p>}
      {inventory.app_connections?.length ? (matchingApps.length ? <div className="router-traffic-table-wrap">
        <table className="investigation-table" aria-label={strings.appConnections}>
          <thead><tr><th scope="col">{strings.process}</th><th scope="col">{strings.connections}</th><th scope="col">{strings.destinations}</th></tr></thead>
          <tbody>{matchingApps.map((app) => <tr key={app.process}>
            <td><button type="button" className="atlas-address-button" onClick={() => openEvents(app.process)}
              aria-label={formatMessage(strings.searchIrisFor0, app.process)}>{app.process}</button></td>
            <td>{app.events.toLocaleString()}</td><td>{app.destinations.toLocaleString()}</td>
          </tr>)}</tbody>
        </table>
      </div> : <p>{strings.noProcessesMatchTheSearch}</p>) : null}
    </section>}
    {inventory && !router && !adapterTraffic && !inventory.local_device && !inventory.app_connections && <p>{strings.noTrafficSourceIsReportingToThis}</p>}
    </div>
    <div className="atlas-section-stack" hidden={activeView !== 'health'}>
    {Array.isArray(inventory?.internet_health) && <section className="panel">
      <h2>{strings.internetHealthFromTheCollector}</h2>
      <p>{strings.defaultIpv4GatewayResponsePlusDnsLookup}</p>
      {latestHealth && <>
        <p className="reference">{strings.lastChecked}<TimeDisplay value={latestHealth.checked_at} />
          {!demo && healthIsStale(latestHealth) && <strong className="health-stale">{strings.olderThan12Minutes}</strong>}</p>
        <dl className="health-summary">
          <div><dt>{strings.gateway}</dt><dd>{latestHealth.gateway === 'responded' ? strings.replied : latestHealth.gateway === 'no_reply' ? strings.noReply : strings.unavailable}</dd></div>
          <div><dt>{strings.dnsLookup}</dt><dd>{latestHealth.dns_ms === null ? strings.failed : formatMessage(strings.ms, latestHealth.dns_ms)}</dd></div>
          <div><dt>{strings.httpsResponse}</dt><dd>{httpsResult(latestHealth)}
            {latestHealth.https_ms !== null && <small>{latestHealth.https_ms}{strings.msHttp}{latestHealth.http_status}</small>}</dd></div>
        </dl>
      </>}
      {!inventory.internet_health.length && <p>{strings.waitingForTheFirstCheck}</p>}
      {inventory.internet_health.length > 0 && <details>
        <summary>{strings.recentCheckHistory}</summary>
        <label className="router-wifi-filter">{strings.show}<SelectControl label={strings.diagnosticHistoryRange} value={String(healthWindow)}
          onChange={(value) => setHealthWindow(Number(value))}
          options={[12, 72].map((value) => ({ value: String(value), label: formatMessage(strings.lastChecks, value) }))} /></label>
        <p className="reference">{strings.httpsRespondedIn}{respondingChecks}{strings.of}{healthHistory.length}{strings.sampledChecks}</p>
        <div className="diagnostic-history-chart" role="list" aria-label={strings.httpsResponseTimes}>
          {healthHistory.map((sample) => <div key={sample.checked_at} role="listitem"
            aria-label={`${formatAbsolute(sample.checked_at)}, ${httpsResult(sample)}${sample.https_ms === null ? '' : ', ' + sample.https_ms + ' ms'}`}
            title={`${httpsResult(sample)}${sample.https_ms === null ? '' : ' · ' + sample.https_ms + ' ms'}`}>
            <span data-missed={sample.https_ms === null || undefined}
              style={{ height: sample.https_ms === null ? '4px' : `max(2px, ${sample.https_ms / peakLatency * 100}%)` }} />
          </div>)}
        </div>
        <div className="router-traffic-table-wrap">
        <table className="investigation-table router-traffic-table" aria-label={strings.collectorInternetChecks}>
          <thead><tr><th scope="col">{strings.checked}</th><th scope="col">{strings.gateway}</th><th scope="col">{strings.dns}</th><th scope="col">{strings.https}</th><th scope="col">{strings.response}</th></tr></thead>
          <tbody>{[...healthHistory].reverse().map((sample) => <tr key={sample.checked_at}>
            <td><TimeDisplay value={sample.checked_at} /></td>
            <td>{sample.gateway === 'responded' ? strings.replied : sample.gateway === 'no_reply' ? strings.noReply : strings.unavailable}</td>
            <td>{sample.dns_ms === null ? strings.lookupFailed : formatMessage(strings.ms, sample.dns_ms)}</td>
            <td>{sample.https_ms === null ? strings.noResponse : formatMessage(strings.ms, sample.https_ms)}</td>
            <td>{sample.http_status === null ? httpsResult(sample) : formatMessage(strings.message0Http1, httpsResult(sample), sample.http_status)}</td>
          </tr>)}</tbody>
        </table>
        </div>
      </details>}
    </section>}
    <section className="panel">
      <h2 id="atlas-windows-events" tabIndex={-1}>{strings.windowsEventCollection}</h2>
      <p className="reference">{strings.forConnectionTelemetryEnableNetworkconnectEventId}</p>
      <p role="status">{!windowsEvents || windowsEvents.state === 'disabled' ? strings.noWindowsEventSourceIsActiveFor :
        windowsEvents.state === 'starting' ? strings.connectingToTheSysmonLog :
        windowsEvents.state === 'unavailable' ? sysmonProblems[windowsEvents.problem ?? 'read_failed'] :
        <>{windowsEvents.session_events} {windowsEvents.recent ? strings.recentEventsAvailable : strings.newEventsSinceLaunch}{strings.lastChecked2}<TimeDisplay value={windowsEvents.updated_at} /></>}</p>
    </section>
    {inventory?.linux_journal && <section className="panel">
      <h2 id="atlas-linux-events" tabIndex={-1}>{strings.linuxEventCollection}</h2>
      <p>{strings.collectsRecentOpensshAuthenticationFailuresAndSudo}</p>
      <p role="status">{inventory.linux_journal.state === 'unavailable' ?
        strings.theCollectorCouldNotReadTheSystem : inventory.linux_journal.state === 'starting' ?
        strings.waitingForTheFirstJournalCheck :
        <>{inventory.linux_journal.session_events}{strings.newEventsSinceLaunchLastChecked}<TimeDisplay value={inventory.linux_journal.updated_at} /></>}</p>
    </section>}
    {inventory && !inventory.internet_health && !inventory.linux_journal && (!windowsEvents || windowsEvents.state === 'disabled') && <p>{strings.thisCollectorHasNotSuppliedDiagnostics}</p>}
    </div>
    <div className="atlas-section-stack" hidden={activeView !== 'traces'}>
    <PacketTrace active={visible && activeView === 'traces'} onTrace={setTraceLinks} />
    </div>
    {visible && activeView === 'remote' && <RemoteEndpointMap links={inventory?.links ?? []} trace={traceLinks}
      source={labelSource} cloud={Boolean(labelSource)} localAddresses={inventory?.local_device?.addresses.map((entry) => entry.address) ?? []}
      inspectCollection={() => { setAtlasView('health'); onTarget(null); requestAnimationFrame(() => document.getElementById('atlas-windows-events')?.focus()); }} />}
  </main>;
}
