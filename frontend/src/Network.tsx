import { useEffect, useState } from 'react';

type CaseReference = { id: string; title: string };
type Host = { id: string; host: string; events: number; last_seen: string; cases: CaseReference[] };
type Connection = {
  asset_id: string; address: string; direction: 'inbound' | 'outbound';
  events: number; last_seen: string; cases: CaseReference[]; source: string;
};
type Collector = { state: 'starting' | 'disabled' | 'ready' | 'unavailable'; updated_at: string | null; records: Neighbor[] };
type Snapshot = { assets: Host[]; links: Connection[]; neighbors?: Collector };
type Neighbor = { address: string; mac: string; network: string; state: string; name: string };

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

function groupNeighbors(records: Neighbor[]) {
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

export function Network({ endpoint, openCase }: { endpoint: string; openCase: (id: string) => void }) {
  const [inventory, setInventory] = useState<Snapshot | null>(null);
  const [fetchError, setFetchError] = useState(false);
  const [neighbors, setNeighbors] = useState<Neighbor[]>([]);
  const [fileMessage, setFileMessage] = useState('');
  const [search, setSearch] = useState('');
  const query = search.trim().toLowerCase();
  const fits = (...values: string[]) => values.some((value) => value.toLowerCase().includes(query));
  const hosts = new Map(inventory?.assets.map((asset) => [asset.id, asset.host]));
  const matchingHosts = inventory?.assets.filter((asset) => fits(asset.host)) ?? [];
  const matchingLinks = inventory?.links.filter((link) => fits(link.address, hosts.get(link.asset_id) ?? '')) ?? [];
  const collector = inventory?.neighbors;
  const matchesDevice = ([, records]: [string, Neighbor[]]) => records.some((record) =>
    fits(record.address, record.name, record.mac, record.network));
  const liveDevices = groupNeighbors(collector?.records ?? []);
  const importedDevices = groupNeighbors(neighbors);

  useEffect(() => {
    if (!endpoint) return;
    const controller = new AbortController();
    let timer: number | undefined;
    async function refresh() {
      try {
        const response = await fetch(endpoint, { signal: controller.signal, cache: 'no-store' });
        if (!response.ok) throw new Error('Inventory unavailable');
        const result: Snapshot = await response.json();
        if (result.neighbors) result.neighbors.records = readNeighbors(result.neighbors.records);
        if (!controller.signal.aborted) {
          setInventory(result);
          setFetchError(false);
        }
      } catch {
        if (!controller.signal.aborted) setFetchError(true);
      } finally {
        if (!controller.signal.aborted && endpoint.startsWith('/api/')) {
          timer = window.setTimeout(refresh, 5000);
        }
      }
    }
    void refresh();
    return () => {
      controller.abort();
      window.clearTimeout(timer);
    };
  }, [endpoint]);

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
        </li>;
      })}</ul>
      {devices.length > 0 && !matching.length && <p>No devices match this search.</p>}
    </>;
  }

  return <main className="network">
    <header className="panel overview">
      <div>
        <h1>Network inventory</h1>
        <p>Review devices that sent telemetry, their observed connections, and device records from your network.</p>
      </div>
      <label className="network-search">Find a host, IP address or MAC address
        <input type="search" value={search} onChange={(event) => setSearch(event.target.value)} />
      </label>
    </header>
    {fetchError && <p role="status">The telemetry inventory is temporarily unavailable.</p>}
    {collector && collector.state !== 'disabled' && <section className="panel">
      <h2>Local network devices</h2>
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
          <div className="case-links">{caseButtons(asset.cases)}</div>
        </li>)}</ul>
        {!matchingHosts.length && <p>{inventory ? 'No reporting devices match.' : 'Loading reporting devices…'}</p>}
      </section>
      <section className="panel">
        <h2>Observed connections</h2>
        <ul className="network-list">{matchingLinks.map((link) => <li key={link.asset_id + link.address + link.direction}>
          <strong>{link.address}</strong>
          <small>{link.direction === 'inbound' ? 'Inbound to' : 'Outbound from'} {hosts.get(link.asset_id)} · {link.source} · {link.events} {link.events === 1 ? 'event' : 'events'}</small>
          <div className="case-links">{caseButtons(link.cases)}</div>
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
  </main>;
}
