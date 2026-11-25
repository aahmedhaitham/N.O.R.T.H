import { useState } from 'react';
import { Background, Controls, Position, ReactFlow, type Edge, type Node } from '@xyflow/react';

export type AtlasDevice = {
  id: string;
  label: string;
  network: string;
  mac: string;
  addresses: string[];
  states: string[];
  traffic?: { download_bytes: number; upload_bytes: number };
};

const trafficAmount = new Intl.NumberFormat(undefined, { maximumFractionDigits: 1 });
const virtual = /VMware|VirtualBox|vEthernet|Hyper-V/i;
const wireless = /wi-?fi|wlan|wireless/i;
const pageSize = 8;

function formatTraffic(bytes: number) {
  if (bytes >= 1e9) return trafficAmount.format(bytes / 1e9) + ' GB';
  if (bytes >= 1e6) return trafficAmount.format(bytes / 1e6) + ' MB';
  if (bytes >= 1e3) return trafficAmount.format(bytes / 1e3) + ' kB';
  return trafficAmount.format(bytes) + ' B';
}

function RouterTraffic({ traffic, stale }: { traffic: AtlasDevice['traffic']; stale: boolean }) {
  if (!traffic) return <section className="atlas-traffic">
    <h4>Router traffic</h4>
    <p>Traffic totals are unavailable for this device.</p>
  </section>;
  const rows = [
    { label: 'Downloaded', bytes: traffic.download_bytes },
    { label: 'Uploaded', bytes: traffic.upload_bytes },
  ];
  const scale = Math.max(1, ...rows.map(({ bytes }) => bytes));
  return <section className="atlas-traffic">
    <h4>Router traffic</h4>
    <p>{stale ? 'Last available router totals' : 'Router accounting period'}</p>
    <ul>
      {rows.map(({ label, bytes }) => <li className="atlas-traffic-row" key={label}>
        <span>{label}</span><strong>{formatTraffic(bytes)}</strong>
        <div className="atlas-traffic-track" aria-hidden="true">
          <span style={{ width: (bytes / scale) * 100 + '%' }} />
        </div>
      </li>)}
    </ul>
  </section>;
}

export function AtlasMap({ devices, staleTraffic }: { devices: AtlasDevice[]; staleTraffic: boolean }) {
  const [filter, setFilter] = useState('all');
  const [selected, setSelected] = useState('');
  const [page, setPage] = useState(0);
  const matching = devices.filter(({ network }) => filter === 'all' ||
    (filter === 'wifi' && wireless.test(network) && !virtual.test(network)) ||
    (filter === 'virtual' && virtual.test(network)))
    .sort((a, b) => Number(virtual.test(a.network)) - Number(virtual.test(b.network)) ||
      a.network.localeCompare(b.network) || a.id.localeCompare(b.id));
  const pageCount = Math.max(1, Math.ceil(matching.length / pageSize));
  const currentPage = Math.min(page, pageCount - 1);
  const displayed = matching.slice(currentPage * pageSize, (currentPage + 1) * pageSize);
  const groups = new Map<string, AtlasDevice[]>();
  for (const device of displayed) {
    const group = groups.get(device.network) ?? [];
    group.push(device);
    groups.set(device.network, group);
  }
  const nodes: Node[] = [];
  const edges: Edge[] = [];
  const selectedDevice = displayed.find((item) => 'device:' + item.id === selected) ?? displayed[0];
  let offset = 0;
  for (const [name, group] of groups) {
    const interfaceId = 'interface:' + name;
    nodes.push({ id: interfaceId, type: 'input', data: { label: name },
      position: { x: 0, y: offset + (group.length - 1) * 32 },
      sourcePosition: Position.Right, selectable: false, focusable: false, className: 'atlas-interface' });
    group.forEach((device, index) => {
      const id = 'device:' + device.id;
      nodes.push({ id, type: 'output', ariaLabel: device.label + ' on ' + name, data: { label: device.label },
        position: { x: 290, y: offset + index * 64 }, targetPosition: Position.Left,
        className: device === selectedDevice ? 'atlas-device atlas-selected' : 'atlas-device' });
      edges.push({ id, source: interfaceId, target: id, selectable: false, focusable: false });
    });
    offset += group.length * 64 + 22;
  }

  return <section className="panel atlas-map">
    <header className="atlas-map-heading">
      <div><h2>Network map</h2>
        <p>Devices grouped by the interface that observed them.</p></div>
      <label>Show <select value={filter} onChange={(event) => { setFilter(event.target.value); setPage(0); setSelected(''); }}>
        <option value="all">All interfaces</option><option value="wifi">Wi-Fi interfaces</option>
        <option value="virtual">Virtual adapters</option>
      </select></label>
    </header>
    {!displayed.length ? <p>No device observations match this view.</p> : <>
      <div className="atlas-toolbar atlas-pagination">
        <span className="reference">{currentPage * pageSize + 1}–{currentPage * pageSize + displayed.length} of {matching.length} observed devices</span>
        {pageCount > 1 && <>
          <button disabled={currentPage === 0} onClick={() => setPage(currentPage - 1)}>Previous</button>
          <button disabled={currentPage + 1 >= pageCount} onClick={() => setPage(currentPage + 1)}>Next</button>
        </>}
      </div>
      <div className="atlas-layout">
      <div className="graph atlas-canvas" aria-label="Observed network topology">
        <ReactFlow key={filter + '|' + displayed.map((item) => item.id).join('|')} nodes={nodes} edges={edges}
          onNodeClick={(_, node) => { if (node.id.startsWith('device:')) setSelected(node.id); }}
          onSelectionChange={({ nodes: selection }) => { if (selection[0]?.id.startsWith('device:')) setSelected(selection[0].id); }}
          fitView fitViewOptions={{ maxZoom: 1.2, padding: .1 }} minZoom={.1}
          nodesDraggable={false} nodesConnectable={false}>
          <Background gap={20} /><Controls showInteractive={false} />
        </ReactFlow>
      </div>
      {selectedDevice && <aside className="atlas-device-detail">
        <div className="atlas-device-heading">
          <span>Device inspector</span>
          <h3>{selectedDevice.label}</h3>
        </div>
        <label>Observed device
          <select value={'device:' + selectedDevice.id} onChange={(event) => setSelected(event.target.value)}>
            {displayed.map((item) => <option key={item.id} value={'device:' + item.id}>{item.label} · {item.network}</option>)}
          </select>
        </label>
        <dl>
          <dt>Observed on</dt><dd>{selectedDevice.network}</dd>
          <dt>MAC address</dt><dd>{selectedDevice.mac || 'Unavailable'}</dd>
          <dt>IP addresses</dt><dd>{selectedDevice.addresses.length ?
            selectedDevice.addresses.map((address) => <code key={address}>{address}</code>) : 'Unavailable'}</dd>
          <dt>Last observed state</dt><dd>{selectedDevice.states.join(' · ') || 'Unavailable'}</dd>
        </dl>
        <RouterTraffic traffic={selectedDevice.traffic} stale={staleTraffic} />
      </aside>}
      </div>
    </>}
  </section>;
}
