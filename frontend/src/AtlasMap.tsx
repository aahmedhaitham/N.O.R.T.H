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

const mb = new Intl.NumberFormat(undefined, { maximumFractionDigits: 2 });
const virtual = /VMware|VirtualBox|vEthernet|Hyper-V/i;
const wireless = /wi-?fi|wlan|wireless/i;

export function AtlasMap({ devices, staleTraffic }: { devices: AtlasDevice[]; staleTraffic: boolean }) {
  const [filter, setFilter] = useState('all');
  const [selected, setSelected] = useState('');
  const matching = devices.filter(({ network }) => filter === 'all' ||
    (filter === 'wifi' && wireless.test(network) && !virtual.test(network)) ||
    (filter === 'virtual' && virtual.test(network)));
  const displayed = matching.slice(0, 60);
  const groups = new Map<string, AtlasDevice[]>();
  for (const device of displayed) {
    const group = groups.get(device.network) ?? [];
    group.push(device);
    groups.set(device.network, group);
  }
  const nodes: Node[] = [];
  const edges: Edge[] = [];
  let offset = 0;
  for (const [name, group] of groups) {
    const interfaceId = 'interface:' + name;
    nodes.push({ id: interfaceId, data: { label: name }, position: { x: 0, y: offset },
      sourcePosition: Position.Right, selectable: false, className: 'atlas-interface' });
    group.forEach((device, index) => {
      const id = 'device:' + device.id;
      nodes.push({ id, data: { label: device.label }, position: { x: 290 + (index % 3) * 250,
        y: offset + Math.floor(index / 3) * 78 }, targetPosition: Position.Left,
        className: 'atlas-device', selected: selected === id });
      edges.push({ id, source: interfaceId, target: id });
    });
    offset += Math.ceil(group.length / 3) * 78 + 60;
  }
  const device = displayed.find((item) => 'device:' + item.id === selected);

  return <section className="panel atlas-map">
    <header className="atlas-map-heading">
      <div><h2>Network map</h2>
        <p>Devices grouped by the interface that observed them. Lines show observations, and Wi-Fi labels come from interface names.</p></div>
      <label>Show <select value={filter} onChange={(event) => setFilter(event.target.value)}>
        <option value="all">All interfaces</option><option value="wifi">Wi-Fi interfaces</option>
        <option value="virtual">Virtual adapters</option>
      </select></label>
    </header>
    {!displayed.length ? <p>No device observations match this view.</p> : <>
      <p className="reference">{displayed.length} of {matching.length} devices shown. Select a device to inspect its addresses and usage.</p>
      <div className="graph atlas-canvas" aria-label="Observed network topology">
        <ReactFlow key={filter + '|' + displayed.map((item) => item.id).join('|')} nodes={nodes} edges={edges}
          onNodeClick={(_, node) => { if (node.id.startsWith('device:')) setSelected(node.id); }}
          onSelectionChange={({ nodes: selection }) => { if (selection[0]?.id.startsWith('device:')) setSelected(selection[0].id); }}
          fitView fitViewOptions={{ maxZoom: 1, padding: .14 }} minZoom={.1}
          nodesDraggable={false} nodesConnectable={false} colorMode="dark">
          <Background gap={20} /><Controls showInteractive={false} />
        </ReactFlow>
      </div>
      {device && <div className="atlas-device-detail" aria-live="polite">
        <h3>{device.label}</h3>
        <p>{[device.network, device.mac, ...device.addresses].filter(Boolean).join(' · ')}</p>
        <p>{device.states.join(' · ')}</p>
        <p>{device.traffic ? `${mb.format(device.traffic.download_bytes / 1e6)} MB downloaded · ${mb.format(device.traffic.upload_bytes / 1e6)} MB uploaded · ${staleTraffic ? 'Last available router totals' : 'Router accounting period'}` :
          'Traffic totals are unavailable for this device.'}</p>
      </div>}
    </>}
  </section>;
}
