import { SelectControl } from './SelectControl';
import { useState } from 'react';
import { Background, Controls, Position, ReactFlow, type Edge, type Node } from '@xyflow/react';
import { explainAddress, explainMacAddress } from './deviceExplanation';
import { formatTraffic, type TrafficTotals } from './formatTraffic';

export type AtlasDevice = {
  id: string;
  label: string;
  observedName?: string;
  nameSource?: string;
  savedLabel?: string;
  network: string;
  mac: string;
  addresses: string[];
  states: string[];
  traffic?: TrafficTotals;
};

const virtual = /VMware|VirtualBox|vEthernet|Hyper-V/i;
const wireless = /wi-?fi|wlan|wireless/i;
const pageSize = 8;

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
  const intervals = Array.isArray(traffic.recent_usage) ? traffic.recent_usage.slice(-12) : [];
  const peak = intervals.reduce((largest, sample) => Math.max(largest, sample.download_bytes + sample.upload_bytes), 1);
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
    {intervals.length > 0 && <details className="atlas-address-context">
      <summary>Recent usage intervals</summary>
      <p>Bytes transferred per interval</p>
      <div className="atlas-usage-chart" aria-hidden="true">
        {intervals.map((interval) => <div key={interval.to} className="atlas-usage-column">
          <span style={{ height: `${interval.upload_bytes / peak * 100}%` }} />
          <span style={{ height: `${interval.download_bytes / peak * 100}%` }} />
        </div>)}
      </div>
      <ul>{[...intervals].reverse().map((interval) => <li key={interval.to}>
        <p>{new Date(interval.from).toLocaleTimeString()}–{new Date(interval.to).toLocaleTimeString()}</p>
        <p>↓ {formatTraffic(interval.download_bytes)} · ↑ {formatTraffic(interval.upload_bytes)}</p>
      </li>)}</ul>
    </details>}
  </section>;
}

function DeviceLabel({ mac, label, save }: { mac: string; label: string; save: (mac: string, label: string) => Promise<void> }) {
  const [draft, setDraft] = useState(label);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState('');
  async function submit() {
    setBusy(true);
    setMessage('');
    try {
      await save(mac, draft.trim());
      setDraft(draft.trim());
      setMessage(draft.trim() ? 'Label saved.' : 'Label removed.');
    } catch {
      setMessage('Could not save the label. Try again.');
    } finally {
      setBusy(false);
    }
  }
  return <form className="atlas-device-label" onSubmit={(event) => { event.preventDefault(); void submit(); }}>
    <label>Workspace label<input value={draft} maxLength={64} disabled={busy}
      placeholder="e.g. My iPhone" onChange={(event) => setDraft(event.target.value)} /></label>
    <button type="submit" disabled={busy || draft.trim() === label}>{draft.trim() ? 'Save label' : 'Remove label'}</button>
    {message && <p role="status">{message}</p>}
  </form>;
}

export function AtlasMap({ devices, staleTraffic, openEvents, saveLabel }: {
  devices: AtlasDevice[]; staleTraffic: boolean; openEvents: (search: string) => void;
  saveLabel?: (mac: string, label: string) => Promise<void>;
}) {
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
  const macContext = selectedDevice ? explainMacAddress(selectedDevice.mac) : '';
  const selectedMac = selectedDevice?.mac.replace(/[:-]/g, '').toLowerCase() ?? '';
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
      <label>Show <SelectControl label="Network interfaces" value={filter}
        onChange={(value) => { setFilter(value); setPage(0); setSelected(''); }}
        options={[{ value: 'all', label: 'All interfaces' }, { value: 'wifi', label: 'Wi-Fi interfaces' },
          { value: 'virtual', label: 'Virtual adapters' }]} /></label>
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
          <SelectControl label="Observed device" value={'device:' + selectedDevice.id} onChange={setSelected}
            options={displayed.map((item) => ({ value: 'device:' + item.id, label: item.label + ' · ' + item.network }))} />
        </label>
        {saveLabel && /^[0-9a-f]{12}$/.test(selectedMac) && selectedMac !== '000000000000' &&
          <DeviceLabel key={selectedMac} mac={selectedMac} label={selectedDevice.savedLabel ?? ''} save={saveLabel} />}
        <dl>
          <dt>Observed on</dt><dd>{selectedDevice.network}</dd>
          <dt>MAC address</dt><dd>{selectedDevice.mac || 'Unavailable'}</dd>
          <dt>IP addresses</dt><dd>{selectedDevice.addresses.length ?
            selectedDevice.addresses.map((address) => <button key={address} type="button" className="atlas-address-button"
              aria-label={`Search IRIS for ${address}`} onClick={() => openEvents(address)}>
              <code>{address}</code><span aria-hidden="true">↗</span>
            </button>) : 'Unavailable'}</dd>
          <dt>Last observed state</dt><dd>{selectedDevice.states.join(' · ') || 'Unavailable'}</dd>
        </dl>
        <details className="atlas-address-context" key={selectedDevice.id}>
          <summary>Explain device evidence</summary>
          {selectedDevice.observedName && <p><strong>{selectedDevice.observedName}</strong> · {selectedDevice.nameSource}</p>}
          {selectedDevice.addresses.map((address) => <div key={address}>
            <code>{address}</code>
            <p>{explainAddress(address)}</p>
          </div>)}
          {macContext && <p>{macContext}</p>}
          <p>Device model and physical location require an inventory or another verified source.</p>
        </details>
        <RouterTraffic traffic={selectedDevice.traffic} stale={staleTraffic} />
      </aside>}
      </div>
    </>}
  </section>;
}
