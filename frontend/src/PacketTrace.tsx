import { useMemo, useRef, useState } from 'react';
import { maxTraceBytes, readPacketTrace } from './parsePcap';
import { formatTraffic } from './formatTraffic';

const pageSize = 50;
type Conversation = { a: string; b: string; packets: number; bytes: number };
type Adapter = { id: number; label: string };

function endpoints(source: string, destination: string) {
  return source < destination ? [source, destination] : [destination, source];
}

function addressWithPort(address: string, port?: number) {
  if (port === undefined) return address;
  return (address.includes(':') ? '[' + address + ']' : address) + ':' + port;
}

export function PacketTrace() {
  const [trace, setTrace] = useState<ReturnType<typeof readPacketTrace> | null>(null);
  const [message, setMessage] = useState('');
  const [page, setPage] = useState(0);
  const [search, setSearch] = useState('');
  const [protocol, setProtocol] = useState('');
  const [port, setPort] = useState('');
  const [pair, setPair] = useState<Conversation | null>(null);
  const [adapters, setAdapters] = useState<Adapter[]>([]);
  const [adapter, setAdapter] = useState('');
  const [seconds, setSeconds] = useState(15);
  const [captureStatus, setCaptureStatus] = useState('');
  const [captureBusy, setCaptureBusy] = useState(false);
  const desktop = location.protocol === 'north:';
  const load = useRef(0);
  const overview = useMemo(() => {
    const groups = new Map<string, Conversation>();
    const protocols = new Set<string>();
    let bytes = 0;
    for (const packet of trace?.packets ?? []) {
      protocols.add(packet.protocol);
      bytes += packet.bytes;
      if (packet.source === '—' || packet.destination === '—') continue;
      const [a, b] = endpoints(packet.source, packet.destination);
      const key = a + '|' + b;
      const group = groups.get(key) ?? { a, b, packets: 0, bytes: 0 };
      group.packets++;
      group.bytes += packet.bytes;
      groups.set(key, group);
    }
    const conversations = [...groups.values()].sort((first, second) => second.bytes - first.bytes).slice(0, 5);
    return { bytes, protocols: [...protocols].sort(), conversations };
  }, [trace]);
  const query = search.trim().toLowerCase();
  const portQuery = port.trim();
  const invalidPort = Boolean(portQuery) && (!/^\d{1,5}$/.test(portQuery) || Number(portQuery) > 65535);
  const matching = (trace?.packets ?? []).filter((packet) => {
    if (protocol && packet.protocol !== protocol) return false;
    if (portQuery && (invalidPort || (packet.sourcePort !== Number(portQuery) && packet.destinationPort !== Number(portQuery)))) return false;
    if (query && !packet.source.includes(query) && !packet.destination.includes(query)) return false;
    if (!pair) return true;
    const [a, b] = endpoints(packet.source, packet.destination);
    return a === pair.a && b === pair.b;
  });
  const durations = matching.map((packet) => Date.parse(packet.time));
  const earliest = Math.min(...durations);
  const latest = Math.max(...durations);
  const intervalWidth = Math.max(1, (latest - earliest + 1) / 12);
  const volume = Array<number>(12).fill(0);
  for (let index = 0; index < matching.length; index++) {
    volume[Math.min(11, Math.floor((durations[index] - earliest) / intervalWidth))] += matching[index].bytes;
  }
  const peak = Math.max(1, ...volume);

  async function openCapture(read: () => Promise<ArrayBuffer>) {
    const request = ++load.current;
    setTrace(null);
    setPage(0);
    setSearch('');
    setProtocol('');
    setPort('');
    setPair(null);
    setMessage('Reading packet headers…');
    try {
      const result = readPacketTrace(await read());
      if (request !== load.current) return;
      setTrace(result);
      setMessage((result.limited ? 'Showing the first 5,000 supported packets.' : `${result.packets.length} packets loaded.`) +
        (result.skipped ? ` Skipped ${result.skipped} unsupported packet records.` : ''));
    } catch (error) {
      if (request === load.current) setMessage(error instanceof Error ? error.message : 'Could not read the capture.');
    }
  }

  async function listAdapters() {
    setCaptureBusy(true);
    setCaptureStatus('');
    try {
      const response = await fetch('/api/desktop/capture/interfaces');
      const body = await response.json();
      if (!response.ok) throw new Error(body.detail);
      const items: Adapter[] = body.interfaces;
      setAdapters(items);
      setAdapter('');
      if (items.length === 0) setCaptureStatus('No eligible capture adapters were found.');
    } catch (error) {
      setAdapters([]);
      setAdapter('');
      setCaptureStatus(error instanceof Error ? error.message : 'Adapters could not be listed.');
    } finally {
      setCaptureBusy(false);
    }
  }

  async function startCapture() {
    setCaptureBusy(true);
    setCaptureStatus('Waiting for capture confirmation and completion…');
    try {
      const response = await fetch('/api/desktop/capture/start', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ id: Number(adapter), seconds }),
      });
      if (response.status === 204) {
        setCaptureStatus('Capture cancelled.');
        return;
      }
      if (!response.ok) throw new Error((await response.json()).detail);
      await openCapture(() => response.arrayBuffer());
      setCaptureStatus('');
    } catch (error) {
      setCaptureStatus(error instanceof Error ? error.message : 'Capture could not finish.');
    } finally {
      setCaptureBusy(false);
    }
  }

  return <details className="panel">
    <summary>Inspect a packet trace</summary>
    <p>Open a PCAP or PCAPNG from an authorized network. NORTH reads Ethernet, loopback, raw IP, and Linux cooked headers and keeps the file in this window.</p>
    {desktop ? <details>
      <summary>Capture on this computer</summary>
      <p>Record a short trace on an authorized local adapter. Packet prefixes can contain payload bytes and stay in this app window.</p>
      <div className="event-filters">
        <button type="button" disabled={captureBusy} onClick={() => void listAdapters()}>Find adapters</button>
        {adapters.length > 0 && <>
          <label>Adapter <select value={adapter} disabled={captureBusy} onChange={(event) => setAdapter(event.target.value)}>
            <option value="">Select an adapter</option>
            {adapters.map((item) => <option key={item.id} value={item.id}>{item.label}</option>)}
          </select></label>
          <label>Duration <select value={seconds} disabled={captureBusy} onChange={(event) => setSeconds(Number(event.target.value))}>
            {[10, 15, 30].map((duration) => <option key={duration} value={duration}>{duration} seconds</option>)}
          </select></label>
          <button type="button" disabled={captureBusy || !adapter} onClick={() => void startCapture()}>Start capture</button>
        </>}
      </div>
      {captureStatus && <p role="status">{captureStatus}</p>}
    </details> : <details>
      <summary>Capture on this computer</summary>
      <p>The collector bundle includes a short capture tool for computers with Dumpcap and a working capture driver. Capture only on interfaces you’re authorized to monitor.</p>
      <pre>{'python tools/capture_north.py --list\npython tools/capture_north.py --interface 1 --seconds 15'}</pre>
      <p>Use the interface number from the list. The capture stops automatically and saves a local PCAPNG you can open here. Packet prefixes can contain payload bytes.</p>
    </details>}
    <input type="file" accept=".pcap,.pcapng" aria-label="Open local packet capture" disabled={captureBusy} onChange={(event) => {
      const file = event.currentTarget.files?.[0];
      if (file) void openCapture(() => {
        if (file.size > maxTraceBytes) throw new Error('Choose a capture up to 8 MiB.');
        return file.arrayBuffer();
      });
      event.currentTarget.value = '';
    }} />
    {message && <p role="status">{message}</p>}
    {trace && <button type="button" onClick={() => { setTrace(null); setMessage('Capture cleared from this window.'); }}>Clear capture</button>}
    {trace && trace.packets.length > 0 && <>
      <p className="reference">{trace.packets.length.toLocaleString()} loaded packets · {formatTraffic(overview.bytes)} in original packet lengths</p>
      {overview.conversations.length > 0 && <div className="trace-conversations">
        <h3>Top address pairs</h3>
        <ul>{overview.conversations.map((item) => <li key={item.a + '|' + item.b}>
          <button type="button" aria-pressed={pair === item} onClick={() => {
            setPair(pair === item ? null : item);
            setSearch('');
            setProtocol('');
            setPort('');
            setPage(0);
          }}><span>{item.a} ↔ {item.b}</span><small>{item.packets} packets · {formatTraffic(item.bytes)}</small></button>
        </li>)}</ul>
      </div>}
      <div className="event-filters trace-filters" role="group" aria-label="Filter packet headers">
        <label>Find an IP address
          <input type="search" value={search} onChange={(event) => { setSearch(event.target.value); setPage(0); }} />
        </label>
        <label>Protocol <select value={protocol} onChange={(event) => { setProtocol(event.target.value); setPage(0); }}>
          <option value="">All protocols</option>
          {overview.protocols.map((name) => <option key={name}>{name}</option>)}
        </select></label>
        <label>TCP or UDP port<input type="text" inputMode="numeric" value={port} maxLength={5}
          aria-invalid={invalidPort || undefined} onChange={(event) => { setPort(event.target.value); setPage(0); }} /></label>
        {(search || protocol || port || pair) && <button type="button" onClick={() => {
          setSearch(''); setProtocol(''); setPort(''); setPair(null); setPage(0);
        }}>Clear filters</button>}
      </div>
      <p role="status">{invalidPort ? 'Enter a port between 0 and 65535.' :
        `${matching.length.toLocaleString()} of ${trace.packets.length.toLocaleString()} packets match`}</p>
      {matching.length > 1 && latest > earliest && <section className="trace-volume">
        <h3>Matched traffic over time</h3>
        <div className="atlas-usage-chart" role="list" aria-label="Packet bytes by time interval">
          {volume.map((bytes, index) => <div className="atlas-usage-column" role="listitem" key={index}
            aria-label={`Interval ${index + 1}: ${formatTraffic(bytes)}`} title={formatTraffic(bytes)}>
            <span style={{ height: `${bytes / peak * 100}%` }} />
          </div>)}
        </div>
        <div className="trace-axis">
          <time>{new Date(earliest).toISOString().slice(11, 23)} UTC</time>
          <time>{new Date(latest).toISOString().slice(11, 23)} UTC</time>
        </div>
      </section>}
      {matching.length > 0 &&
      <div className="router-traffic-table-wrap">
        <table className="investigation-table" aria-label="Packet headers">
          <thead><tr><th scope="col">Time (UTC)</th><th scope="col">Source</th><th scope="col">Destination</th><th scope="col">Protocol</th><th scope="col">Bytes</th></tr></thead>
          <tbody>{matching.slice(page * pageSize, (page + 1) * pageSize).map((packet, index) =>
            <tr key={page * pageSize + index}>
              <td><time dateTime={packet.time}>{packet.time}</time></td>
              <td>{addressWithPort(packet.source, packet.sourcePort)}</td>
              <td>{addressWithPort(packet.destination, packet.destinationPort)}</td><td>{packet.protocol}</td><td>{packet.bytes}</td>
            </tr>)}</tbody>
        </table>
      </div>}
      {matching.length > pageSize && <div className="event-pagination">
        <button type="button" disabled={page === 0} onClick={() => setPage(page - 1)}>Previous</button>
        <span className="reference">Page {page + 1}</span>
        <button type="button" disabled={(page + 1) * pageSize >= matching.length} onClick={() => setPage(page + 1)}>Next</button>
      </div>}
    </>}
  </details>;
}
