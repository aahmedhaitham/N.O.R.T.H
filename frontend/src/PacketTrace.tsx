import { useMemo, useRef, useState } from 'react';
import { maxTraceBytes, readPacketTrace } from './parsePcap';
import { formatTraffic } from './formatTraffic';

const pageSize = 50;
type Conversation = { a: string; b: string; packets: number; bytes: number };

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
  const [pair, setPair] = useState<Conversation | null>(null);
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
  const matching = (trace?.packets ?? []).filter((packet) => {
    if (protocol && packet.protocol !== protocol) return false;
    if (query && !packet.source.includes(query) && !packet.destination.includes(query)) return false;
    if (!pair) return true;
    const [a, b] = endpoints(packet.source, packet.destination);
    return a === pair.a && b === pair.b;
  });

  async function open(file: File) {
    const request = ++load.current;
    setTrace(null);
    setPage(0);
    setSearch('');
    setProtocol('');
    setPair(null);
    setMessage('Reading packet headers…');
    try {
      if (file.size > maxTraceBytes) throw new Error('Choose a capture up to 8 MiB.');
      const result = readPacketTrace(await file.arrayBuffer());
      if (request !== load.current) return;
      setTrace(result);
      setMessage((result.limited ? 'Showing the first 5,000 supported packets.' : `${result.packets.length} packets loaded.`) +
        (result.skipped ? ` Skipped ${result.skipped} unsupported packet records.` : ''));
    } catch (error) {
      if (request === load.current) setMessage(error instanceof Error ? error.message : 'Could not read the capture.');
    }
  }

  return <details className="panel">
    <summary>Inspect a packet trace</summary>
    <p>Open an Ethernet PCAP or PCAPNG from an authorized network. NORTH displays packet headers and keeps the file in this window.</p>
    <input type="file" accept=".pcap,.pcapng" aria-label="Open local packet capture" onChange={(event) => {
      const file = event.currentTarget.files?.[0];
      if (file) void open(file);
      event.currentTarget.value = '';
    }} />
    {message && <p role="status">{message}</p>}
    {trace && trace.packets.length > 0 && <>
      <p className="reference">{trace.packets.length.toLocaleString()} loaded packets · {formatTraffic(overview.bytes)} in original packet lengths</p>
      {overview.conversations.length > 0 && <div className="trace-conversations">
        <h3>Top address pairs</h3>
        <ul>{overview.conversations.map((item) => <li key={item.a + '|' + item.b}>
          <button type="button" aria-pressed={pair === item} onClick={() => {
            setPair(pair === item ? null : item);
            setSearch('');
            setProtocol('');
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
        {(search || protocol || pair) && <button type="button" onClick={() => {
          setSearch(''); setProtocol(''); setPair(null); setPage(0);
        }}>Clear filters</button>}
      </div>
      <p role="status">{matching.length.toLocaleString()} of {trace.packets.length.toLocaleString()} packets match</p>
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
