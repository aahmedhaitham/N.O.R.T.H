import { useRef, useState } from 'react';
import { maxTraceBytes, readPacketTrace } from './parsePcap';

const pageSize = 50;

export function PacketTrace() {
  const [trace, setTrace] = useState<ReturnType<typeof readPacketTrace> | null>(null);
  const [message, setMessage] = useState('');
  const [page, setPage] = useState(0);
  const load = useRef(0);

  async function open(file: File) {
    const request = ++load.current;
    setTrace(null);
    setPage(0);
    setMessage('Reading packet headers…');
    try {
      if (file.size > maxTraceBytes) throw new Error('Choose a PCAP file up to 8 MiB.');
      const result = readPacketTrace(await file.arrayBuffer());
      if (request !== load.current) return;
      setTrace(result);
      setMessage(result.limited ? 'Showing the first 5,000 packets.' : `${result.packets.length} packets loaded.`);
    } catch (error) {
      if (request === load.current) setMessage(error instanceof Error ? error.message : 'Could not read the capture.');
    }
  }

  return <details className="panel">
    <summary>Inspect a packet trace</summary>
    <p>Open a classic Ethernet PCAP from an authorized network. NORTH displays headers and keeps the file in this window.</p>
    <input type="file" accept=".pcap" aria-label="Open local PCAP" onChange={(event) => {
      const file = event.currentTarget.files?.[0];
      if (file) void open(file);
      event.currentTarget.value = '';
    }} />
    {message && <p role="status">{message}</p>}
    {trace && trace.packets.length > 0 && <>
      <div className="router-traffic-table-wrap">
        <table className="investigation-table" aria-label="Packet headers">
          <thead><tr><th scope="col">Time (UTC)</th><th scope="col">Source</th><th scope="col">Destination</th><th scope="col">Protocol</th><th scope="col">Bytes</th></tr></thead>
          <tbody>{trace.packets.slice(page * pageSize, (page + 1) * pageSize).map((packet, index) =>
            <tr key={page * pageSize + index}>
              <td><time dateTime={packet.time}>{packet.time}</time></td><td>{packet.source}</td>
              <td>{packet.destination}</td><td>{packet.protocol}</td><td>{packet.bytes}</td>
            </tr>)}</tbody>
        </table>
      </div>
      {trace.packets.length > pageSize && <div className="event-pagination">
        <button type="button" disabled={page === 0} onClick={() => setPage(page - 1)}>Previous</button>
        <span className="reference">Page {page + 1}</span>
        <button type="button" disabled={(page + 1) * pageSize >= trace.packets.length} onClick={() => setPage(page + 1)}>Next</button>
      </div>}
    </>}
  </details>;
}
