import { feedbackMessages } from './messages';
import { clientMessages } from './messages';
import { PacketTraceMessages as strings, formatMessage } from './messages';
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { maxTraceBytes, readPacketTrace } from './parsePcap';
import { formatTraffic } from './formatTraffic';
import { SelectControl } from './SelectControl';
import { TimeDisplay } from './TimeDisplay';

const pageSize = 50;
type Conversation = { a: string; b: string; packets: number; bytes: number };
type Adapter = { device: string; label: string };
type CaptureMode = 'live' | 'quick';

function endpoints(source: string, destination: string) {
  return source < destination ? [source, destination] : [destination, source];
}

function addressWithPort(address: string, port?: number) {
  if (port === undefined) return address;
  return (address.includes(':') ? '[' + address + ']' : address) + ':' + port;
}

export function PacketTrace({ active, onTrace }: {
  active: boolean; onTrace: (packets: { source: string; destination: string }[]) => void;
}) {
  const [trace, setTrace] = useState<ReturnType<typeof readPacketTrace> | null>(null);
  const [message, setMessage] = useState('');
  const [page, setPage] = useState(0);
  const [search, setSearch] = useState('');
  const [protocol, setProtocol] = useState('');
  const [port, setPort] = useState('');
  const [pair, setPair] = useState<Conversation | null>(null);
  const [adapters, setAdapters] = useState<Adapter[]>([]);
  const [adapter, setAdapter] = useState('');
  const [seconds, setSeconds] = useState(10);
  const [captureStatus, setCaptureStatus] = useState('');
  const [detecting, setDetecting] = useState(false);
  const [captureMode, setCaptureMode] = useState<CaptureMode | null>(null);
  const [paused, setPaused] = useState(false);
  const [elapsed, setElapsed] = useState(0);
  const desktop = location.protocol === 'north:';
  const capture = useRef<AbortController | null>(null);
  const pauseRequested = useRef(false);
  const filePicker = useRef<HTMLInputElement>(null);
  const load = useRef(0);
  useEffect(() => {
    if (trace) onTrace(trace.packets.map(({ source, destination }) => ({ source, destination })));
  }, [trace, onTrace]);
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
  const currentPage = Math.min(page, Math.max(0, Math.ceil(matching.length / pageSize) - 1));

  async function openCapture(read: () => Promise<ArrayBuffer>) {
    const request = ++load.current;
    setTrace(null);
    setPage(0);
    setSearch('');
    setProtocol('');
    setPort('');
    setPair(null);
    setMessage(strings.readingPacketHeaders);
    try {
      const result = readPacketTrace(await read());
      if (request !== load.current) return;
      setTrace(result);
      setMessage((result.limited ? feedbackMessages.showingTheFirstSupportedPackets : `${result.packets.length} packets loaded.`) +
        (result.skipped ? ` Skipped ${result.skipped} unsupported packet records.` : ''));
    } catch (error) {
      if (request === load.current) setMessage(error instanceof Error ? error.message : strings.couldNotReadTheCapture);
    }
  }

  const listAdapters = useCallback(async (signal?: AbortSignal) => {
    setDetecting(true);
    setCaptureStatus('');
    try {
      const response = await fetch('/api/desktop/capture/interfaces', { signal });
      const body = await response.json();
      if (signal?.aborted) return;
      if (!response.ok) throw new Error(body.detail);
      const items: Adapter[] = body.interfaces;
      setAdapters(items);
      setAdapter((selected) => items.some(({ device }) => device === selected) ? selected :
        (items.find(({ label }) => /^Wi-?Fi$/i.test(label)) ?? items[0])?.device ?? '');
      if (items.length === 0) setCaptureStatus(feedbackMessages.noEligibleCaptureAdaptersWereFound);
    } catch (error) {
      if (signal?.aborted) return;
      setAdapters([]);
      setAdapter('');
      setCaptureStatus(error instanceof Error ? error.message : feedbackMessages.adaptersCouldNotBeListed);
    } finally {
      if (!signal?.aborted) setDetecting(false);
    }
  }, []);

  useEffect(() => {
    if (!desktop || !active) return;
    const detection = new AbortController();
    void listAdapters(detection.signal);
    return () => {
      detection.abort();
      capture.current?.abort();
    };
  }, [desktop, active, listAdapters]);

  useEffect(() => {
    if (active) return;
    setCaptureMode(null);
    setCaptureStatus('');
  }, [active]);

  useEffect(() => {
    if (!captureMode) return;
    const start = performance.now();
    const timer = window.setInterval(() => setElapsed(Math.floor((performance.now() - start) / 1000)), 250);
    return () => window.clearInterval(timer);
  }, [captureMode]);

  async function startCapture(mode: CaptureMode) {
    if (capture.current || !adapter) return;
    const controller = new AbortController();
    load.current++;
    capture.current = controller;
    pauseRequested.current = false;
    setCaptureMode(mode);
    setElapsed(0);
    setCaptureStatus('');
    setMessage('');
    if (mode === 'live' && !paused) {
      setTrace(null);
      onTrace([]);
      setPair(null);
      setPage(0);
    }
    setPaused(false);
    try {
      do {
        const response = await fetch('/api/desktop/capture/start', {
          method: 'POST', headers: { 'Content-Type': 'application/json', 'X-North-Capture': 'local' },
          body: JSON.stringify({ device: adapter, seconds: mode === 'live' ? 3 : seconds }),
          signal: controller.signal,
        });
        if (response.status === 204 || controller.signal.aborted) return;
        if (!response.ok) throw new Error((await response.json()).detail);
        if (mode === 'quick') {
          await openCapture(() => response.arrayBuffer());
          break;
        }
        const batch = readPacketTrace(await response.arrayBuffer());
        if (controller.signal.aborted) return;
        setTrace((previous) => {
          const packets = [...(previous?.packets ?? []), ...batch.packets];
          return { ...batch, packets: packets.slice(-5000), limited: packets.length > 5000 || batch.limited || !!previous?.limited };
        });
      } while (!pauseRequested.current && !controller.signal.aborted);
    } catch (error) {
      if (!controller.signal.aborted) setCaptureStatus(error instanceof Error ? error.message : feedbackMessages.captureCouldNotFinish);
    } finally {
      capture.current = null;
      if (!controller.signal.aborted) {
        if (pauseRequested.current) setCaptureStatus((status) => status === feedbackMessages.pausingAfterTheCurrentBatch ? '' : status);
        setPaused(mode === 'live' && pauseRequested.current);
        setCaptureMode(null);
      }
    }
  }

  return <section className="trace-workspace" aria-labelledby="trace-heading">
    <header className="trace-header">
      <div><h2 id="trace-heading">{strings.packetCapture}</h2><p>{strings.recordLocalNetworkTrafficOrInspectA}</p></div>
      <button type="button" disabled={!!captureMode} onClick={() => filePicker.current?.click()}>{strings.openTraceFile}</button>
    </header>
    {desktop ? <section className="panel capture-console" aria-label={strings.captureOnThisComputer}>
      <div className="capture-state" data-recording={!!captureMode}>
        <span aria-hidden="true" />{captureMode ? strings.recording : paused ? strings.paused : detecting ? strings.detectingAdapters : adapter ? strings.readyToCapture : strings.adapterUnavailable}
        {captureMode && <time>{elapsed}{strings.s}</time>}
      </div>
      <div className="capture-controls">
          <label>{strings.networkAdapter}<SelectControl label={strings.networkAdapter2} value={adapter} disabled={detecting || !!captureMode} onChange={(value) => {
            setAdapter(value);
            setPaused(false);
          }} options={[{ value: '', label: strings.selectAnAdapter }, ...adapters.map((item) => ({ value: item.device, label: item.label }))]} /></label>
          {captureMode === 'live' ?
            <button type="button" disabled={!!captureStatus} onClick={() => {
              pauseRequested.current = true;
              setCaptureStatus(feedbackMessages.pausingAfterTheCurrentBatch);
            }}>{strings.pause}</button> :
            <button className="primary-action" type="button" disabled={detecting || !!captureMode || !adapter}
              onClick={() => void startCapture('live')}>{paused ? strings.resumeCapture : strings.startLiveCapture}</button>}
          <label>{strings.quickCapture}<SelectControl label={strings.quickCaptureDuration} value={String(seconds)} disabled={!!captureMode}
            onChange={(value) => setSeconds(Number(value))}
            options={[10, 15, 30].map((duration) => ({ value: String(duration), label: formatMessage(strings.seconds, duration) }))} /></label>
          <button type="button" disabled={detecting || !!captureMode || !adapter} onClick={() => void startCapture('quick')}>{strings.record}{seconds}{strings.s}</button>
          {!adapter && !detecting && <button type="button" onClick={() => void listAdapters()}>{strings.retryAdapterDetection}</button>}
      </div>
      {captureMode === 'quick' && <progress aria-label={strings.quickCaptureProgress} max={seconds} value={Math.min(elapsed, seconds)} />}
      <p className="capture-note">{strings.captureOnlyOnNetworksYouReAuthorized}</p>
      <p className="capture-feedback" role="status">{captureStatus || (paused ? strings.capturePausedTheRecordedPacketsAreAvailable :
        captureMode === 'live' ? strings.updatingEveryFewSecondsLeavingPacketTraces : '')}</p>
    </section> : <p className="reference">{strings.useNorthDesktopForLiveCaptureOr}</p>}
    <input ref={filePicker} hidden type="file" accept=".pcap,.pcapng" aria-label={strings.openLocalPacketCapture} onChange={(event) => {
      const file = event.currentTarget.files?.[0];
      if (file) {
        setPaused(false);
        void openCapture(() => {
          if (file.size > maxTraceBytes) throw new Error(clientMessages.chooseACaptureUpToMib);
          return file.arrayBuffer();
        });
      }
      event.currentTarget.value = '';
    }} />
    {message && <p role="status">{message}</p>}
    {trace && <section className="panel trace-results" aria-label={strings.capturedPackets}>
      <div className="trace-header">
        <div><h3>{strings.capturedPackets}</h3><p>{trace.packets.length.toLocaleString()}{strings.packets}{formatTraffic(overview.bytes)}
          {trace.limited && (captureMode === 'live' || paused ? strings.recentPacketsOnly : strings.packetLimitReached)}</p></div>
        <button type="button" disabled={!!captureMode} onClick={() => {
          setTrace(null);
          onTrace([]);
          setPaused(false);
          setMessage('');
        }}>{strings.clearTrace}</button>
      </div>
      {trace.packets.length > 0 && <>
      {overview.conversations.length > 0 && <div className="trace-conversations">
        <h3>{strings.topAddressPairs}</h3>
        <ul>{overview.conversations.map((item) => <li key={item.a + '|' + item.b}>
          <button type="button" aria-pressed={pair?.a === item.a && pair?.b === item.b} onClick={() => {
            setPair(pair?.a === item.a && pair?.b === item.b ? null : item);
            setSearch('');
            setProtocol('');
            setPort('');
            setPage(0);
          }}><span>{item.a} ↔ {item.b}</span><small>{item.packets}{strings.packets}{formatTraffic(item.bytes)}</small></button>
        </li>)}</ul>
      </div>}
      <div className="event-filters trace-filters" role="group" aria-label={strings.filterPacketHeaders}>
        <label>{strings.findAnIpAddress}
          <input type="search" value={search} onChange={(event) => { setSearch(event.target.value); setPage(0); }} />
        </label>
        <label>{strings.protocol}<SelectControl label={strings.packetProtocol} value={protocol}
          onChange={(value) => { setProtocol(value); setPage(0); }}
          options={[{ value: '', label: strings.allProtocols }, ...overview.protocols.map((name) => ({ value: name, label: name }))]} /></label>
        <label>{strings.tcpOrUdpPort}<input type="text" inputMode="numeric" value={port} maxLength={5}
          aria-invalid={invalidPort || undefined} onChange={(event) => { setPort(event.target.value); setPage(0); }} /></label>
        {(search || protocol || port || pair) && <button type="button" onClick={() => {
          setSearch(''); setProtocol(''); setPort(''); setPair(null); setPage(0);
        }}>{strings.clearFilters}</button>}
      </div>
      <p role="status">{invalidPort ? strings.enterAPortBetween0And65535 :
        formatMessage(strings.message0Of1PacketsMatch, matching.length.toLocaleString(), trace.packets.length.toLocaleString())}</p>
      {matching.length > 1 && latest > earliest && <section className="trace-volume">
        <h3>{strings.matchedTrafficOverTime}</h3>
        <div className="atlas-usage-chart" role="list" aria-label={strings.packetBytesByTimeInterval}>
          {volume.map((bytes, index) => <div className="atlas-usage-column" role="listitem" key={index}
            aria-label={formatMessage(strings.interval01, index + 1, formatTraffic(bytes))} title={formatTraffic(bytes)}>
            <span style={{ height: `${bytes / peak * 100}%` }} />
          </div>)}
        </div>
        <div className="trace-axis">
          <time>{new Date(earliest).toISOString().slice(11, 23)}{strings.utc}</time>
          <time>{new Date(latest).toISOString().slice(11, 23)}{strings.utc}</time>
        </div>
      </section>}
      {matching.length > 0 &&
      <div className="router-traffic-table-wrap">
        <table className="investigation-table" aria-label={strings.packetHeaders}>
          <thead><tr><th scope="col">{strings.time}</th><th scope="col">{strings.source}</th><th scope="col">{strings.destination}</th><th scope="col">{strings.protocol2}</th><th scope="col">{strings.bytes}</th></tr></thead>
          <tbody>{matching.slice(currentPage * pageSize, (currentPage + 1) * pageSize).map((packet, index) =>
            <tr key={currentPage * pageSize + index}>
              <td><TimeDisplay value={packet.time} /></td>
              <td className="packet-endpoint">{addressWithPort(packet.source, packet.sourcePort)}</td>
              <td className="packet-endpoint">{addressWithPort(packet.destination, packet.destinationPort)}</td><td>{packet.protocol}</td><td>{packet.bytes}</td>
            </tr>)}</tbody>
        </table>
      </div>}
      {matching.length > pageSize && <div className="event-pagination">
        <button type="button" disabled={currentPage === 0} onClick={() => setPage(currentPage - 1)}>{strings.previous}</button>
        <span className="reference">{strings.page}{currentPage + 1}</span>
        <button type="button" disabled={(currentPage + 1) * pageSize >= matching.length} onClick={() => setPage(currentPage + 1)}>{strings.next}</button>
      </div>}
    </>}
    </section>}
  </section>;
}
