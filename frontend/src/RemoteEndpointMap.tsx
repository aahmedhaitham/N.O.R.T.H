import { clientMessages } from './messages';
import { RemoteEndpointMapMessages as strings } from './messages';
import { useEffect, useMemo, useState } from 'react';
import { useAssistant } from './Assistant';
import { SelectControl } from './SelectControl';
import './remote-map.css';

type Point = [number, number];
type Country = {
  properties: { code: string; name: string; lon: number; lat: number };
  geometry: { type: 'Polygon' | 'MultiPolygon'; coordinates: Point[][] | Point[][][] };
};
type World = { features: Country[] };
type Lookup = (addresses: string[]) => Promise<Record<string, string>>;
type Link = { address: string; direction: string; events: number };
type TraceLink = { source: string; destination: string };
type MapData = { world: World; observed: Record<string, string>; trace: Record<string, string> };
const originKey = 'north-map-origin';
const desktop = location.protocol === 'north:';
let browserLookup: Promise<Lookup> | undefined;

async function resolveHere(addresses: string[]) {
  if (!addresses.length) return {};
  if (desktop) {
    const response = await fetch('/api/desktop/remote-locations', {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(addresses),
    });
    if (!response.ok) throw new Error(clientMessages.lookupFailed);
    return response.json() as Promise<Record<string, string>>;
  }
  const module = new URL('/geo/ip-country.mjs', location.href).href;
  browserLookup ??= import(/* @vite-ignore */ module).then(({ countryResolver }) => countryResolver(async (file: string) => {
    const response = await fetch('/geo/' + file);
    if (!response.ok || response.headers.get('Content-Type')?.includes('text/html')) throw new Error(clientMessages.lookupFailed);
    return response.arrayBuffer();
  })).catch((error) => { browserLookup = undefined; throw error; });
  return (await browserLookup!)(addresses);
}

const project = ([lon, lat]: Point): Point => [(lon + 180) * 2, (90 - lat) * 2];
function countryPath(country: Country) {
  const { coordinates, type } = country.geometry;
  const polygons = (type === 'Polygon' ? [coordinates] : coordinates) as Point[][][];
  return polygons.flatMap((polygon) => polygon.map((ring) =>
    ring.map((point, index) => (index ? 'L' : 'M') + project(point).map((value) => value.toFixed(1)).join(' ')).join('') + 'Z',
  )).join('');
}
function readOrigin() {
  try { return localStorage.getItem(originKey) ?? ''; } catch { return ''; }
}

export function RemoteEndpointMap({ links, trace, source, cloud, localAddresses, inspectCollection }: {
  links: Link[]; trace: TraceLink[]; source?: string | null; cloud: boolean;
  localAddresses: string[]; inspectCollection: () => void;
}) {
  const publishLocations = useAssistant()?.locations;
  const [origin, setOrigin] = useState(readOrigin);
  const [data, setData] = useState<MapData | null>(null);
  const [failed, setFailed] = useState(false);
  const [retry, setRetry] = useState(0);
  const [pcAddresses, setPcAddresses] = useState(localAddresses);
  const [traceOrigin, setTraceOrigin] = useState('');
  useEffect(() => {
    if (!desktop) return;
    const request = new AbortController();
    void fetch('/api/desktop/remote-locations', { signal: request.signal }).then(async (response) => {
      if (response.ok) setPcAddresses(await response.json());
    }).catch(() => {});
    return () => request.abort();
  }, []);
  const localIpKey = JSON.stringify([...new Set([...localAddresses, ...pcAddresses, traceOrigin.trim()])]);
  const outbound = useMemo(() => links.filter((link) => link.direction === 'outbound'), [links]);
  const observedAddresses = JSON.stringify([...new Set(outbound.map((link) => link.address))].slice(0, 500));
  const traceCounts = useMemo(() => {
    const locals = new Set<string>(JSON.parse(localIpKey));
    const counts = new Map<string, number>();
    for (const packet of trace) {
      if (!locals.has(packet.source)) continue;
      counts.set(packet.destination, (counts.get(packet.destination) ?? 0) + 1);
    }
    return counts;
  }, [trace, localIpKey]);
  const traceAddresses = JSON.stringify([...traceCounts.keys()].slice(0, 500));

  useEffect(() => {
    const request = new AbortController();
    async function lookupObserved() {
      const addresses: string[] = JSON.parse(observedAddresses);
      if (!addresses.length) return {};
      if (!cloud || desktop) return resolveHere(addresses);
      const response = await fetch('/api/network/remote-locations?source=' + encodeURIComponent(source ?? ''),
        { signal: request.signal });
      if (!response.ok) throw new Error(clientMessages.lookupFailed);
      return response.json() as Promise<Record<string, string>>;
    }
    Promise.all([
      fetch('/geo/world.json', { signal: request.signal }).then(async (response) => {
        if (!response.ok) throw new Error(clientMessages.mapUnavailable);
        return response.json() as Promise<World>;
      }),
      lookupObserved(), resolveHere(JSON.parse(traceAddresses)),
    ]).then(([world, observed, trace]) => {
      if (!request.signal.aborted) { setData({ world, observed, trace }); setFailed(false); }
    }).catch(() => { if (!request.signal.aborted) setFailed(true); });
    return () => request.abort();
  }, [observedAddresses, traceAddresses, source, cloud, retry]);

  const features = useMemo(() => data?.world.features.map((item) => ({ ...item.properties, path: countryPath(item) })) ?? [], [data?.world]);
  useEffect(() => {
    if (!data) return;
    const names = new Intl.DisplayNames(undefined, { type: 'region' });
    publishLocations?.(Object.fromEntries(Object.entries(data.observed).map(([address, code]) => [address, names.of(code) ?? code])));
  }, [data, publishLocations]);
  if (failed) return <section className="panel"><h2>{strings.remoteEndpointLocationApproximate}</h2>
    <p role="status">{strings.countryDataCouldNotLoad}</p><button type="button" onClick={() => { setFailed(false); setRetry(retry + 1); }}>{strings.retry}</button></section>;
  if (!data) return <section className="panel"><h2>{strings.remoteEndpointLocationApproximate}</h2><p role="status">{strings.loadingCountryData}</p></section>;

  const countries = new Map<string, { events: number; packets: number }>();
  function record(code: string | undefined, field: 'events' | 'packets', count: number) {
    if (!code) return;
    const totals = countries.get(code) ?? { events: 0, packets: 0 };
    totals[field] += count;
    countries.set(code, totals);
  }
  for (const link of outbound) record(data.observed[link.address], 'events', link.events);
  for (const [address, count] of traceCounts) record(data.trace[address], 'packets', count);
  const countryNames = new Intl.DisplayNames(undefined, { type: 'region' });
  const sorted = [...countries].sort((a, b) => b[1].events + b[1].packets - a[1].events - a[1].packets);
  const from = features.find((item) => item.code === origin);
  const fromPoint = from && project([from.lon, from.lat]);

  return <section className="panel remote-endpoints" aria-labelledby="remote-map-heading">
    <header><h2 id="remote-map-heading">{strings.remoteEndpointLocationApproximate}</h2>
      <p>{strings.countryLevelEstimatesForRecordedOutboundConnections}</p></header>
    <label className="remote-origin">{strings.originCountryForThisPc}
      <SelectControl label={strings.originCountryForThisPc} value={origin} options={[{ value: '', label: strings.chooseCountryForArcs },
        ...features.filter((item) => /^[A-Z]{2}$/.test(item.code)).sort((a, b) => a.name.localeCompare(b.name))
          .map((item) => ({ value: item.code, label: item.name }))]}
        onChange={(next) => { setOrigin(next); try { localStorage.setItem(originKey, next); } catch { /* Use this session only. */ } }} />
    </label>
    {trace.length > 0 && <label className="remote-origin">{strings.localSourceIpInTheTrace}
      <input type="text" value={traceOrigin} maxLength={45} placeholder={strings.optionalIfDetected}
        onChange={(event) => setTraceOrigin(event.target.value)} />
    </label>}
    <svg viewBox="0 0 720 360" className="remote-world" role="img" aria-label={strings.worldMapOfApproximateRemoteDestinationCountries}>
      {features.map((item) => <path key={item.name} d={item.path} data-destination={countries.has(item.code)} />)}
      {sorted.map(([code]) => {
        const destination = features.find((item) => item.code === code);
        if (!destination) return null;
        const [x, y] = project([destination.lon, destination.lat]);
        return <g key={code}>
          <title>{destination.name}</title>
          {fromPoint && origin !== code && <path className="remote-arc" d={'M' + fromPoint.join(' ') + ' Q' +
            (x + fromPoint[0]) / 2 + ' ' + Math.max(6, Math.min(y, fromPoint[1]) - 32) + ' ' + x + ' ' + y} />}
          <circle className="remote-destination" cx={x} cy={y} r={3} />
        </g>;
      })}
      {fromPoint && <circle className="remote-from" cx={fromPoint[0]} cy={fromPoint[1]} r={4} />}
    </svg>
    {!outbound.length && !traceCounts.size && <div>
      <p>{strings.noOutboundConnectionsAreAvailableEnableNetwork}</p>
      <button type="button" onClick={inspectCollection}>{strings.enableConnectionCollection}</button>
    </div>}
    {trace.length > 0 && !traceCounts.size && <p className="reference">{strings.theTraceHasNoOutboundPacketsThat}</p>}
    {outbound.length + traceCounts.size > 0 && !sorted.length && <p>{strings.noPublicDestinationInTheseRecordsCould}</p>}
    {sorted.length > 0 && <ul className="remote-countries">{sorted.map(([code, totals]) => <li key={code}>
      <strong>{countryNames.of(code) ?? code}</strong><span>{totals.events}{strings.connectionEvents}{totals.packets}{strings.tracePackets}</span>
    </li>)}</ul>}
    <p className="reference">{strings.countryBoundariesNaturalEarthCountryEstimates}<a href="https://db-ip.com/" target="_blank" rel="noreferrer">{strings.ipGeolocationByDbIp}</a>{strings.liteNovember2026}</p>
  </section>;
}
