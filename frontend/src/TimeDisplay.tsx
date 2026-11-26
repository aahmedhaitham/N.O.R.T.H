import { TimeDisplayMessages as strings } from './messages';
import { useState, useSyncExternalStore } from 'react';
import { SelectControl } from './SelectControl';

const zoneKey = 'north-timezone';
let zone = 'local';
try { if (localStorage.getItem(zoneKey) === 'UTC') zone = 'UTC'; } catch { /* Use the local timezone. */ }
const relative = new Intl.RelativeTimeFormat(undefined, { numeric: 'auto' });
const absoluteFormats = {
  local: new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'long' }),
  UTC: new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'long', timeZone: 'UTC' }),
};
let clock = { now: Date.now(), zone };
let timer = 0;
const listeners = new Set<() => void>();
function tick() {
  clock = { now: Date.now(), zone };
  for (const listener of listeners) listener();
}
function subscribe(listener: () => void) {
  listeners.add(listener);
  if (!timer) timer = window.setInterval(tick, 15000);
  return () => {
    listeners.delete(listener);
    if (!listeners.size) { window.clearInterval(timer); timer = 0; }
  };
}
const getClock = () => clock;

export function formatAbsolute(value: string) {
  const timestamp = Date.parse(value);
  return Number.isFinite(timestamp) ? absoluteFormats[zone === 'UTC' ? 'UTC' : 'local'].format(timestamp) : '—';
}

export function TimeDisplay({ value }: { value?: string | null }) {
  const { now } = useSyncExternalStore(subscribe, getClock);
  const timestamp = value ? Date.parse(value) : NaN;
  if (!value || !Number.isFinite(timestamp)) return <span className="reference">—</span>;
  const seconds = Math.round((timestamp - now) / 1000);
  const magnitude = Math.abs(seconds);
  const label = magnitude < 60 ? relative.format(seconds, 'second') :
    magnitude < 3600 ? relative.format(Math.round(seconds / 60), 'minute') :
    magnitude < 86400 ? relative.format(Math.round(seconds / 3600), 'hour') : relative.format(Math.round(seconds / 86400), 'day');
  const absolute = formatAbsolute(value);
  return <time dateTime={value} title={absolute} aria-label={label + ', ' + absolute}>{label}</time>;
}

export function TimezoneControl() {
  const [selected, setSelected] = useState(zone);
  return <SelectControl label={strings.timezone} value={selected}
    options={[{ value: 'local', label: strings.systemTimezone }, { value: 'UTC', label: strings.utc }]}
    onChange={(value) => {
      zone = value;
      setSelected(value);
      try { localStorage.setItem(zoneKey, value); } catch { /* The session preference still applies. */ }
      tick();
    }} />;
}
