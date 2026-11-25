const trafficAmount = new Intl.NumberFormat(undefined, { maximumFractionDigits: 1 });

export function formatTraffic(bytes: number) {
  if (bytes >= 1e12) return trafficAmount.format(bytes / 1e12) + ' TB';
  if (bytes >= 1e9) return trafficAmount.format(bytes / 1e9) + ' GB';
  if (bytes >= 1e6) return trafficAmount.format(bytes / 1e6) + ' MB';
  if (bytes >= 1e3) return trafficAmount.format(bytes / 1e3) + ' kB';
  return trafficAmount.format(bytes) + ' B';
}
