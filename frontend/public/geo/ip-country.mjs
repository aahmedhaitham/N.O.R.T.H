function ipv4(address) {
  const parts = address.split('.');
  if (parts.length !== 4 || parts.some((part) => !/^\d{1,3}$/.test(part) || Number(part) > 255)) return null;
  return Uint8Array.from(parts, Number);
}

export function publicAddress(address) {
  if (typeof address !== 'string' || address.length > 45) return null;
  const v4 = ipv4(address);
  if (v4) {
    const [a, b, c] = v4;
    if (a === 0 || a === 10 || a === 127 || a >= 224 ||
        (a === 100 && b >= 64 && b <= 127) || (a === 169 && b === 254) ||
        (a === 172 && b >= 16 && b <= 31) || (a === 192 && (b === 168 || (b === 0 && (c === 0 || c === 2)))) ||
        (a === 198 && (b === 18 || b === 19 || (b === 51 && c === 100))) ||
        (a === 203 && b === 0 && c === 113)) return null;
    return v4;
  }
  if (!address.includes(':')) return null;
  const normalized = address.toLowerCase();
  if (normalized.startsWith('::ffff:')) {
    const mapped = normalized.slice(7);
    if (mapped.includes('.')) return publicAddress(mapped);
    const groups = mapped.split(':');
    if (groups.length !== 2 || groups.some((group) => !/^[\da-f]{1,4}$/.test(group))) return null;
    const [high, low] = groups.map((group) => parseInt(group, 16));
    return publicAddress([high >> 8, high & 255, low >> 8, low & 255].join('.'));
  }
  const halves = normalized.split('::');
  if (halves.length > 2) return null;
  const left = halves[0] ? halves[0].split(':') : [];
  const right = halves[1] ? halves[1].split(':') : [];
  const missing = 8 - left.length - right.length;
  if ((halves.length === 1 && missing !== 0) || (halves.length === 2 && missing < 1)) return null;
  if ([...left, ...right].some((part) => !/^[\da-f]{1,4}$/.test(part))) return null;
  const parts = [...left, ...Array(missing).fill('0'), ...right].map((part) => parseInt(part, 16));
  if ((parts[0] & 0xe000) !== 0x2000 || (parts[0] === 0x2001 && parts[1] === 0x0db8) ||
      (parts[0] & 0xfff0) === 0x3ff0) return null;
  return Uint8Array.from(parts.flatMap((part) => [part >> 8, part & 255]));
}

function compare(data, index, bytes) {
  for (const byte of bytes) {
    const difference = data[index++] - byte;
    if (difference) return difference;
  }
  return 0;
}

function country(data, bytes) {
  const width = bytes.length;
  const recordSize = width * 2 + 2;
  if (data.length % recordSize) throw new Error('Invalid country database');
  let low = 0;
  let high = data.length / recordSize - 1;
  while (low <= high) {
    const middle = Math.floor((low + high) / 2);
    const offset = middle * recordSize;
    if (compare(data, offset, bytes) > 0) high = middle - 1;
    else if (compare(data, offset + width, bytes) < 0) low = middle + 1;
    else return String.fromCharCode(data[offset + width * 2], data[offset + width * 2 + 1]);
  }
  return null;
}

export function countryResolver(load) {
  const pending = new Map();
  return async (addresses) => {
    const locations = await Promise.all([...new Set(addresses)].slice(0, 500).map(async (address) => {
      const bytes = publicAddress(address);
      if (!bytes) return null;
      const file = bytes.length === 4 ? 'country-4.bin' : 'country-6.bin';
      if (!pending.has(file)) pending.set(file,
        Promise.resolve().then(() => load(file)).then((data) => new Uint8Array(data)).catch((error) => {
          pending.delete(file);
          throw error;
        }));
      const code = country(await pending.get(file), bytes);
      return code ? [address, code] : null;
    }));
    return Object.fromEntries(locations.filter(Boolean));
  };
}
