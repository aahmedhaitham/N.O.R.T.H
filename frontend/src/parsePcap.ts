export const maxTraceBytes = 8 * 1024 * 1024;
const maxPackets = 5000;

type Packet = { time: string; source: string; destination: string; protocol: string; bytes: number;
  sourcePort?: number; destinationPort?: number };
const protocols: Record<number, string> = { 1: 'ICMP', 6: 'TCP', 17: 'UDP', 58: 'ICMPv6' };
const sectionHeader = 0x0a0d0d0a;
const linkTypes = new Map([
  [1, { label: 'Ethernet', headerLength: 14, typeOffset: 12 }],
  [101, { label: 'Raw IP', headerLength: 0, typeOffset: null }],
  [113, { label: 'Linux cooked', headerLength: 16, typeOffset: 14 }],
  [276, { label: 'Linux cooked v2', headerLength: 20, typeOffset: 0 }],
]);

function ipv6Address(data: DataView, offset: number) {
  const words = Array.from({ length: 8 }, (_, index) => data.getUint16(offset + 2 * index).toString(16));
  let start = 0, length = 1;
  for (let index = 0; index < words.length;) {
    if (words[index] !== '0') { index++; continue; }
    const first = index;
    while (words[index] === '0') index++;
    if (index - first > length) { start = first; length = index - first; }
  }
  return length > 1 ? words.slice(0, start).join(':') + '::' + words.slice(start + length).join(':') : words.join(':');
}

function parsePacket(data: DataView, start: number, end: number, time: string, bytes: number,
  link: NonNullable<ReturnType<typeof linkTypes.get>>): Packet {
  const packet: Packet = { time, source: '—', destination: '—', protocol: link.label, bytes };
  if (end <= start || end - start < link.headerLength) return packet;
  const ip = (offset: number, version: 4 | 6) => version === 4 ?
    Array.from({ length: 4 }, (_, index) => data.getUint8(offset + index)).join('.') :
    ipv6Address(data, offset);
  const version = data.getUint8(start) >> 4;
  let type = link.typeOffset === null ? (version === 4 ? 0x0800 : version === 6 ? 0x86dd : 0) :
    data.getUint16(start + link.typeOffset);
  let header = start + link.headerLength;
  while ((type === 0x8100 || type === 0x88a8) && header + 4 <= end) {
    type = data.getUint16(header + 2);
    header += 4;
  }
  let transport = end;
  let ipEnd = end;
  if (type === 0x0800 && header + 20 <= end && data.getUint8(header) >> 4 === 4) {
    packet.source = ip(header + 12, 4);
    packet.destination = ip(header + 16, 4);
    packet.protocol = protocols[data.getUint8(header + 9)] ?? 'IPv4';
    const headerLength = (data.getUint8(header) & 15) * 4;
    const firstFragment = (data.getUint16(header + 6) & 0x1fff) === 0;
    if (headerLength >= 20 && firstFragment) transport = header + headerLength;
    ipEnd = Math.min(end, header + data.getUint16(header + 2));
  } else if (type === 0x86dd && header + 40 <= end && data.getUint8(header) >> 4 === 6) {
    packet.source = ip(header + 8, 6);
    packet.destination = ip(header + 24, 6);
    transport = header + 40;
    ipEnd = Math.min(end, transport + data.getUint16(header + 4));
    let next = data.getUint8(header + 6);
    while (transport + 2 <= ipEnd && (next === 0 || next === 43 || next === 44 || next === 60)) {
      const following = data.getUint8(transport);
      if (next === 44) {
        if (transport + 8 > ipEnd) break;
        if (data.getUint16(transport + 2) & 0xfff8) {
          transport = end;
          next = following;
          break;
        }
        transport += 8;
      } else {
        transport += (data.getUint8(transport + 1) + 1) * 8;
      }
      next = following;
    }
    packet.protocol = protocols[next] ?? 'IPv6';
  } else if (type === 0x0806) {
    packet.protocol = 'ARP';
  }
  if ((packet.protocol === 'TCP' || packet.protocol === 'UDP') && transport + 4 <= ipEnd) {
    packet.sourcePort = data.getUint16(transport);
    packet.destinationPort = data.getUint16(transport + 2);
  }
  return packet;
}

function readClassic(data: DataView) {
  const magic = data.getUint32(0);
  const little = magic === 0xd4c3b2a1 || magic === 0x4d3cb2a1;
  const nanos = magic === 0x4d3cb2a1 || magic === 0xa1b23c4d;
  if (!little && magic !== 0xa1b2c3d4 && !nanos) throw new Error('This viewer supports PCAP and PCAPNG files.');
  const link = linkTypes.get(data.getUint32(20, little) & 0xffff);
  if (data.getUint16(4, little) !== 2 || data.getUint16(6, little) !== 4 || !link) {
    throw new Error('Choose a PCAP 2.4 file with Ethernet, raw IP, or Linux cooked headers.');
  }

  const packets: Packet[] = [];
  const u32 = (offset: number) => data.getUint32(offset, little);
  let offset = 24;
  while (offset < data.byteLength && packets.length < maxPackets) {
    if (offset + 16 > data.byteLength) throw new Error('The packet record header is incomplete.');
    const fraction = u32(offset + 4);
    const captured = u32(offset + 8);
    const bytes = u32(offset + 12);
    const start = offset + 16;
    const end = start + captured;
    if (end > data.byteLength || captured > bytes || fraction >= (nanos ? 1e9 : 1e6)) {
      throw new Error('The file contains an invalid packet record.');
    }
    const time = new Date(u32(offset) * 1000 + fraction / (nanos ? 1e6 : 1e3)).toISOString();
    packets.push(parsePacket(data, start, end, time, bytes, link));
    offset = end;
  }
  return { packets, limited: offset < data.byteLength, skipped: 0 };
}

function readNextGeneration(data: DataView) {
  const packets: Packet[] = [];
  const interfaces: { linkType: number; ticksPerSecond: number; offsetSeconds: number }[] = [];
  let little = false;
  let offset = 0;
  let skipped = 0;
  while (offset < data.byteLength && packets.length < maxPackets) {
    if (offset + 12 > data.byteLength) throw new Error('The PCAPNG block header is incomplete.');
    const section = data.getUint32(offset) === sectionHeader;
    if (section) {
      const marker = data.getUint32(offset + 8);
      if (marker !== 0x1a2b3c4d && marker !== 0x4d3c2b1a) throw new Error('Invalid PCAPNG byte order.');
      little = marker === 0x4d3c2b1a;
      interfaces.length = 0;
    }
    const type = data.getUint32(offset, little);
    const length = data.getUint32(offset + 4, little);
    const end = offset + length - 4;
    if (length < 12 || length % 4 || end + 4 > data.byteLength || data.getUint32(end, little) !== length) {
      throw new Error('The file contains an invalid PCAPNG block.');
    }
    if (section && (length < 28 || data.getUint16(offset + 12, little) !== 1)) {
      throw new Error('Unsupported PCAPNG section version.');
    }
    if (type === 1) {
      if (length < 20) throw new Error('The PCAPNG interface description is incomplete.');
      const entry = { linkType: data.getUint16(offset + 8, little), ticksPerSecond: 1e6, offsetSeconds: 0 };
      for (let option = offset + 16; option + 4 <= end;) {
        const code = data.getUint16(option, little);
        const size = data.getUint16(option + 2, little);
        if (code === 0) break;
        const value = option + 4;
        option = value + Math.ceil(size / 4) * 4;
        if (option > end) throw new Error('Invalid PCAPNG interface option.');
        if (code === 9 && size === 1) {
          const resolution = data.getUint8(value);
          entry.ticksPerSecond = (resolution & 128 ? 2 : 10) ** (resolution & 127);
        }
        if (code === 14 && size === 8) entry.offsetSeconds = Number(data.getBigInt64(value, little));
      }
      interfaces.push(entry);
    } else if (type === 6) {
      if (length < 32) throw new Error('The PCAPNG packet block is incomplete.');
      const entry = interfaces[data.getUint32(offset + 8, little)];
      const captured = data.getUint32(offset + 20, little);
      const bytes = data.getUint32(offset + 24, little);
      const start = offset + 28;
      if (!entry || start + Math.ceil(captured / 4) * 4 > end || captured > bytes) {
        throw new Error('The file contains an invalid PCAPNG packet record.');
      }
      const link = linkTypes.get(entry.linkType);
      if (link) {
        const ticks = data.getUint32(offset + 12, little) * 2 ** 32 + data.getUint32(offset + 16, little);
        const date = new Date((entry.offsetSeconds + ticks / entry.ticksPerSecond) * 1000);
        if (!Number.isFinite(date.getTime())) throw new Error('The PCAPNG timestamp is out of range.');
        packets.push(parsePacket(data, start, start + captured, date.toISOString(), bytes, link));
      } else {
        skipped++;
      }
    } else if (type === 2 || type === 3) {
      skipped++;
    }
    offset += length;
  }
  return { packets, limited: offset < data.byteLength, skipped };
}

export function readPacketTrace(buffer: ArrayBuffer) {
  if (buffer.byteLength < 24 || buffer.byteLength > maxTraceBytes) throw new Error('Choose a valid capture up to 8 MiB.');
  const data = new DataView(buffer);
  return data.getUint32(0) === sectionHeader ? readNextGeneration(data) : readClassic(data);
}
