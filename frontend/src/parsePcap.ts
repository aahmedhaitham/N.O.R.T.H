export const maxTraceBytes = 8 * 1024 * 1024;
const maxPackets = 5000;

type Packet = { time: string; source: string; destination: string; protocol: string; bytes: number };

export function readPacketTrace(buffer: ArrayBuffer): { packets: Packet[]; limited: boolean } {
  if (buffer.byteLength < 24 || buffer.byteLength > maxTraceBytes) throw new Error('Choose a valid PCAP file up to 8 MiB.');
  const data = new DataView(buffer);
  const magic = data.getUint32(0);
  const little = magic === 0xd4c3b2a1 || magic === 0x4d3cb2a1;
  const nanos = magic === 0x4d3cb2a1 || magic === 0xa1b23c4d;
  if (!little && magic !== 0xa1b2c3d4 && !nanos) throw new Error('This viewer supports classic PCAP files.');
  if (data.getUint16(4, little) !== 2 || data.getUint16(6, little) !== 4 || (data.getUint32(20, little) & 0xffff) !== 1) {
    throw new Error('Choose a classic PCAP 2.4 capture with Ethernet headers.');
  }

  const packets: Packet[] = [];
  const u32 = (offset: number) => data.getUint32(offset, little);
  const ip = (offset: number, version: 4 | 6) => version === 4 ?
    Array.from({ length: 4 }, (_, index) => data.getUint8(offset + index)).join('.') :
    Array.from({ length: 8 }, (_, index) => data.getUint16(offset + 2 * index).toString(16)).join(':');
  const protocols: Record<number, string> = { 1: 'ICMP', 6: 'TCP', 17: 'UDP', 58: 'ICMPv6' };
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
    const packet = { time, source: '—', destination: '—', protocol: 'Ethernet', bytes };
    if (captured >= 14) {
      let type = data.getUint16(start + 12);
      let header = start + 14;
      while ((type === 0x8100 || type === 0x88a8) && header + 4 <= end) {
        type = data.getUint16(header + 2);
        header += 4;
      }
      if (type === 0x0800 && header + 20 <= end && data.getUint8(header) >> 4 === 4) {
        packet.source = ip(header + 12, 4);
        packet.destination = ip(header + 16, 4);
        packet.protocol = protocols[data.getUint8(header + 9)] ?? 'IPv4';
      } else if (type === 0x86dd && header + 40 <= end && data.getUint8(header) >> 4 === 6) {
        packet.source = ip(header + 8, 6);
        packet.destination = ip(header + 24, 6);
        packet.protocol = protocols[data.getUint8(header + 6)] ?? 'IPv6';
      } else if (type === 0x0806) {
        packet.protocol = 'ARP';
      }
    }
    packets.push(packet);
    offset = end;
  }
  return { packets, limited: offset < data.byteLength };
}
