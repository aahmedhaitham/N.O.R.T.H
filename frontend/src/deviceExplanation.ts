import { clientMessages } from './messages';
export function explainAddress(value: string) {
  const address = value.trim().toLowerCase().split('%')[0];
  if (address.includes(':')) {
    let canonical: string;
    try {
      canonical = new URL('http://[' + address + ']').hostname.slice(1, -1);
    } catch {
      return clientMessages.thisValueIsNotARecognizedIp;
    }
    if (canonical === '::1') return clientMessages.ipvLoopbackThisAddressRefersToThe;
    const prefix = Number.parseInt(canonical.split(':')[0], 16);
    if ((prefix & 0xffc0) === 0xfe80) return clientMessages.linkLocalIpvItIsUsedOn;
    if ((prefix & 0xfe00) === 0xfc00) return clientMessages.uniqueLocalIpvItIsIntendedFor;
    if (canonical.startsWith('2001:db8:') ||
        (prefix === 0x3fff && (Number.parseInt(canonical.split(':')[1], 16) & 0xf000) === 0)) {
      return clientMessages.documentationIpvThisRangeIsReservedFor;
    }
    return clientMessages.ipvAddressTheAddressAloneDoesNot;
  }
  const parts = address.split('.');
  if (parts.length !== 4 || parts.some((part) => !/^\d{1,3}$/.test(part) || Number(part) > 255)) {
    return clientMessages.thisValueIsNotARecognizedIp;
  }
  const [a, b, c] = parts.map(Number);
  if (a === 127) return clientMessages.ipvLoopbackThisAddressRefersToThe2;
  if (a === 169 && b === 254) return clientMessages.linkLocalIpvItIsUsedOn2;
  if (a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168)) {
    return clientMessages.privateIpvManyNetworksCanUseThis;
  }
  if ((a === 192 && b === 0 && c === 2) || (a === 198 && b === 51 && c === 100) || (a === 203 && b === 0 && c === 113)) {
    return clientMessages.documentationIpvThisRangeIsReservedFor2;
  }
  return clientMessages.ipvAddressTheAddressAloneDoesNot2;
}

export function explainMacAddress(value: string) {
  const compact = value.trim().replace(/[:-]/g, '');
  if (!/^[a-f\d]{12}$/i.test(compact)) return '';
  const firstOctet = Number.parseInt(compact.slice(0, 2), 16);
  if (firstOctet & 1) return clientMessages.thisMacAddressIsAGroupAddress;
  if (firstOctet & 2) return clientMessages.thisMacAddressIsLocallyAssignedPrivate;
  return clientMessages.thisMacAddressCanHelpMatchObservations;
}
