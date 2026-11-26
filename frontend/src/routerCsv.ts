import { clientMessages } from './messages.ts';
const aliases = {
  address: ['ip', 'ipaddress', 'ipv4', 'ipv4address', 'address'],
  mac: ['mac', 'macaddress', 'lladdr', 'hardwareaddress'],
  name: ['name', 'devicename', 'hostname', 'clientname'],
  interface: ['interface', 'network', 'ssid', 'connectiontype'],
  state: ['state', 'status', 'devicestatus'],
} as const;

function parseRows(text: string, delimiter: string) {
  const rows: string[][] = [];
  let row: string[] = [];
  let field = '';
  let quoted = false;
  let closed = false;
  for (let offset = 0; offset < text.length; offset++) {
    const next = text[offset];
    if (quoted) {
      if (next !== '"') field += next;
      else if (text[offset + 1] === '"') { field += '"'; offset++; }
      else { quoted = false; closed = true; }
    } else if (next === delimiter || next === '\r' || next === '\n') {
      row.push(field.trim());
      field = '';
      closed = false;
      if (next !== delimiter) {
        if (row.some(Boolean)) rows.push(row);
        if (rows.length > 5001) throw new Error(clientMessages.chooseAFileWithAtMostDevice);
        row = [];
        if (next === '\r' && text[offset + 1] === '\n') offset++;
      }
    } else if (next === '"' && !field && !closed) {
      quoted = true;
    } else if (closed || next === '"') {
      throw new Error(clientMessages.theFileContainsAnInvalidQuotedField);
    } else {
      field += next;
    }
  }
  if (quoted) throw new Error(clientMessages.theFileContainsAnUnclosedQuotedField);
  row.push(field.trim());
  if (row.some(Boolean)) rows.push(row);
  return rows;
}

export function readRouterCsv(text: string) {
  const firstLine = text.split(/\r?\n/, 1)[0];
  const delimiter = firstLine.includes('\t') ? '\t' : firstLine.includes(';') && !firstLine.includes(',') ? ';' : ',';
  const [headers, ...rows] = parseRows(text, delimiter);
  const columns = (headers ?? []).map((header) => header.toLowerCase().replace(/[^a-z0-9]/g, ''));
  const indices = Object.entries(aliases).map(([field, names]) => [
    field, columns.findIndex((column) => (names as readonly string[]).includes(column)),
  ] as const);
  if (indices[0][1] < 0) throw new Error(clientMessages.theDeviceExportNeedsAnIpAddress);
  return rows.map((row) => Object.fromEntries(indices.map(([field, index]) => [field, row[index] ?? ''])));
}
