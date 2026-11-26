const { execFile } = require('node:child_process');
const { access } = require('node:fs/promises');
const path = require('node:path');
const { promisify } = require('node:util');

const run = promisify(execFile);
const maxCapture = 8 * 1024 * 1024;

function parseWindowsInterfaces(output) {
  return output.split(/\r?\n/).flatMap((line) => {
    const match = /^\s*(\d+)\. (\\Device\\NPF_(?:\{[0-9a-f-]{36}\}|Loopback))(?: \((.*)\))?\s*$/i.exec(line);
    return match ? [{ id: Number(match[1]), device: match[2], label: match[3] || 'Network adapter ' + match[1],
      link: /loopback$/i.test(match[2]) ? 'NULL' : 'EN10MB' }] : [];
  });
}

async function dumpcapPath() {
  if (!process.env.ProgramFiles) throw new Error('Dumpcap is unavailable.');
  const executable = path.join(process.env.ProgramFiles, 'Wireshark', 'dumpcap.exe');
  await access(executable);
  return executable;
}

function makePacketCapture({ execute = run, locate = dumpcapPath, isWindows = process.platform === 'win32' }) {
  let active = false;
  return async (request) => {
    const pathname = new URL(request.url).pathname;
    if (!isWindows) return Response.json({ detail: 'Desktop capture is available on Windows.' }, { status: 501 });
    const listing = pathname === '/api/desktop/capture/interfaces' && request.method === 'GET';
    if (!listing && (pathname !== '/api/desktop/capture/start' || request.method !== 'POST')) {
      return Response.json({ detail: 'Capture operation unavailable.' }, { status: 405 });
    }
    if (active) return Response.json({ detail: 'A capture is already in progress.' }, { status: 409 });
    if (!listing) active = true;
    try {
      let selection;
      if (!listing) {
        if (request.headers.get('X-North-Capture') !== 'local' ||
            request.headers.get('Content-Type') !== 'application/json') {
          return Response.json({ detail: 'Start the capture from NORTH Desktop.' }, { status: 403 });
        }
        try {
          const body = await request.text();
          if (body.length > 128) throw new Error();
          selection = JSON.parse(body);
          if (typeof selection?.device !== 'string' || ![3, 10, 15, 30].includes(selection?.seconds)) throw new Error();
        } catch {
          return Response.json({ detail: 'Choose an interface and a supported capture duration.' }, { status: 422 });
        }
      }
      const executable = await locate();
      const { stdout } = await execute(executable, ['-D'], { windowsHide: true, timeout: 12000 });
      const interfaces = parseWindowsInterfaces(stdout);
      if (listing) return Response.json({ interfaces: interfaces.map(({ device, label }) => ({ device, label })) });
      const adapter = interfaces.find(({ device }) => device === selection.device);
      if (!adapter) return Response.json({ detail: 'The selected adapter is unavailable.' }, { status: 404 });
      if (request.signal.aborted) {
        return new Response(null, { status: 204 });
      }
      const { stdout: capture } = await execute(executable, [
        '-i', adapter.device, '-y', adapter.link, '-p', '-s', '96', '-a', 'duration:' + selection.seconds,
        '-a', 'filesize:7000', '-c', '5000', '-w', '-',
      ], {
        windowsHide: true, timeout: (selection.seconds + 15) * 1000, maxBuffer: maxCapture,
        encoding: 'buffer', signal: request.signal,
      });
      if (capture.length < 28 || capture.length > maxCapture) throw new Error('Invalid capture.');
      return new Response(capture, { headers: { 'Content-Type': 'application/octet-stream', 'Cache-Control': 'no-store' } });
    } catch (error) {
      const denied = /permission to capture|admin.only mode/i.test(String(error?.stderr ?? ''));
      return Response.json({ detail: listing ?
        'NORTH could not list adapters. Check that Wireshark’s Dumpcap and its capture driver are installed.' :
        denied ? 'Windows capture permissions denied access to this adapter.' :
        'Capture could not finish. Check the adapter and capture permissions.' }, { status: denied ? 403 : 503 });
    } finally {
      if (!listing) active = false;
    }
  };
}

module.exports = { makePacketCapture };
