const { app, BrowserWindow, Menu, dialog, ipcMain, net, protocol, session, shell } = require('electron');
const fs = require('node:fs/promises');
const path = require('node:path');
const { networkInterfaces } = require('node:os');
const { pathToFileURL } = require('node:url');
const { desktopStartup, workspaceOrigin, parseWorkspaceConnection } = require('./workspace.cjs');
const { makeCloudProxy } = require('./cloud-proxy.cjs');
const { makeLocalWorkspace } = require('./local-workspace.cjs');
const { makeLocalFindings } = require('./local-findings.cjs');
const { deviceHistory } = require('./device-history.cjs');
const { postureHistory } = require('./posture-history.cjs');
const { listenerHistory } = require('./listener-history.cjs');
const { makePacketCapture } = require('./packet-capture.cjs');
const { makeCollectorInstall } = require('./collector-install.cjs');
const strings = require('./messages.js');

let activeWindow;
let setupWindow;
let startupComplete = false;
let cloudProxy;
let connectedOrigin;
let hostedOrigin;
const icon = path.join(__dirname, 'icons', 'north.ico');
const localAddress = 'north://app/';
const cloudPartition = 'persist:north-cloud';
const localPartition = 'persist:north-local';
const ui = app.isPackaged ? path.join(process.resourcesPath, 'north-ui') : path.join(__dirname, 'ui');
const scripts = app.isPackaged ? path.join(process.resourcesPath, 'north-tools') : path.join(__dirname, '..', 'tools');
const collectorRoot = app.isPackaged ? path.join(process.resourcesPath, 'north-collector') : path.join(__dirname, '..');
const collectorInstall = makeCollectorInstall({
  root: collectorRoot,
  data: app.getPath('userData'),
  async confirm() {
    if (!activeWindow || activeWindow.isDestroyed()) return false;
    const { response } = await dialog.showMessageBox(activeWindow, {
      type: 'question', title: strings.collectorTitle, message: strings.collectorQuestion,
      detail: strings.collectorDetail,
      buttons: [strings.cancel, strings.setupCollector], defaultId: 0, cancelId: 0,
    });
    return response === 1;
  },
});
const localWorkspace = makeLocalWorkspace(scripts, undefined,
  deviceHistory(path.join(app.getPath('userData'), 'device-history.json')),
  listenerHistory(path.join(app.getPath('userData'), 'listener-history.json')),
  postureHistory(path.join(app.getPath('userData'), 'posture-history.json')),
  async () => {
    if (!activeWindow || activeWindow.isDestroyed()) return false;
    const { response } = await dialog.showMessageBox(activeWindow, {
      type: 'question', title: 'Microsoft Defender quick scan', message: 'Request a Defender quick scan on this PC?',
      detail: 'Microsoft Defender will scan using its current settings and may take action according to its own policy.',
      buttons: ['Cancel', 'Request quick scan'], defaultId: 0, cancelId: 0,
    });
    return response === 1;
  });
const localFindings = makeLocalFindings({ root: collectorRoot, data: app.getPath('userData'),
  sourceChecks: localWorkspace.sourceChecks, packagedFirst: app.isPackaged });
const packetCapture = makePacketCapture({});
let offlineCountryLookup;

async function desktopLocations(request) {
  if (request.method === 'GET') {
    return Response.json(Object.values(networkInterfaces()).flatMap((items) =>
      (items ?? []).filter((item) => !item.internal).map((item) => item.address)));
  }
  if (request.method !== 'POST' || request.headers.get('Content-Type') !== 'application/json') {
    return new Response(null, { status: 405 });
  }
  let addresses;
  try {
    const body = await request.text();
    if (body.length > 25000) throw new Error();
    addresses = JSON.parse(body);
    if (!Array.isArray(addresses) || addresses.length > 500 || addresses.some((item) => typeof item !== 'string')) throw new Error();
  } catch {
    return Response.json({ detail: 'Invalid address list.' }, { status: 422 });
  }
  try {
    if (!offlineCountryLookup) {
      const { countryResolver } = await import(pathToFileURL(path.join(ui, 'geo', 'ip-country.mjs')).href);
      offlineCountryLookup = countryResolver((file) => fs.readFile(path.join(ui, 'geo', file)));
    }
    return Response.json(await offlineCountryLookup(addresses));
  } catch {
    return Response.json({ detail: 'Offline country database unavailable.' }, { status: 503 });
  }
}

protocol.registerSchemesAsPrivileged([{ scheme: 'north', privileges: {
  standard: true, secure: true, supportFetchAPI: true,
} }]);

async function handleLocalRequest(request, api, origin) {
  const url = new URL(request.url);
  if (url.hostname !== 'app') return new Response(null, { status: 404 });
  if (url.pathname === '/api/desktop/remote-locations') return desktopLocations(request);
  if (url.pathname.startsWith('/api/desktop/capture/')) return packetCapture(request);
  if (url.pathname.startsWith('/api/desktop/collector/')) return collectorInstall(request, origin, api);
  if (api === localWorkspace && (/^\/api\/local\/(findings|evidence|rules)(\/|$)/).test(url.pathname)) {
    return localFindings.handle(request);
  }
  if (url.pathname.startsWith('/api/')) {
    return api ? api(request) : Response.json({ detail: 'No workspace selected.' }, { status: 503 });
  }
  if (request.method !== 'GET') return new Response(null, { status: 405 });
  let filename;
  try {
    const requested = decodeURIComponent(['/', '/cloud'].includes(url.pathname) ? '/index.html' : url.pathname);
    filename = path.resolve(ui, '.' + requested);
  } catch {
    return new Response(null, { status: 400 });
  }
  if (!filename.startsWith(ui + path.sep)) return new Response(null, { status: 404 });
  const response = await net.fetch(pathToFileURL(filename).toString());
  if (!filename.endsWith('.html')) return response;
  const headers = new Headers(response.headers);
  headers.set('Content-Security-Policy',
    "default-src 'none'; script-src 'self'; connect-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; font-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'");
  return new Response(response.body, { status: response.status, headers });
}

function settingsPath() {
  return path.join(app.getPath('userData'), 'workspace.json');
}

function show(window) {
  const previous = activeWindow;
  activeWindow = window;
  window.on('closed', () => {
    if (activeWindow === window) activeWindow = undefined;
  });
  if (previous && previous !== window) previous.close();
}

function configureWindow() {
  const window = new BrowserWindow({
    title: strings.setupWindow, icon, width: 560, height: 410, minWidth: 400, minHeight: 350,
    backgroundColor: '#0c1018',
    webPreferences: {
      sandbox: true, contextIsolation: true, nodeIntegration: false,
      preload: path.join(__dirname, 'preload.cjs'),
    },
  });
  setupWindow = window;
  window.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));
  window.webContents.on('will-navigate', (event) => event.preventDefault());
  window.on('closed', () => { if (setupWindow === window) setupWindow = undefined; });
  show(window);
  void window.loadFile(path.join(__dirname, 'setup.html')).catch(() => {
    dialog.showErrorBox('NORTH', strings.setupFailed);
  });
}

async function openWorkspace(nextOrigin, remember = false) {
  const connected = Boolean(nextOrigin);
  const window = new BrowserWindow({
    title: 'NORTH', icon, width: 1350, height: 850, minWidth: 375, minHeight: 500, show: false,
    backgroundColor: '#0c1018',
    webPreferences: {
      sandbox: true, contextIsolation: true, nodeIntegration: false,
      partition: connected ? cloudPartition : localPartition,
    },
  });
  const contents = window.webContents;
  contents.setWindowOpenHandler(({ url }) => {
    const ticket = /^north:\/\/app\/desktop-approve\/([a-f0-9]{32}\.[a-f0-9]{64}\.\d{10}\.[a-f0-9]{64})$/.exec(url)?.[1];
    if (connected && ticket) {
      const approval = new URL('/', nextOrigin);
      approval.searchParams.set('desktop_sign_in', ticket);
      void shell.openExternal(approval.href).catch(() => {});
    }
    const collectorDownload = /^north:\/\/app(\/downloads\/NORTH-Collector-(?:Windows|Linux)\.zip)$/.exec(url)?.[1];
    if (connected && collectorDownload) {
      void shell.openExternal(new URL(collectorDownload, nextOrigin).href).catch(() => {});
    }
    return { action: 'deny' };
  });
  contents.session.setPermissionRequestHandler((_contents, _permission, done) => done(false));
  contents.session.setPermissionCheckHandler(() => false);
  const guard = (event) => {
    if (!event.url.startsWith(localAddress)) event.preventDefault();
  };
  contents.on('will-navigate', guard);
  contents.on('will-redirect', guard);
  const previousProxy = cloudProxy;
  const previousOrigin = connectedOrigin;
  if (connected) {
    cloudProxy = makeCloudProxy(nextOrigin);
    connectedOrigin = nextOrigin;
  }
  try {
    await window.loadURL(localAddress + (connected ? 'cloud' : ''));
    if (remember) {
      await fs.writeFile(settingsPath(), JSON.stringify({ origin: nextOrigin }), 'utf8');
    }
  } catch (error) {
    cloudProxy = previousProxy;
    connectedOrigin = previousOrigin;
    window.destroy();
    throw error;
  }
  show(window);
  window.show();
}

async function openSavedWorkspace() {
  try {
    const settings = await fs.readFile(settingsPath(), 'utf8').catch(() =>
      fs.readFile(path.join(ui, 'workspace-default.json'), 'utf8'));
    await openWorkspace(workspaceOrigin(JSON.parse(settings).origin));
  } catch {
    configureWindow();
  }
}

ipcMain.handle('north:connect', async (event, value) => {
  const expected = pathToFileURL(path.join(__dirname, 'setup.html')).href;
  if (hostedOrigin || !setupWindow || event.sender !== setupWindow.webContents ||
      event.senderFrame !== event.sender.mainFrame || event.senderFrame?.url !== expected) {
    return strings.setupUnavailable;
  }
  try {
    const nextOrigin = parseWorkspaceConnection(value);
    await openWorkspace(nextOrigin, true);
    return null;
  } catch (error) {
    return error instanceof Error ? error.message : strings.openFailed;
  }
});

if (!app.requestSingleInstanceLock()) {
  app.quit();
} else {
  app.on('second-instance', () => {
    if (activeWindow?.isMinimized()) activeWindow.restore();
    activeWindow?.focus();
  });
  app.whenReady().then(async () => {
    const config = await fs.readFile(path.join(ui, 'workspace-default.json'), 'utf8')
      .then(JSON.parse, (error) => {
        if (error.code === 'ENOENT') return {};
        throw error;
      });
    const startup = desktopStartup(config);
    hostedOrigin = startup.origin;
    if (!startup.cloudOnly) {
      session.fromPartition(localPartition).protocol.handle('north', (request) => handleLocalRequest(request, localWorkspace));
    }
    session.fromPartition(cloudPartition).protocol.handle('north', (request) => handleLocalRequest(request, cloudProxy, connectedOrigin));
    Menu.setApplicationMenu(Menu.buildFromTemplate([
      { label: strings.workspace, submenu: [
        ...(startup.cloudOnly ? [] : [
          { label: strings.thisComputer, click: () => void openWorkspace().catch(showStartupError) },
          { label: strings.openCloudWorkspace, click: openSavedWorkspace },
          { label: strings.changeWorkspace, click: configureWindow },
        ]),
        { label: strings.reload, accelerator: 'Ctrl+R', click: () => activeWindow?.reload() },
        { role: 'quit' },
      ] },
      { label: strings.edit, submenu: [{ role: 'undo' }, { role: 'redo' }, { role: 'cut' }, { role: 'copy' }, { role: 'paste' }, { role: 'selectAll' }] },
      { label: strings.view, submenu: [{ role: 'resetZoom' }, { role: 'zoomIn' }, { role: 'zoomOut' }, { type: 'separator' }, { role: 'togglefullscreen' }] },
    ]));
    await openWorkspace(hostedOrigin);
    startupComplete = true;
  }).catch(() => {
    showStartupError();
    app.quit();
  });
  app.on('window-all-closed', () => { if (startupComplete) app.quit(); });
  app.on('before-quit', () => localFindings.stop());
}

function showStartupError() {
  dialog.showErrorBox('NORTH', strings.dashboardFailed);
}
