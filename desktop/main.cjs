const { app, BrowserWindow, Menu, dialog, ipcMain } = require('electron');
const fs = require('node:fs/promises');
const path = require('node:path');
const { workspaceOrigin } = require('./workspace.cjs');

let activeWindow;
let setupWindow;
let startupComplete = false;
const icon = path.join(__dirname, 'icons', 'north.ico');

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
    title: 'NORTH — Connect workspace', icon, width: 560, height: 410, minWidth: 400, minHeight: 350,
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
    dialog.showErrorBox('NORTH', 'The workspace setup screen could not open.');
  });
}

async function openWorkspace(nextOrigin, remember = false) {
  const window = new BrowserWindow({
    title: 'NORTH', icon, width: 1350, height: 850, minWidth: 375, minHeight: 500, show: false,
    backgroundColor: '#0c1018',
    webPreferences: {
      sandbox: true, contextIsolation: true, nodeIntegration: false,
      partition: 'persist:north-cloud',
    },
  });
  const contents = window.webContents;
  contents.setWindowOpenHandler(() => ({ action: 'deny' }));
  contents.session.setPermissionRequestHandler((_contents, _permission, done) => done(false));
  contents.session.setPermissionCheckHandler(() => false);
  const guard = (event) => {
    if (new URL(event.url).origin !== nextOrigin) event.preventDefault();
  };
  contents.on('will-navigate', guard);
  contents.on('will-redirect', guard);
  try {
    await window.loadURL(nextOrigin);
    if (remember) {
      await fs.writeFile(settingsPath(), JSON.stringify({ origin: nextOrigin }), 'utf8');
    }
  } catch (error) {
    window.destroy();
    throw error;
  }
  show(window);
  window.show();
}

ipcMain.handle('north:connect', async (event, value) => {
  if (!setupWindow || event.sender !== setupWindow.webContents) return 'Workspace setup is unavailable.';
  try {
    const nextOrigin = workspaceOrigin(value);
    await openWorkspace(nextOrigin, true);
    return null;
  } catch (error) {
    return error instanceof Error ? error.message : 'Could not open the workspace.';
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
    Menu.setApplicationMenu(Menu.buildFromTemplate([
      { label: 'Workspace', submenu: [
        { label: 'Connect to workspace…', click: configureWindow },
        { label: 'Reload', accelerator: 'Ctrl+R', click: () => activeWindow?.reload() },
        { role: 'quit' },
      ] },
      { label: 'Edit', submenu: [{ role: 'undo' }, { role: 'redo' }, { role: 'cut' }, { role: 'copy' }, { role: 'paste' }, { role: 'selectAll' }] },
    ]));
    try {
      const settings = JSON.parse(await fs.readFile(settingsPath(), 'utf8'));
      await openWorkspace(workspaceOrigin(settings.origin));
    } catch {
      configureWindow();
    }
    startupComplete = true;
  });
  app.on('window-all-closed', () => { if (startupComplete) app.quit(); });
}
