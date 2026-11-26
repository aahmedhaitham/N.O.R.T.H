const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('north', {
  /** @param {string} address @returns {Promise<string | null>} */
  connect: (address) => ipcRenderer.invoke('north:connect', address),
});
