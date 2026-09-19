const { contextBridge, ipcRenderer } = require('electron');
const allowed = new Set(['diagnostics','engines','providers','chooseFolder','scan','scan.cancel','quarantine.list','quarantine.add','quarantine.restore','settings.get','settings.set','network.audit','power.get','power.set','process.priority','cleanup.preview','cleanup.trash','analyze']);
contextBridge.exposeInMainWorld('aegis', {
  call(action, payload) {
    if (!allowed.has(action)) return Promise.reject(new Error('Unknown operation.'));
    return ipcRenderer.invoke('aegis:call', action, payload);
  },
  onEvent(callback) {
    const listener = (_event, value) => callback(value);
    ipcRenderer.on('aegis:event', listener);
    return () => ipcRenderer.removeListener('aegis:event', listener);
  },
});
