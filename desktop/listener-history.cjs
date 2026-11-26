const fs = require('node:fs/promises');
const { dirname } = require('node:path');

const maxListeners = 2000;

function listenerHistory(filename) {
  let pending = Promise.resolve();
  return function observe(rows, observedAt, limited) {
    const operation = pending.then(async () => {
      let state;
      try {
        state = JSON.parse(await fs.readFile(filename, 'utf8'));
      } catch (error) {
        if (error.code !== 'ENOENT') throw error;
        state = { baseline_at: null, listeners: {} };
      }
      const listeners = rows.filter((row) => row.state === 'Listen');
      const initial = !state.baseline_at;
      let changed = false;
      let count = Object.keys(state.listeners).length;
      if (!limited && listeners.length) {
        if (initial) state.baseline_at = observedAt;
        for (const row of listeners) {
          const key = row.local_address.toLowerCase() + '|' + row.local_port;
          const prior = state.listeners[key];
          if (prior) {
            if (prior.last_seen < observedAt) {
              prior.last_seen = observedAt;
              changed = true;
            }
          } else if (count < maxListeners) {
            state.listeners[key] = {
              local_address: row.local_address, local_port: row.local_port,
              first_seen: observedAt, last_seen: observedAt, baseline: initial,
            };
            count++;
            changed = true;
          }
        }
      }
      if (changed) {
        await fs.mkdir(dirname(filename), { recursive: true });
        await fs.writeFile(filename + '.tmp', JSON.stringify(state), { mode: 0o600 });
        await fs.rename(filename + '.tmp', filename);
      }
      const recent = Object.values(state.listeners).filter((item) => !item.baseline)
        .sort((a, b) => b.first_seen.localeCompare(a.first_seen)).slice(0, 12);
      return { baseline_at: state.baseline_at, recent, full: count >= maxListeners };
    });
    pending = operation.catch(() => {});
    return operation;
  };
}

module.exports = { listenerHistory };
