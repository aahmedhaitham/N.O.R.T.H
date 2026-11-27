const fs = require('node:fs/promises');
const { dirname } = require('node:path');

function postureHistory(filename) {
  let pending = Promise.resolve();
  return (checks, at) => {
    const operation = pending.then(async () => {
      let prior;
      try {
        prior = JSON.parse(await fs.readFile(filename, 'utf8'));
      } catch (error) {
        if (error.code !== 'ENOENT') throw error;
      }
      const states = Object.fromEntries(checks.map(({ id, status }) => [id, status]));
      const changes = checks.flatMap(({ id, title, status }) => {
        const before = prior?.states?.[id];
        return ['pass', 'fail', 'unknown'].includes(before) && before !== status
          ? [{ id, title, before, after: status }] : [];
      });
      await fs.mkdir(dirname(filename), { recursive: true });
      await fs.writeFile(filename + '.tmp', JSON.stringify({ at, states }), { mode: 0o600 });
      await fs.rename(filename + '.tmp', filename);
      return { compared_at: prior?.at ?? null, changes };
    });
    pending = operation.catch(() => {});
    return operation;
  };
}

module.exports = { postureHistory };
