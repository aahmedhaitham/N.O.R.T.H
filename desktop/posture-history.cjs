const { randomBytes, createHmac } = require('node:crypto');
const fs = require('node:fs/promises');
const { dirname } = require('node:path');

function postureHistory(filename) {
  let pending = Promise.resolve();
  return (checks, at, exclusions = null) => {
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
      const stored = { at, states };
      let exclusion_changes;
      if (exclusions || prior?.exclusion_key) {
        stored.exclusion_key = prior?.exclusion_key ?? randomBytes(32).toString('hex');
        stored.exclusions = prior?.exclusions ?? null;
        if (exclusions) {
          const next = [...new Set(exclusions.map((entry) =>
            createHmac('sha256', stored.exclusion_key).update(entry.toLowerCase()).digest('hex')))];
          if (stored.exclusions) {
            const before = new Set(stored.exclusions);
            const after = new Set(next);
            exclusion_changes = {
              added: next.filter((item) => !before.has(item)).length,
              removed: stored.exclusions.filter((item) => !after.has(item)).length,
            };
          }
          stored.exclusions = next;
        }
      }
      await fs.mkdir(dirname(filename), { recursive: true });
      await fs.writeFile(filename + '.tmp', JSON.stringify(stored), { mode: 0o600 });
      await fs.rename(filename + '.tmp', filename);
      return { compared_at: prior?.at ?? null, changes, ...(exclusion_changes && { exclusion_changes }) };
    });
    pending = operation.catch(() => {});
    return operation;
  };
}

module.exports = { postureHistory };
