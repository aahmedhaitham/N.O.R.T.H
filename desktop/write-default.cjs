const fs = require('node:fs');
const path = require('node:path');
const { workspaceOrigin } = require('./workspace.cjs');

const cloudOnly = process.env.NORTH_DESKTOP_CLOUD_ONLY === '1';
if (cloudOnly && !process.env.NORTH_DESKTOP_DEFAULT_URL) {
  throw new Error('Set NORTH_DESKTOP_DEFAULT_URL to the hosted HTTPS address for a cloud-only build.');
}
if (process.env.NORTH_DESKTOP_DEFAULT_URL) {
  fs.writeFileSync(path.join(__dirname, 'ui', 'workspace-default.json'),
    JSON.stringify({ cloudOnly, origin: workspaceOrigin(process.env.NORTH_DESKTOP_DEFAULT_URL) }));
}
