const { z } = require('zod');

const connectInput = z.string().trim().min(1).max(2048);

function workspaceOrigin(value) {
  if (typeof value !== 'string') throw new Error('Enter your NORTH Cloud address.');
  const url = new URL(value.trim());
  if (url.protocol !== 'https:' || !url.hostname.includes('.') || url.username || url.password ||
      url.pathname !== '/' || url.search || url.hash) {
    throw new Error('Enter the HTTPS workspace address without a page path, password, or query.');
  }
  return url.origin;
}

function desktopStartup(configuration = {}) {
  if (!configuration.cloudOnly) return { cloudOnly: false };
  return { cloudOnly: true, origin: workspaceOrigin(configuration.origin) };
}

function parseWorkspaceConnection(value) {
  const input = connectInput.safeParse(value);
  if (!input.success) throw new Error('Enter your NORTH Cloud address.');
  return workspaceOrigin(input.data);
}

module.exports = { desktopStartup, workspaceOrigin, parseWorkspaceConnection };
