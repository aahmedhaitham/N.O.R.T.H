const assert = require('node:assert/strict');
const { test } = require('node:test');
const { simpleStatus } = require('../frontend/src/simpleStatus.ts');

test('Simple status prioritizes severe findings and requires current observations for Good', () => {
  const base = { ready: false, openCases: 0, unreviewed: 0, severe: false, unknownDevices: 0 };
  const status = (overrides) => simpleStatus({ ...base, ...overrides });
  assert.deepEqual(status({}), { level: 'look', reason: 'visibilityReason' });
  assert.deepEqual(status({ ready: true }), { level: 'good', reason: 'goodReason' });
  assert.deepEqual(status({ ready: true, unknownDevices: 1 }), { level: 'look', reason: 'devicesReason' });
  assert.deepEqual(status({ openCases: 1, unknownDevices: 1 }), { level: 'look', reason: 'findingsReason' });
  assert.deepEqual(status({ unreviewed: 1 }), { level: 'look', reason: 'findingsReason' });
  assert.deepEqual(status({ severe: true, openCases: 1, unknownDevices: 1 }), { level: 'urgent', reason: 'urgentReason' });
});
