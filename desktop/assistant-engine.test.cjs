const assert = require('node:assert/strict');
const { test } = require('node:test');
const { answer, intents } = require('../frontend/src/assistantEngine.ts');

const now = Date.parse('2026-01-15T12:00:00Z');
const rows = {
  devices: [
    { id: 'phone', label: 'Test phone', status: 'new', terms: ['192.0.2.10', '02:00:00:00:00:10'] },
    { id: 'router', label: 'Test router', status: 'reviewed', terms: ['192.0.2.1'] },
  ],
  findings: [{ id: 'finding', label: 'Observed activity', status: 'new', alternative: 'An update can cause this.' }],
  events: [
    { id: 'fresh', label: 'Test browser', timestamp: '2026-01-15T11:30:00Z', terms: ['example.test', 'Canada'], country: 'Canada' },
    { id: 'old', label: 'Another browser', timestamp: '2026-01-15T10:00:00Z', terms: ['other.test'] },
  ],
};
const ids = (question) => answer(question, rows, undefined, now).rows.map((row) => row.id);

test('every registered example resolves, while unrelated requests get three suggestions', () => {
  assert.ok(intents.length >= 30);
  for (const intent of intents) for (const example of intent.examples) {
    assert.doesNotMatch(answer(example, rows).text, /couldn’t confidently/, example);
  }
  const unknown = answer('purple mountains swimming sideways', rows);
  assert.match(unknown.text, /couldn’t confidently/);
  assert.equal(unknown.rows.length, 0);
  assert.equal(unknown.suggestions.length, 3);
});

test('structured slots and context preserve exact evidence and do not substitute unknown entities', () => {
  assert.deepEqual(ids('Who is new on my network?'), ['phone']);
  assert.deepEqual(ids('Is this device known? 192.0.2.10'), ['phone']);
  assert.deepEqual(ids('Which app talked to a domain? example.test'), ['fresh']);
  assert.deepEqual(ids('Which app talked to a country? Canada'), ['fresh']);
  assert.deepEqual(ids('Show events for a process last hour'), ['fresh']);
  assert.deepEqual(ids('Show events for process imaginary'), []);
  const context = { area: 'findings', row: rows.findings[0] };
  assert.equal(answer('Could this finding be a false positive?', {}, context).rows[0].detail, rows.findings[0].alternative);
});
