const assert = require('node:assert/strict');
const { test } = require('node:test');
const { answer, intents, matchIntent } = require('../frontend/src/assistantEngine.ts');
const golden = require('./assistant-golden.json');

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

test('at least 150 distinct phrasings route to the exact expected intent', () => {
  const cases = new Map();
  for (const { id, examples: [question] } of intents) {
    cases.set(question, id);
    cases.set(question.toUpperCase(), id);
    cases.set('Hey NORTH, ' + question, id);
    cases.set('Please ' + question, id);
    cases.set(question.replace(/\?$/, '') + ', thanks', id);
  }
  for (const [question, expected] of [
    ['List devcies', 'devices'], ['What is DNs??', 'glossary-dns'],
    ['Unreviewed alerts', 'attention'], ['Capture packets please', 'capture'],
    ['help', 'help'], ['', undefined], ['How do I change a bicycle tire?', undefined],
  ]) cases.set(question, expected);
  assert.ok(cases.size >= 150);
  for (const [question, expected] of cases) assert.equal(matchIntent(question).intent?.id, expected, question);
});

test('answers preserve bounded evidence as text and never call fetch', (t) => {
  const network = t.mock.method(globalThis, 'fetch', () => { throw new Error('Unexpected network request'); });
  const label = '<img src=x onerror=alert(1)> [label](https://example.test)';
  const snapshot = Object.freeze({ devices: Object.freeze(Array.from({ length: 240 }, (_, id) =>
    Object.freeze({ id: String(id), label, status: 'new', terms: [] }))) });
  const result = answer('List devices', snapshot);
  assert.deepEqual(result.rows.map((row) => row.id), ['0', '1', '2', '3', '4', '5', '6', '7']);
  assert.equal(result.rows[0].label, label);
  assert.equal(snapshot.devices.length, 240);
  assert.equal(network.mock.callCount(), 0);
});

test('every intent preserves its approved answer text and evidence IDs on the fixed snapshot', () => {
  assert.deepEqual(golden.cases.map(({ id }) => id).sort(), intents.map(({ id }) => id).sort());
  for (const { id, question, text, area, evidence } of golden.cases) {
    const result = answer(question, golden.snapshot, undefined, Date.parse(golden.now));
    assert.equal(result.text, text, id);
    assert.equal(result.area ?? null, area, id);
    assert.deepEqual(result.rows.map((row) => row.id), evidence, id);
  }
});

test('deterministic malformed question corpus always returns bounded results', () => {
  let state = 38217;
  const alphabet = ['\u0000', 'é', 'ŋ', '👾', 'a', '[', '?', '.', '١', ' '];
  for (let iteration = 0; iteration < 120; iteration++) {
    let query = '';
    for (let index = 0; index < iteration * 7; index++) {
      state = (state * 48271) % 2147483647;
      query += alphabet[state % alphabet.length];
    }
    const result = answer(query, rows);
    assert.ok(result.rows.length <= 8 && result.suggestions.length <= 3);
  }
});
