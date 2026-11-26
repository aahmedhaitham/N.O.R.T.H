const assert = require('node:assert/strict');
const { test } = require('node:test');
const { processTree } = require('../frontend/src/processLineage.ts');

const guid = (n) => '00000000-0000-0000-0000-' + String(n).padStart(12, '0');
const event = (id, process, parent, kind = 1) => ({
  id, kind, raw: { data: { win: { eventdata: {
    image: 'C:\\Example\\sample.exe', processGuid: '{' + guid(process) + '}',
    parentProcessGuid: parent ? '{' + guid(parent) + '}' : '',
  } } } },
});

test('ECHO process lineage keeps preferred evidence, marks gaps and bounds large cyclic input', () => {
  const { rows } = processTree([
    event('connection', 2, 1, 3), event('child', 2, 1), event('parent', 1),
    event('outside', 3, 900), event('cycle-a', 4, 5), event('cycle-b', 5, 4), event('zero', 0),
  ]);
  assert.deepEqual(rows.map(({ evidenceId, depth }) => [evidenceId, depth]),
    [['parent', 0], ['child', 1], ['outside', 0], ['cycle-a', 0], ['cycle-b', 1]]);
  assert.equal(rows[2].gap, 'Parent outside case evidence');
  assert.equal(rows[3].gap, 'Parent chain could not be resolved');
  assert.equal(rows[0].label, 'sample.exe');
  const large = processTree(Array.from({ length: 600 }, (_, n) => event(String(n), n + 1, n)));
  assert.equal(large.rows.length, 500);
  assert.equal(large.rows.at(-1).depth, 499);
  assert.equal(large.truncated, true);
});
