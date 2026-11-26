const assert = require('node:assert/strict');
const { test } = require('node:test');
const fc = require('fast-check');
const { answer } = require('../frontend/src/assistantEngine.ts');
const { readPacketTrace } = require('../frontend/src/parsePcap.ts');
const { readRouterCsv } = require('../frontend/src/routerCsv.ts');
const { clientMessages } = require('../frontend/src/messages.ts');

function parseOrReject(read, confirm) {
  let result;
  try { result = read(); } catch (error) {
    assert.ok(Object.values(clientMessages).includes(error.message), String(error));
    return;
  }
  confirm(result);
}

test('bounded arbitrary questions and parser inputs return valid results or documented errors', () => {
  fc.assert(fc.property(fc.string({ maxLength: 400 }), fc.uint8Array({ maxLength: 256 }), (input, bytes) => {
    const result = answer(input, {});
    assert.ok(result.rows.length <= 8 && result.suggestions.length <= 3);
    parseOrReject(() => readRouterCsv('ip,name\n' + input), (rows) => assert.ok(rows.length <= input.length + 1));
    const capture = new Uint8Array(24 + bytes.length);
    capture.set([0xd4, 0xc3, 0xb2, 0xa1]);
    new DataView(capture.buffer).setUint32(20, 1, true);
    capture.set(bytes, 24);
    parseOrReject(() => readPacketTrace(capture.buffer), (trace) => assert.ok(trace.packets.length <= 5000));
  }), { seed: 80625, numRuns: 100 });
});
