import { readFileSync } from 'node:fs';
import { matchIntent } from '../frontend/src/assistantEngine.ts';

const fixture = JSON.parse(readFileSync(new URL('../desktop/assistant-heldout.json', import.meta.url), 'utf8').replace(/^\uFEFF/, ''));
let correct = 0;
let total = 0;
const misroutes = [];
const perIntent = Object.entries(fixture).map(([id, phrases]) => {
  let matched = 0;
  for (const phrase of phrases) {
    const actual = matchIntent(phrase).intent?.id ?? null;
    if (actual === id) matched++;
    else misroutes.push({ expected: id, actual, phrase });
  }
  correct += matched;
  total += phrases.length;
  return { intent: id, matched, total: phrases.length };
});
if (total < 120 || new Set(Object.values(fixture).flat().map((text) => text.toLowerCase().replace(/[^a-z0-9 ]/g, ''))).size !== total) {
  throw new Error('Expected at least 120 unique held-out phrasings');
}
const report = { correct, total, accuracy: correct / total, perIntent, misroutes };
console.log(JSON.stringify(process.argv.includes('--summary') ? { correct, total, accuracy: report.accuracy, perIntent } : report, null, 2));
