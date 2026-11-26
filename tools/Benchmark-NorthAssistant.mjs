import { cpus, totalmem, platform, release } from 'node:os';
import { performance } from 'node:perf_hooks';
import { intents, matchIntent } from '../frontend/src/assistantEngine.ts';

const questions = [...intents.map(({ examples }) => examples[0]), 'List devcies', 'Unknown device question', ''];
for (const question of questions) matchIntent(question);
const times = [];
for (let repetition = 0; repetition < 15; repetition++) {
  for (const question of questions) {
    const started = performance.now();
    matchIntent(question);
    times.push(performance.now() - started);
  }
}
times.sort((a, b) => a - b);
console.log(JSON.stringify({
  platform: platform() + ' ' + release(), node: process.version, cpu: cpus()[0]?.model,
  logicalProcessors: cpus().length, ramGiB: +(totalmem() / 1024 ** 3).toFixed(1),
  samples: times.length, medianMs: +times[Math.floor(times.length / 2)].toFixed(3),
  p95Ms: +times[Math.ceil(times.length * 0.95) - 1].toFixed(3),
  benchmarkProcessPeakRssMiB: +(process.resourceUsage().maxRSS / 1024).toFixed(1),
}, null, 2));
