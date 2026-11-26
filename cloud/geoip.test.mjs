import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import { countryResolver, publicAddress } from '../frontend/public/geo/ip-country.mjs';

test('bundled GeoIP resolves public IPv4 and IPv6 and skips private and documentation addresses', async () => {
  const resolve = countryResolver((name) => readFile(new URL('../frontend/public/geo/' + name, import.meta.url)));
  assert.deepEqual(Array.from(publicAddress('::ffff:8.8.8.8')), [8, 8, 8, 8]);
  const results = await resolve(['8.8.8.8', '2001:4860:4860::8888', '192.168.1.1', '192.0.2.1', '2001:db8::1']);
  assert.match(results['8.8.8.8'], /^[A-Z]{2}$/);
  assert.match(results['2001:4860:4860::8888'], /^[A-Z]{2}$/);
  assert.equal(Object.keys(results).length, 2);
});
