const assert = require('node:assert/strict');
const { test } = require('node:test');
const { setupState, setupKey } = require('../frontend/src/onboardingState.ts');

test('first-run visibility distinguishes denied, missing, disabled and unknown sources', () => {
  assert.equal(setupState(undefined, true), 'checking');
  assert.equal(setupState(), 'unknown');
  assert.equal(setupState({ state: 'ready', problem: null }), 'ready');
  assert.equal(setupState({ state: 'unavailable', problem: 'access_denied' }), 'denied');
  assert.equal(setupState({ state: 'unavailable', problem: 'channel_missing' }), 'missing');
  assert.equal(setupState({ state: 'disabled' }), 'idle');
  assert.equal(setupState({ state: 'ready' }, false, true), 'unavailable');
});

test('local and cloud onboarding completion have separate browser preferences', () => {
  assert.notEqual(setupKey(false), setupKey(true));
});
