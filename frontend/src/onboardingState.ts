export type SetupSource = { state: string; problem?: string | null };
export type SetupState = 'checking' | 'ready' | 'denied' | 'missing' | 'unavailable' | 'idle' | 'unknown';

export function setupState(source?: SetupSource, waiting = false, failed = false): SetupState {
  if (failed) return 'unavailable';
  if (!source) return waiting ? 'checking' : 'unknown';
  if (source.problem === 'access_denied') return 'denied';
  if (source.problem === 'channel_missing') return 'missing';
  if (source.state === 'ready') return 'ready';
  if (source.state === 'starting') return 'checking';
  if (source.state === 'disabled') return 'idle';
  return 'unavailable';
}

export const setupKey = (cloud: boolean) => 'north.onboarding.v1.' + (cloud ? 'cloud' : 'local');
export const setupEvent = 'north:open-onboarding';
