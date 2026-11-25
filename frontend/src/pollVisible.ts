export function pollVisible(refresh: () => Promise<void>, interval: number) {
  let stopped = false;
  let running = false;
  let timer: number | undefined;

  async function tick() {
    if (stopped || running) return;
    window.clearTimeout(timer);
    running = true;
    try {
      await refresh();
    } finally {
      running = false;
      if (!stopped && interval) timer = window.setTimeout(onResume, interval);
    }
  }

  function onResume() {
    if (document.visibilityState === 'visible') void tick();
  }

  if (interval) {
    document.addEventListener('visibilitychange', onResume);
    window.addEventListener('focus', onResume);
  }
  void tick();
  return () => {
    stopped = true;
    window.clearTimeout(timer);
    document.removeEventListener('visibilitychange', onResume);
    window.removeEventListener('focus', onResume);
  };
}
