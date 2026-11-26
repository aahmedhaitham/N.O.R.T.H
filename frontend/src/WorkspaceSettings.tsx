import { useEffect, useState } from 'react';
import { TimezoneControl } from './TimeDisplay';
import { DisplayModeControl } from './DisplayMode';

type Settings = {
  ai_available: boolean;
  ai_enabled: boolean;
  retention_days: number | null;
  ai_hourly_limit: number;
  upload_hourly_limit: number;
};

export function WorkspaceSettings({ back, openCollectors }: { back: () => void; openCollectors: () => void }) {
  const [settings, setSettings] = useState<Settings | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [saved, setSaved] = useState(false);
  useEffect(() => {
    const controller = new AbortController();
    void fetch('/api/cloud/settings', { signal: controller.signal }).then(async (response) => {
      if (!response.ok) throw new Error();
      const value: Settings = await response.json();
      if (!controller.signal.aborted) setSettings(value);
    }).catch(() => { if (!controller.signal.aborted) setError('Workspace settings could not load. Reopen this page to retry.'); });
    return () => controller.abort();
  }, []);

  async function update(aiEnabled: boolean) {
    setBusy(true);
    setError('');
    setSaved(false);
    try {
      const response = await fetch('/api/cloud/settings', {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ ai_enabled: aiEnabled }),
      });
      if (!response.ok) throw new Error();
      setSettings((current) => current && { ...current, ai_enabled: aiEnabled });
      setSaved(true);
    } catch {
      setError('NORTH could not save the AI setting. Try again.');
    } finally { setBusy(false); }
  }

  return <main className="collector-settings collector-workspace">
    <header className="collector-heading dashboard-heading"><h1>Workspace settings</h1><button type="button" onClick={back}>Back to workspace</button></header>
    {error && <p role="alert">{error}</p>}
    <section className="panel"><DisplayModeControl /></section>
    <section className="panel"><h2>Timezone</h2><TimezoneControl /></section>
    {!settings && !error && <p role="status">Loading workspace settings…</p>}
    {settings && <>
      <section className="panel">
        <h2>Cloud AI briefs</h2>
        <label><input type="checkbox" checked={settings.ai_enabled} disabled={busy}
          onChange={(event) => void update(event.target.checked)} /> Allow cloud AI to prioritize evidence briefs</label>
        <p>Cloud AI receives generic observation descriptions. The workspace adds event citations and details after it ranks them.</p>
        <p>{settings.ai_available ? `Up to ${settings.ai_hourly_limit} requests per hour in this workspace.` :
          'This server has no cloud AI provider configured.'} Evidence briefs remain available with AI off.</p>
        {saved && <p role="status">AI preference saved.</p>}
      </section>
      <section className="panel">
        <h2>Data retention</h2>
        <p>{settings.retention_days ? `The server schedules events, investigations, and reports for deletion after ${settings.retention_days} days.` :
          'This workspace has no automatic expiry configured for events, investigations, or reports.'}</p>
        <p>Collector settings and the latest network inventory have a separate lifecycle.</p>
      </section>
      <section className="panel">
        <h2>Collector access</h2>
        <p>Paired collectors can upload up to {settings.upload_hourly_limit} snapshots per hour across this workspace. Revoke a pairing to stop future uploads from that collector.</p>
        <button onClick={openCollectors}>Manage collectors</button>
      </section>
    </>}
  </main>;
}
