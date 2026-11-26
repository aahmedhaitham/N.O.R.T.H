import { WorkspaceSettingsMessages as strings, formatMessage } from './messages';
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
    }).catch(() => { if (!controller.signal.aborted) setError(strings.workspaceSettingsCouldNotLoadReopenThis); });
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
      setError(strings.northCouldNotSaveTheAiSetting);
    } finally { setBusy(false); }
  }

  return <main className="collector-settings collector-workspace">
    <header className="collector-heading dashboard-heading"><h1>{strings.workspaceSettings}</h1><button type="button" onClick={back}>{strings.backToWorkspace}</button></header>
    {error && <p role="alert">{error}</p>}
    <section className="panel"><DisplayModeControl /></section>
    <section className="panel"><h2>{strings.timezone}</h2><TimezoneControl /></section>
    {!settings && !error && <p role="status">{strings.loadingWorkspaceSettings}</p>}
    {settings && <>
      <section className="panel">
        <h2>{strings.cloudAiBriefs}</h2>
        <label><input type="checkbox" checked={settings.ai_enabled} disabled={busy}
          onChange={(event) => void update(event.target.checked)} />{strings.allowCloudAiToPrioritizeEvidenceBriefs}</label>
        <p>{strings.cloudAiReceivesGenericObservationDescriptionsThe}</p>
        <p>{settings.ai_available ? formatMessage(strings.upTo0RequestsPerHourIn, settings.ai_hourly_limit) :
          strings.thisServerHasNoCloudAiProvider}{strings.evidenceBriefsRemainAvailableWithAiOff}</p>
        {saved && <p role="status">{strings.aiPreferenceSaved}</p>}
      </section>
      <section className="panel">
        <h2>{strings.dataRetention}</h2>
        <p>{settings.retention_days ? formatMessage(strings.theServerSchedulesEventsInvestigationsAndReports, settings.retention_days) :
          strings.thisWorkspaceHasNoAutomaticExpiryConfigured}</p>
        <p>{strings.collectorSettingsAndTheLatestNetworkInventory}</p>
      </section>
      <section className="panel">
        <h2>{strings.collectorAccess}</h2>
        <p>{strings.pairedCollectorsCanUploadUpTo}{settings.upload_hourly_limit}{strings.snapshotsPerHourAcrossThisWorkspaceRevoke}</p>
        <button onClick={openCollectors}>{strings.manageCollectors}</button>
      </section>
    </>}
  </main>;
}
