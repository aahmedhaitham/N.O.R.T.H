import { useEffect, useRef, useState } from 'react';
import { useNetworkInventory } from './Network';
import { DisplayModeControl } from './DisplayMode';
import { setupState } from './onboardingState';
import { onboardingMessages as t } from './messages';

type Props = { endpoint: string; cloud: boolean; desktop: boolean; finish: () => void; collectors?: () => void };

export function Onboarding({ endpoint, cloud, desktop, finish, collectors }: Props) {
  const [step, setStep] = useState(0);
  const [busy, setBusy] = useState(false);
  const [monitor, setMonitor] = useState<'running' | 'failed'>();
  const [monitorConfirm, setMonitorConfirm] = useState(false);
  const heading = useRef<HTMLHeadingElement>(null);
  const { inventory, fetchError, refreshing, reloadAfterChange } = useNetworkInventory(endpoint);
  const waiting = !inventory && !fetchError;
  const windows = setupState(inventory?.sysmon, waiting, fetchError);
  const network = setupState(inventory?.neighbors, waiting, fetchError);
  const linux = setupState(inventory?.linux_journal, waiting, fetchError);
  const steps = [t.visibility, t.appearance, t.privacy];

  useEffect(() => { heading.current?.focus(); }, [step]);

  async function startMonitoring() {
    setBusy(true);
    try {
      const response = await fetch('/api/local/findings/monitor', { method: 'POST' });
      if (!response.ok || !(await response.json()).running) throw new Error();
      setMonitor('running');
      setMonitorConfirm(false);
    } catch {
      setMonitor('failed');
    } finally { setBusy(false); }
  }

  return <main className="dashboard north-onboarding" aria-labelledby="north-onboarding-title">
    <header className="dashboard-heading"><h1 id="north-onboarding-title">{t.title}</h1>
      <button type="button" onClick={finish}>{t.skip}</button>
    </header>
    <ol className="onboarding-progress" aria-label={t.steps}>
      {steps.map((name, index) => <li key={name} aria-current={step === index ? 'step' : undefined}>{name}</li>)}
    </ol>
    <section className="panel">
      <h2 ref={heading} tabIndex={-1}>{steps[step]}</h2>
      {step === 0 && <>
        <p>{t.checkIntro}</p>
        <dl className="onboarding-checks" aria-live="polite">
          <div><dt>{t.windowsEvents}</dt><dd>{t.states[windows]}</dd></div>
          <div><dt>{t.nearbyDevices}</dt><dd>{t.states[network]}</dd></div>
          {(cloud || inventory?.linux_journal) && <div><dt>{t.linuxEvents}</dt><dd>{t.states[linux]}</dd></div>}
        </dl>
        <button type="button" disabled={refreshing} onClick={reloadAfterChange}>{t.recheck}</button>
        {(windows === 'denied' || windows === 'missing' || windows === 'unavailable') && <details>
          <summary>{t.fixWindows}</summary>
          <p>{windows === 'denied' ? t.deniedHelp : windows === 'missing' ? t.missingHelp : t.readHelp}</p>
        </details>}
        {network !== 'ready' && network !== 'checking' && <details>
          <summary>{t.fixNetwork}</summary><p>{cloud ? t.cloudNetworkHelp : t.localNetworkHelp}</p>
        </details>}
        {cloud && collectors && <button type="button" onClick={collectors}>{t.collectors}</button>}
        {desktop && monitor !== 'running' && <div className="onboarding-monitor">
          {!monitorConfirm ? <button type="button" onClick={() => setMonitorConfirm(true)}>{t.monitorOptions}</button> :
            <><p>{t.monitorEffect}</p><button type="button" disabled={busy} onClick={() => void startMonitoring()}>
              {busy ? t.starting : t.start}</button>{' '}
              <button type="button" disabled={busy} onClick={() => setMonitorConfirm(false)}>{t.cancel}</button></>}
        </div>}
        {monitor && <p role="status">{monitor === 'running' ? t.monitorRunning : t.monitorFailed}</p>}
      </>}
      {step === 1 && <DisplayModeControl />}
      {step === 2 && <>
        <p>{t.localPrivacy}</p>
        <p>{cloud ? t.cloudPrivacy : t.localCloudPrivacy}</p>
        <p>{t.assistantPrivacy}</p>
      </>}
    </section>
    <footer className="finding-actions">
      {step > 0 && <button type="button" onClick={() => setStep(step - 1)}>{t.back}</button>}
      <button type="button" className="primary-action" onClick={() => step < 2 ? setStep(step + 1) : finish()}>
        {step < 2 ? t.next : t.finish}
      </button>
    </footer>
  </main>;
}
