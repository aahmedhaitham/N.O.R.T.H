import { feedbackMessages } from './messages';
import { clientMessages } from './messages';
import { CloudGateMessages as strings } from './messages';
import { useEffect, useState, type ReactNode } from 'react';
import { CollectorSetup } from './CollectorSetup';
import { pollVisible } from './pollVisible';
import { WorkspaceSettings } from './WorkspaceSettings';
import { CollectorPicker, type WorkspaceActions } from './ShellControls';
import { clearWorkspacePreferences, readWorkspacePreference, writeWorkspacePreference } from './workspaceSession';

type Source = { id: string; label: string; updated_at: string; platform?: 'Windows' | 'Linux' | null; revoked_at?: string | null };
type WaitingCollector = Pick<Source, 'id' | 'label'>;
export type CollectorFleet = { sources: Source[]; waiting: WaitingCollector[]; select: (id: string) => void };
type DesktopRequest = { ticket: string; expires: number };
type WorkspaceSection = 'dashboard' | 'collectors' | 'settings';
export type WorkspacePanel = { title: string; content: ReactNode; close: () => void };
export type CloudToolbar = { collector: ReactNode; actions: WorkspaceActions; notice: string; interrupted: boolean };
const desktop = location.protocol === 'north:';
const ticketPattern = /^[a-f0-9]{32}\.[a-f0-9]{64}\.\d{10}\.[a-f0-9]{64}$/;
const desktopCode = (ticket: string) => ticket.slice(0, 8).toUpperCase();
const signInErrors: Record<string, string> = {
  session: feedbackMessages.theSignInRequestExpiredOrIts,
  authorization: feedbackMessages.googleDidNotAuthorizeSignInCheck,
  configuration: feedbackMessages.googleRejectedTheOauthClientCredentialsAsk,
  exchange: feedbackMessages.googleCouldNotCompleteTheCodeExchange,
  profile: feedbackMessages.northCouldNotConfirmYourGoogleAccount,
  provider: feedbackMessages.northCouldNotReachGoogleToComplete,
  workspace: feedbackMessages.northCouldNotOpenYourWorkspaceContact,
};
const desktopPost = (operation: string, payload: object, signal?: AbortSignal) => fetch('/api/cloud/desktop/' + operation, {
  method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload), signal,
});

export function CloudGate({ children }: {
  children: (source: string | null, openCollectors: () => void, controls: CloudToolbar, fleet: CollectorFleet, panel?: WorkspacePanel) => ReactNode;
}) {
  const [signedIn, setSignedIn] = useState<boolean | null>(null);
  const [key, setKey] = useState('');
  const [message, setMessage] = useState('');
  const [connectionIssue, setConnectionIssue] = useState('');
  const [busy, setBusy] = useState(false);
  const [sources, setSources] = useState<Source[]>([]);
  const [waiting, setWaiting] = useState<WaitingCollector[]>([]);
  const [active, setActive] = useState(() => readWorkspacePreference('collector'));
  const [section, updateSection] = useState<WorkspaceSection>(() => {
    const saved = readWorkspacePreference('section');
    return saved === 'collectors' || saved === 'settings' ? saved : 'dashboard';
  });
  const [panelSource, setPanelSource] = useState<string | null>(null);
  const [google, setGoogle] = useState(false);
  const [desktopRequest, setDesktopRequest] = useState<DesktopRequest | null>(null);
  const [approval, setApproval] = useState(() => {
    if (desktop) return '';
    const ticket = new URLSearchParams(location.search).get('desktop_sign_in') ?? sessionStorage.getItem('north-desktop-sign-in') ?? '';
    return ticketPattern.test(ticket) ? ticket : '';
  });
  const source = sources.find((item) => item.id === active) ?? sources[0];
  const hasSource = Boolean(source);

  function setSection(next: WorkspaceSection) {
    if (section === 'dashboard' && next !== 'dashboard') setPanelSource(source?.id ?? null);
    updateSection(next);
    writeWorkspacePreference('section', next);
  }

  function selectCollector(id: string) {
    setActive(id);
    writeWorkspacePreference('collector', id);
  }

  useEffect(() => {
    if (!desktop && location.protocol !== 'https:') return;
    const controller = new AbortController();
    void fetch('/api/cloud/auth/options', { signal: controller.signal }).then(async (response) => {
      if (!response.ok) return;
      const options = await response.json();
      if (!controller.signal.aborted) setGoogle(options.google === true);
    }).catch(() => {});
    return () => controller.abort();
  }, []);

  useEffect(() => {
    if (desktop || !approval) return;
    sessionStorage.setItem('north-desktop-sign-in', approval);
    const url = new URL(location.href);
    if (url.searchParams.has('desktop_sign_in')) {
      url.searchParams.delete('desktop_sign_in');
      history.replaceState(null, '', url);
    }
  }, [approval]);

  useEffect(() => {
    if (!desktopRequest) return;
    const expires = desktopRequest.expires;
    const controller = new AbortController();
    let timer: number | undefined;
    async function poll() {
      try {
        if (Date.now() / 1000 >= expires) throw new Error(clientMessages.desktopSignInExpiredTryAgain);
        const response = await desktopPost('exchange', {}, controller.signal);
        if (controller.signal.aborted) return;
        if (response.status === 202) { timer = window.setTimeout(poll, 2500); return; }
        if (!response.ok) throw new Error(clientMessages.desktopSignInCouldNotBeCompleted);
        setDesktopRequest(null);
        setSignedIn(true);
      } catch (error) {
        if (controller.signal.aborted) return;
        setDesktopRequest(null);
        setMessage(error instanceof Error ? error.message : strings.desktopSignInFailed);
      }
    }
    timer = window.setTimeout(poll, 2500);
    return () => { controller.abort(); window.clearTimeout(timer); };
  }, [desktopRequest]);

  async function startDesktopSignIn() {
    setBusy(true);
    setMessage('');
    try {
      const response = await desktopPost('start', {});
      if (!response.ok) throw new Error(clientMessages.couldNotStartBrowserSignIn);
      const data = await response.json();
      if (!ticketPattern.test(data.ticket) || !Number.isFinite(data.expires)) throw new Error(clientMessages.invalidSignInRequest);
      setDesktopRequest(data);
    } catch (error) {
      setMessage(error instanceof Error ? error.message : strings.couldNotStartBrowserSignIn);
    } finally { setBusy(false); }
  }

  async function approveDesktop() {
    setBusy(true);
    try {
      const response = await desktopPost('approve', { ticket: approval });
      const result = await response.json();
      setMessage(response.ok ? strings.desktopAccessApprovedYouCanReturnTo : result.detail);
      if (response.ok || response.status === 410 || response.status === 409) clearApproval();
    } catch {
      setMessage(strings.desktopApprovalFailedTryAgain);
    } finally { setBusy(false); }
  }

  function clearApproval() {
    sessionStorage.removeItem('north-desktop-sign-in');
    setApproval('');
  }

  useEffect(() => {
    const controller = new AbortController();
    async function status() {
      try {
        const response = await fetch('/api/cloud/status', { signal: controller.signal });
        if (controller.signal.aborted) return;
        if (response.ok) {
          const data = await response.json();
          if (controller.signal.aborted) return;
          setSources(data.sources);
          setWaiting(data.waiting_collectors ?? []);
          setConnectionIssue('');
          setSignedIn(true);
        } else if (response.status === 401) {
          clearWorkspacePreferences();
          setSources([]);
          setWaiting([]);
          setActive('');
          updateSection('dashboard');
          setConnectionIssue('');
          setSignedIn(false);
        } else {
          setSignedIn((current) => current ?? false);
          setConnectionIssue(feedbackMessages.northCloudIsTemporarilyUnavailableRetrying);
        }
      } catch {
        if (!controller.signal.aborted) {
          setSignedIn((current) => current ?? false);
          setConnectionIssue(feedbackMessages.couldNotReachNorthCloudRetrying);
        }
      }
    }
    const stop = pollVisible(status, signedIn && !hasSource ? 5000 : 30000);
    return () => { controller.abort(); stop(); };
  }, [signedIn, hasSource]);

  async function signIn() {
    setBusy(true);
    setMessage('');
    try {
      const response = await fetch('/api/cloud/login', {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ key }),
      });
      if (!response.ok) throw new Error(response.status === 401 ? feedbackMessages.accessKeyDidNotMatch : feedbackMessages.couldNotSignIn);
      setKey('');
      setSignedIn(true);
    } catch (error) {
      setMessage(error instanceof Error ? error.message : strings.couldNotSignIn);
    } finally {
      setBusy(false);
    }
  }

  async function signOut() {
    try {
      const response = await fetch('/api/cloud/logout', { method: 'POST' });
      if (!response.ok) throw new Error(clientMessages.signOutCouldNotBeCompleted);
      setSignedIn(false);
      setSources([]);
      setWaiting([]);
      setActive('');
      updateSection('dashboard');
      clearWorkspacePreferences();
      setMessage('');
      setConnectionIssue('');
    } catch {
      setMessage(strings.signOutCouldNotBeCompleted);
    }
  }

  if (signedIn) {
    if (approval) return <main className="cloud-sign-in"><section className="panel">
      <h1>{strings.approveNorthDesktop}</h1>
      <p>{strings.approveOnlyIfThisCodeMatchesThe}</p>
      <p><strong>{desktopCode(approval)}</strong></p>
      {message && <p role="status">{message}</p>}
      <div className="cloud-actions">
        <button onClick={() => void approveDesktop()} disabled={busy}>{strings.approveDesktopAccess}</button>
        <button onClick={clearApproval}>{strings.cancel}</button>
      </div>
    </section></main>;
    const close = () => setSection('dashboard');
    const openCollectors = () => setSection('collectors');
    const controls: CloudToolbar = {
      collector: <CollectorPicker current={source} options={[...sources, ...waiting]} choose={selectCollector} />,
      actions: { settings: () => setSection('settings'), collectors: openCollectors, signOut: () => void signOut() },
      notice: message || connectionIssue,
      interrupted: Boolean(connectionIssue),
    };
    const panel: WorkspacePanel | undefined = section === 'collectors' ? {
      title: strings.collectors, content: <CollectorSetup back={close} availableSources={sources.map(({ id }) => id)}
        useCollector={(id) => { selectCollector(id); close(); }} />, close,
    } : section === 'settings' ? {
      title: strings.workspaceSettings, content: <WorkspaceSettings back={close} openCollectors={openCollectors} />, close,
    } : undefined;
    return children(panel ? panelSource : source?.id ?? null, openCollectors, controls,
      { sources, waiting, select: selectCollector }, panel);
  }

  const keyForm = <form className="event-filters" onSubmit={(event) => {
    event.preventDefault(); void signIn();
  }}>
    <label>{strings.workspaceAccessKey}
      <input type="password" autoComplete="current-password" value={key} required
        onChange={(event) => setKey(event.target.value)} />
    </label>
    <button type="submit" disabled={busy}>{busy ? strings.signingIn : strings.signInWithKey}</button>
  </form>;

  return <main className="cloud-sign-in">
    <section className="panel">
      <h1>{strings.northCloud}</h1>
      {signedIn === false && google && (desktop ? desktopRequest ? <div>
        <p>{strings.confirmThisCodeInYourBrowser}<strong>{desktopCode(desktopRequest.ticket)}</strong></p>
        <a className="button primary-action" target="_blank" rel="noopener" href={'/desktop-approve/' + desktopRequest.ticket}>{strings.openBrowser}</a>
        <button onClick={() => setDesktopRequest(null)}>{strings.cancel}</button>
      </div> : <p><button className="primary-action" disabled={busy} onClick={() => void startDesktopSignIn()}>{strings.signInThroughBrowser}</button></p> :
        <p><a className="button primary-action" href="/api/cloud/auth/google">{strings.continueWithGoogle}</a></p>)}
      {signedIn === null ? <p>{strings.checkingYourSession}</p> : google && !desktopRequest ?
        <details className="alternate-signin"><summary>{strings.useAWorkspaceKey}</summary>{keyForm}</details> :
        !desktopRequest && keyForm}
      {message && <p role="alert">{message}</p>}
      {connectionIssue && <p role="status">{connectionIssue}</p>}
      {!message && signedIn === false && new URLSearchParams(location.search).has('sign_in_failed') &&
        <p role="alert">{signInErrors[new URLSearchParams(location.search).get('sign_in_failed') ?? ''] ??
          strings.googleSignInCouldNotBeCompleted}</p>}
    </section>
  </main>;
}
