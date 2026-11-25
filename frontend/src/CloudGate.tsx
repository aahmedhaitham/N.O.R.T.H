import { useEffect, useState, type ReactNode } from 'react';
import { CollectorSetup } from './CollectorSetup';
import { pollVisible } from './pollVisible';
import { WorkspaceSettings } from './WorkspaceSettings';
import { clearWorkspacePreferences, readWorkspacePreference, writeWorkspacePreference } from './workspaceSession';

type Source = { id: string; label: string; updated_at: string };
type DesktopRequest = { ticket: string; expires: number };
type WorkspaceSection = 'dashboard' | 'collectors' | 'settings';
export type WorkspacePanel = { title: string; content: ReactNode; close: () => void };
const desktop = location.protocol === 'north:';
const ticketPattern = /^[a-f0-9]{32}\.[a-f0-9]{64}\.\d{10}\.[a-f0-9]{64}$/;
const desktopCode = (ticket: string) => ticket.slice(0, 8).toUpperCase();
const signInErrors: Record<string, string> = {
  session: 'The sign-in request expired or its browser session was lost. Start again in this tab.',
  authorization: 'Google did not authorize sign-in. Check that you’re using a staging test account.',
  configuration: 'Google rejected the OAuth client credentials. Ask the workspace administrator to check the client ID and secret.',
  exchange: 'Google could not complete the code exchange. Start sign-in again.',
  profile: 'NORTH could not confirm your Google account. Try signing in again.',
  provider: 'NORTH could not reach Google to complete sign-in. Try again shortly.',
  workspace: 'NORTH could not open your workspace. Contact the workspace administrator.',
};
const desktopPost = (operation: string, payload: object, signal?: AbortSignal) => fetch('/api/cloud/desktop/' + operation, {
  method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload), signal,
});

export function CloudGate({ children }: {
  children: (source: string | null, openCollectors: () => void, controls: ReactNode, panel?: WorkspacePanel) => ReactNode;
}) {
  const [signedIn, setSignedIn] = useState<boolean | null>(null);
  const [key, setKey] = useState('');
  const [message, setMessage] = useState('');
  const [connectionIssue, setConnectionIssue] = useState('');
  const [busy, setBusy] = useState(false);
  const [sources, setSources] = useState<Source[]>([]);
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
        if (Date.now() / 1000 >= expires) throw new Error('Desktop sign-in expired. Try again.');
        const response = await desktopPost('exchange', {}, controller.signal);
        if (controller.signal.aborted) return;
        if (response.status === 202) { timer = window.setTimeout(poll, 2500); return; }
        if (!response.ok) throw new Error('Desktop sign-in could not be completed. Try again.');
        setDesktopRequest(null);
        setSignedIn(true);
      } catch (error) {
        if (controller.signal.aborted) return;
        setDesktopRequest(null);
        setMessage(error instanceof Error ? error.message : 'Desktop sign-in failed.');
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
      if (!response.ok) throw new Error('Could not start browser sign-in.');
      const data = await response.json();
      if (!ticketPattern.test(data.ticket) || !Number.isFinite(data.expires)) throw new Error('Invalid sign-in request.');
      setDesktopRequest(data);
    } catch (error) {
      setMessage(error instanceof Error ? error.message : 'Could not start browser sign-in.');
    } finally { setBusy(false); }
  }

  async function approveDesktop() {
    setBusy(true);
    try {
      const response = await desktopPost('approve', { ticket: approval });
      const result = await response.json();
      setMessage(response.ok ? 'Desktop access approved. You can return to NORTH.' : result.detail);
      if (response.ok || response.status === 410 || response.status === 409) clearApproval();
    } catch {
      setMessage('Desktop approval failed. Try again.');
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
          setConnectionIssue('');
          setSignedIn(true);
        } else if (response.status === 401) {
          clearWorkspacePreferences();
          setSources([]);
          setActive('');
          updateSection('dashboard');
          setConnectionIssue('');
          setSignedIn(false);
        } else {
          setSignedIn((current) => current ?? false);
          setConnectionIssue('NORTH Cloud is temporarily unavailable. Retrying…');
        }
      } catch {
        if (!controller.signal.aborted) {
          setSignedIn((current) => current ?? false);
          setConnectionIssue('Could not reach NORTH Cloud. Retrying…');
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
      if (!response.ok) throw new Error(response.status === 401 ? 'Access key did not match.' : 'Could not sign in.');
      setKey('');
      setSignedIn(true);
    } catch (error) {
      setMessage(error instanceof Error ? error.message : 'Could not sign in.');
    } finally {
      setBusy(false);
    }
  }

  async function signOut() {
    try {
      const response = await fetch('/api/cloud/logout', { method: 'POST' });
      if (!response.ok) throw new Error('Sign-out could not be completed.');
      setSignedIn(false);
      setSources([]);
      setActive('');
      updateSection('dashboard');
      clearWorkspacePreferences();
      setMessage('');
      setConnectionIssue('');
    } catch {
      setMessage('Sign-out could not be completed.');
    }
  }

  if (signedIn) {
    const controls = <div className="cloud-banner">
      <div className="cloud-context">
      {source ? <label><span>Collector</span>
        <select value={source.id} onChange={(event) => selectCollector(event.target.value)}>
          {sources.map((item) => <option key={item.id} value={item.id}>{item.label}</option>)}
        </select>
      </label> : <span>No collector connected</span>}
      {source && <span>Last sync {new Date(source.updated_at).toLocaleString()}</span>}
      </div>
      {message && <span role="alert">{message}</span>}
      {connectionIssue && <span role="status">{connectionIssue}</span>}
      <div className="cloud-actions">
        <button onClick={() => setSection('collectors')} aria-pressed={section === 'collectors'}>Collectors</button>
        <button onClick={() => setSection('settings')} aria-pressed={section === 'settings'}>Settings</button>
        <button onClick={() => void signOut()}>Sign out</button>
      </div>
    </div>;
    if (approval) return <main className="cloud-sign-in"><section className="panel">
      <h1>Approve NORTH Desktop</h1>
      <p>Approve only if this code matches the one displayed in the desktop app.</p>
      <p><strong>{desktopCode(approval)}</strong></p>
      {message && <p role="status">{message}</p>}
      <div className="cloud-actions">
        <button onClick={() => void approveDesktop()} disabled={busy}>Approve desktop access</button>
        <button onClick={clearApproval}>Cancel</button>
      </div>
    </section></main>;
    const close = () => setSection('dashboard');
    const openCollectors = () => setSection('collectors');
    const panel: WorkspacePanel | undefined = section === 'collectors' ? {
      title: 'Collectors', content: <CollectorSetup back={close} availableSources={sources.map(({ id }) => id)}
        useCollector={(id) => { selectCollector(id); close(); }} />, close,
    } : section === 'settings' ? {
      title: 'Workspace settings', content: <WorkspaceSettings back={close} openCollectors={openCollectors} />, close,
    } : undefined;
    return children(panel ? panelSource : source?.id ?? null, openCollectors, controls, panel);
  }

  const keyForm = <form className="event-filters" onSubmit={(event) => {
    event.preventDefault(); void signIn();
  }}>
    <label>Workspace access key
      <input type="password" autoComplete="current-password" value={key} required
        onChange={(event) => setKey(event.target.value)} />
    </label>
    <button type="submit" disabled={busy}>{busy ? 'Signing in…' : 'Sign in with key'}</button>
  </form>;

  return <main className="cloud-sign-in">
    <section className="panel">
      <h1>NORTH Cloud</h1>
      {signedIn === false && google && (desktop ? desktopRequest ? <div>
        <p>Confirm this code in your browser <strong>{desktopCode(desktopRequest.ticket)}</strong></p>
        <a className="button primary-action" target="_blank" rel="noopener" href={'/desktop-approve/' + desktopRequest.ticket}>Open browser</a>
        <button onClick={() => setDesktopRequest(null)}>Cancel</button>
      </div> : <p><button className="primary-action" disabled={busy} onClick={() => void startDesktopSignIn()}>Sign in through browser</button></p> :
        <p><a className="button primary-action" href="/api/cloud/auth/google">Continue with Google</a></p>)}
      {signedIn === null ? <p>Checking your session…</p> : google && !desktopRequest ?
        <details className="alternate-signin"><summary>Use a workspace key</summary>{keyForm}</details> :
        !desktopRequest && keyForm}
      {message && <p role="alert">{message}</p>}
      {connectionIssue && <p role="status">{connectionIssue}</p>}
      {!message && signedIn === false && new URLSearchParams(location.search).has('sign_in_failed') &&
        <p role="alert">{signInErrors[new URLSearchParams(location.search).get('sign_in_failed') ?? ''] ??
          'Google sign-in could not be completed. Try again.'}</p>}
    </section>
  </main>;
}
