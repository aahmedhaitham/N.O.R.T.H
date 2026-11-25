import { useEffect, useState } from 'react';

type Search = { id: string; label: string; query: string; kind: string };
const endpoint = '/api/cloud/saved-searches';

export function SavedSearches({ query, kind, apply }: {
  query: string; kind: string; apply: (search: Search) => void;
}) {
  const [searches, setSearches] = useState<Search[]>([]);
  const [label, setLabel] = useState('');
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState('');
  useEffect(() => {
    const controller = new AbortController();
    void fetch(endpoint, { signal: controller.signal }).then(async (response) => {
      if (!response.ok) throw new Error();
      const result = await response.json();
      if (!controller.signal.aborted) setSearches(result.searches);
    }).catch(() => {
      if (!controller.signal.aborted) setMessage('Saved searches could not be loaded.');
    });
    return () => controller.abort();
  }, []);

  async function mutate(payload: object, removeId?: string) {
    setBusy(true);
    setMessage('');
    try {
      const response = await fetch(endpoint, { method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload) });
      const result = await response.json();
      if (!response.ok) throw new Error(result.detail ?? 'Could not update saved searches.');
      if (removeId) setSearches((current) => current.filter((item) => item.id !== removeId));
      else {
        setSearches((current) => [...current, result].sort((a, b) => a.label.localeCompare(b.label)));
        setLabel('');
      }
      setMessage(removeId ? 'Saved search removed.' : 'Search saved.');
    } catch (error) {
      setMessage(error instanceof Error ? error.message : 'Could not update saved searches.');
    } finally { setBusy(false); }
  }

  return <details className="panel">
    <summary>Saved searches{searches.length > 0 ? ` (${searches.length})` : ''}</summary>
    <ul className="network-list">{searches.map((item) => <li key={item.id}>
      <div className="case-links">
        <button onClick={() => apply(item)}>{item.label}</button>
        <button disabled={busy} onClick={() => void mutate({ action: 'remove', id: item.id }, item.id)}
          aria-label={'Remove saved search ' + item.label}>Remove</button>
      </div>
    </li>)}</ul>
    {query || kind ? <form className="event-filters" onSubmit={(event) => {
      event.preventDefault(); void mutate({ action: 'save', label, query, kind });
    }}>
      <label>Save the applied filters as <input required maxLength={60} value={label} onChange={(event) => setLabel(event.target.value)} /></label>
      <button type="submit" disabled={busy || !label.trim()}>Save search</button>
    </form> : <p>Apply an event filter to save it.</p>}
    {message && <p role="status">{message}</p>}
  </details>;
}
