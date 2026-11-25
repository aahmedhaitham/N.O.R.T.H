import { useEffect, useState } from 'react';

type Review = { status: 'open' | 'investigating' | 'resolved'; notes: string; revision: number; updated_at: string | null };

export function CaseReview({ endpoint }: { endpoint: string }) {
  const [review, setReview] = useState<Review | null>(null);
  const [original, setOriginal] = useState<Review | null>(null);
  const [revision, setRevision] = useState(0);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState('');
  const [error, setError] = useState(false);
  useEffect(() => {
    const controller = new AbortController();
    void fetch(endpoint, { signal: controller.signal }).then(async (response) => {
      if (!response.ok) throw new Error();
      const value: Review = await response.json();
      if (!controller.signal.aborted) { setReview(value); setOriginal(value); }
    }).catch(() => {
      if (!controller.signal.aborted) { setError(true); setMessage('Case review unavailable.'); }
    });
    return () => controller.abort();
  }, [endpoint, revision]);

  async function save(value: Review) {
    setBusy(true);
    setError(false);
    setMessage('');
    try {
      const response = await fetch(endpoint, {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(value),
      });
      if (!response.ok) {
        throw new Error(response.status === 409 ? 'This review changed in another session. Copy any unsaved notes before reloading.' : 'Could not save case review.');
      }
      const saved: Review = await response.json();
      setReview(saved);
      setOriginal(saved);
      setMessage('Review saved.');
    } catch (exception) {
      setError(true);
      setMessage(exception instanceof Error ? exception.message : 'Could not save case review.');
    } finally { setBusy(false); }
  }

  const changed = review && (review.status !== original?.status || review.notes !== original?.notes);
  return <section className="panel">
    <h2>Case review</h2>
    {!review && !error && <p role="status">Loading review…</p>}
    {review && <form className="case-review" onSubmit={(event) => { event.preventDefault(); void save(review); }}>
      <label>Status <select disabled={busy} value={review.status} onChange={(event) =>
        setReview({ ...review, status: event.target.value as Review['status'] })}>
        <option value="open">Open</option><option value="investigating">Investigating</option><option value="resolved">Resolved</option>
      </select></label>
      <label>Analyst notes <textarea disabled={busy} maxLength={2000} rows={4} value={review.notes}
        onChange={(event) => setReview({ ...review, notes: event.target.value })} /></label>
      <div className="case-links"><button type="submit" disabled={busy || !changed}>Save review</button>
        {review.updated_at && <small>Saved {new Date(review.updated_at).toLocaleString()}</small>}</div>
    </form>}
    {message && <p role={error ? 'alert' : 'status'}>{message}</p>}
    {error && <button onClick={() => { setMessage(''); setError(false); setReview(null); setRevision((value) => value + 1); }}>Reload review</button>}
  </section>;
}
