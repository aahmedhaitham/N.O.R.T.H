import { feedbackMessages } from './messages';
import { CaseReviewMessages as strings } from './messages';
import { TimeDisplay } from './TimeDisplay';
import { SelectControl } from './SelectControl';
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
      if (!controller.signal.aborted) { setError(true); setMessage(strings.caseReviewUnavailable); }
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
        throw new Error(response.status === 409 ? feedbackMessages.thisReviewChangedInAnotherSessionCopy : feedbackMessages.couldNotSaveCaseReview);
      }
      const saved: Review = await response.json();
      setReview(saved);
      setOriginal(saved);
      setMessage(strings.reviewSaved);
    } catch (exception) {
      setError(true);
      setMessage(exception instanceof Error ? exception.message : strings.couldNotSaveCaseReview);
    } finally { setBusy(false); }
  }

  const changed = review && (review.status !== original?.status || review.notes !== original?.notes);
  return <section className="panel">
    <h2>{strings.caseReview}</h2>
    {!review && !error && <p role="status">{strings.loadingReview}</p>}
    {review && <form className="case-review" onSubmit={(event) => { event.preventDefault(); void save(review); }}>
      <label>{strings.status}<SelectControl label={strings.caseStatus} disabled={busy} value={review.status}
        onChange={(value) => setReview({ ...review, status: value as Review['status'] })}
        options={[{ value: 'open', label: strings.open }, { value: 'investigating', label: strings.investigating },
          { value: 'resolved', label: strings.resolved }]} /></label>
      <label>{strings.analystNotes}<textarea disabled={busy} maxLength={2000} rows={4} value={review.notes}
        onChange={(event) => setReview({ ...review, notes: event.target.value })} /></label>
      <div className="case-links"><button type="submit" disabled={busy || !changed}>{strings.saveReview}</button>
        {review.updated_at && <small>{strings.saved}<TimeDisplay value={review.updated_at} /></small>}</div>
    </form>}
    {message && <p role={error ? 'alert' : 'status'}>{message}</p>}
    {error && <button onClick={() => { setMessage(''); setError(false); setReview(null); setRevision((value) => value + 1); }}>{strings.reloadReview}</button>}
  </section>;
}
