export async function readJson<T>(url: string, options?: RequestInit, timeout = 35_000): Promise<T> {
  const deadline = AbortSignal.timeout(timeout);
  const signal = options?.signal ? AbortSignal.any([deadline, options.signal]) : deadline;
  const response = await fetch(url, { cache: 'no-store', ...options, signal });
  if (!response.ok || !response.headers.get('content-type')?.toLowerCase().includes('application/json')) {
    throw new Error('The request could not be completed.');
  }
  const text = await response.text();
  if (!text.trim()) throw new Error('The server returned no data.');
  try { return JSON.parse(text) as T; } catch { throw new Error('The server returned unreadable data.'); }
}
