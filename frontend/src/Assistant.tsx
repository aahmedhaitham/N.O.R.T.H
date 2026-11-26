import { createContext, useContext, useEffect, useRef, useState, type ReactNode } from 'react';
import { answer, intents, type Area, type Row, type Snapshot } from './assistantEngine';
import type { ChartEvent } from './OverviewCharts';

type Selection = { area: Area; row: Row };
type AssistantState = {
  read: () => Snapshot; publish: (area: Area, rows: Row[]) => void;
  events: (rows: ChartEvent[]) => void; event: (id: string) => ChartEvent | undefined;
  locations: (rows: Record<string, string>) => void;
  availability: (area: Area, reason?: string) => void;
  open: (context?: Selection, question?: string) => void;
  request: { context?: Selection; question?: string } | null; close: () => void;
};
const Assistant = createContext<AssistantState | null>(null);
export const useAssistant = () => useContext(Assistant);

export function AssistantProvider({ children }: { children: ReactNode }) {
  const data = useRef<Snapshot>({});
  const evidence = useRef(new Map<string, ChartEvent>());
  const countries = useRef<Record<string, string>>({});
  const [request, setRequest] = useState<AssistantState['request']>(null);
  const [methods] = useState(() => ({
    read: () => ({
      ...data.current,
      events: data.current.events?.map((row) => {
        const address = evidence.current.get(row.id)?.destination;
        const country = address && Object.hasOwn(countries.current, address) ? countries.current[address] : '';
        return country ? { ...row, country, terms: [...(row.terms ?? []), country] } : row;
      }),
    }),
    publish: (area: Area, rows: Row[]) => { data.current[area] = rows.slice(0, 200); },
    events: (rows: ChartEvent[]) => {
      const incoming = new Map(rows.slice(0, 100).map((event) => [event.id, event]));
      const next = new Map([...incoming, ...[...evidence.current].filter(([id]) => !incoming.has(id))]);
      evidence.current = new Map([...next].slice(0, 200));
      data.current.events = [...evidence.current.values()].map(eventRow);
    },
    event: (id: string) => evidence.current.get(id),
    locations: (rows: Record<string, string>) => { countries.current = rows; },
    availability: (area: Area, reason?: string) => {
      const unavailable = data.current.unavailable ??= {};
      if (reason) unavailable[area] = reason; else delete unavailable[area];
    },
    open: (context?: Selection, question?: string) => setRequest({ context, question }),
    close: () => setRequest(null),
  }));
  return <Assistant.Provider value={{ ...methods, request }}>{children}</Assistant.Provider>;
}

export function eventRow(event: ChartEvent): Row {
  const raw = event.raw as { data?: { win?: { eventdata?: { queryName?: string } } }; QueryName?: string } | null;
  return { id: event.id, label: event.process || event.host || 'Recorded event', timestamp: event.timestamp,
    terms: [event.process, event.host, event.destination, event.source_ip ?? '', raw?.QueryName ?? '',
      raw?.data?.win?.eventdata?.queryName ?? ''].filter((value) => typeof value === 'string' && !!value),
    detail: event.destination || event.target || event.host };
}

export function Explain({ area, row, question }: Selection & { question: string }) {
  const open = useAssistant()?.open;
  return open && <button type="button" onClick={() => open({ area, row }, question)}>
    {question === 'Why am I seeing this alert?' ? 'Why am I seeing this?' : 'Explain this'}
  </button>;
}

type Entry = { question: string; result: ReturnType<typeof answer> };
const page: Record<Area, string> = {
  devices: 'ATLAS', connections: 'ATLAS', cases: 'ECHO', events: 'IRIS', findings: 'Overview', coverage: 'Detections',
};
function EvidenceText({ value }: { value: string }) {
  const [copied, setCopied] = useState(false);
  return <span className="assistant-evidence"><code>{value.length > 180 ? value.slice(0, 177) + '…' : value}</code>
    <button type="button" onClick={() => void navigator.clipboard.writeText(value).then(() => setCopied(true), () => setCopied(false))}>
      {copied ? 'Copied' : 'Copy'}
    </button></span>;
}
export function AssistantPanel({ cite }: { cite: (area: Area, row: Row) => void }) {
  const assistant = useAssistant()!;
  const [history, setHistory] = useState<Entry[]>([]);
  const [input, setInput] = useState('');
  const [context, setContext] = useState<Selection>();
  const field = useRef<HTMLInputElement>(null);
  const request = assistant.request;
  const read = assistant.read;
  useEffect(() => {
    if (!request) return;
    setContext(request.context);
    if (request.question) {
      const { question, context } = request;
      setHistory((previous) => [...previous.slice(-23), { question, result: answer(question, read(), context) }]);
    }
    field.current?.focus();
  }, [request, read]);
  useEffect(() => {
    function shortcut(event: KeyboardEvent) {
      if (event.defaultPrevented || event.repeat || !(event.ctrlKey || event.metaKey) || event.key.toLowerCase() !== 'j') return;
      event.preventDefault();
      if (request) assistant.close(); else assistant.open();
    }
    window.addEventListener('keydown', shortcut);
    return () => window.removeEventListener('keydown', shortcut);
  }, [assistant, request]);
  function ask(question: string) {
    if (!question.trim()) return;
    setHistory((previous) => [...previous.slice(-23), { question, result: answer(question, read(), context) }]);
    setInput('');
  }
  if (!request) return null;
  const latest = history.at(-1);
  return <aside className="assistant-dock" aria-labelledby="assistant-title" onKeyDown={(event) => {
    if (event.key === 'Escape') { event.stopPropagation(); assistant.close(); }
  }}>
    <header><h2 id="assistant-title">NORTH Assistant</h2><button type="button" onClick={assistant.close}>Close</button></header>
    <p>Built in · works offline · answers from your NORTH data</p>
    {context && <button type="button" onClick={() => setContext(undefined)}>Clear evidence context</button>}
    <div className="assistant-history" aria-live="polite">
      {history.map(({ question, result }, index) => <article key={index}>
        <h3>{question}</h3><p>{result.text}</p>
        {result.rows.map((row) => <div key={row.id}>
          <EvidenceText value={row.label} />
          {row.detail && <EvidenceText value={row.detail} />}
          {result.area && <button type="button" onClick={() => cite(result.area!, row)}>
            Open evidence in {page[result.area]}
          </button>}
        </div>)}
      </article>)}
    </div>
    <div className="finding-actions">
      {latest?.result.text.startsWith('I couldn’t confidently') && <span>Did you mean…?</span>}
      {(latest?.result.suggestions ?? ['Is my PC okay?', 'What needs attention?', 'List devices']).map((question) =>
        <button type="button" key={question} onClick={() => ask(question)}>{question}</button>)}
    </div>
    <form className="finding-actions" onSubmit={(event) => { event.preventDefault(); ask(input); }}>
      <label>Ask NORTH <input ref={field} value={input} maxLength={240} list="north-assistant-questions"
        onChange={(event) => setInput(event.target.value)} /></label>
      <datalist id="north-assistant-questions">{intents.flatMap((intent) => intent.examples).map((question) =>
        <option key={question} value={question} />)}</datalist>
      <button type="submit" disabled={!input.trim()}>Ask</button>
    </form>
    <details><summary>What you can ask</summary><ul>{intents.map((intent) => <li key={intent.id}>
      <button type="button" onClick={() => ask(intent.examples[0])}>{intent.examples[0]}</button>
    </li>)}</ul></details>
    <button type="button" disabled={!history.length} onClick={() => { setHistory([]); setContext(undefined); }}>Clear history</button>
  </aside>;
}
