export type Area = 'events' | 'devices' | 'connections' | 'findings' | 'cases' | 'coverage' | 'verification' | 'posture' | 'sensor' | 'cloudtrail';
export type Row = {
  id: string; label: string; detail?: string; timestamp?: string; status?: string;
  terms?: string[]; guidance?: string; alternative?: string; country?: string; score?: string;
};
export type VerificationSummary = { at: string; counts: number[] };
export type Snapshot = Partial<Record<Exclude<Area, "verification">, Row[]>> & { verification?: VerificationSummary; verificationRows?: Row[]; unavailable?: Partial<Record<Area, string>> };
export type Tool = Area | 'guide';
type Intent = { id: string; examples: string[]; keywords: string[]; tool: Tool; template: string; follow: string[] };
const intent = (id: string, tool: Tool, template: string, keywords: string, ...examples: string[]): Intent =>
  ({ id, tool, template, keywords: keywords.split('|'), examples,
    follow: tool === 'guide' ? ['What can NORTH Assistant do?'] : ['What needs attention?', 'What can NORTH see?'] });

export const intents = [
  intent('status', 'cases', 'Open investigations in the available snapshot.', 'overall status|is my pc okay|health', 'Is my PC okay?', 'What is my overall status?'),
  intent('attention', 'findings', 'Unreviewed findings in the available snapshot.', 'needs attention|unreviewed|alerts', 'What needs attention?'),
  intent('explain-finding', 'findings', 'Recorded findings explain what triggered the observation.', 'explain finding|describe finding', 'Explain this finding'),
  intent('danger', 'findings', 'Use the finding severity and its evidence to assess concern.', 'dangerous|severity|serious', 'Is this finding dangerous?'),
  intent('false-positive', 'findings', 'Possible benign explanations for the recorded findings.', 'false positive|benign|likely fine', 'Could this finding be a false positive?'),
  intent('next', 'findings', 'Suggested review steps from the recorded findings.', 'what should i do|next action|next steps', 'What should I do?'),
  intent('why-alert', 'findings', 'These observations are the basis for the available findings.', 'why alert|seeing this alert|triggered', 'Why am I seeing this alert?'),
  intent('devices', 'devices', 'Devices reported in the available inventory.', 'list devices|network devices|who is on', 'List devices', 'Who is on my network?'),
  intent('new-device', 'devices', 'Devices flagged as new in the available inventory.', 'who is new|new devices|unrecognized', 'Who is new on my network?'),
  intent('known-device', 'devices', 'Matching device records and their review state.', 'known device|is device|recognize device', 'Is this device known?'),
  intent('trust', 'devices', 'Open the device record and review it there. NORTH Assistant cannot change trust.', 'mark trusted|trust a device|trusted', 'Mark a device trusted'),
  intent('outbound', 'connections', 'Recorded outbound connections in the available snapshot.', 'connected to the internet|outbound|internet connections', 'What connected to the internet?'),
  intent('domain', 'events', 'Recorded events matching the requested domain or application.', 'app talked|dns domain|contacted domain', 'Which app talked to a domain?'),
  intent('country', 'events', 'Recorded application events joined to an approximate destination country by exact IP address.', 'country|location|region', 'Which app talked to a country?'),
  intent('changed', 'events', 'Recent recorded events within the requested period.', 'what changed|since yesterday|recent changes', 'What changed since yesterday?'),
  intent('visibility', 'coverage', 'Visibility reported by the local collector and rule catalog.', 'can north see|visibility|coverage', 'What can NORTH see?'),
  intent('blind', 'coverage', 'Coverage gaps reported by the local rule catalog.', 'blind to|blind spots|missing coverage', 'What is NORTH blind to?'),
  intent('fix', 'coverage', 'Review the saved remediation guidance. No settings have been changed.', 'fix a gap|fix coverage|remediation', 'How do I fix a coverage gap?'),
  intent('sysmon', 'coverage', 'Sysmon requirements and their recorded state.', 'sysmon installed|sysmon status|is sysmon', 'Is Sysmon installed?'),
  intent('empty', 'guide', 'An empty view can mean collection has not started, a source cannot be read, or no matching events were recorded. Check source status and clear filters to distinguish them.', 'screen empty|no results|why empty', 'Why is this screen empty?'),
  intent('process-events', 'events', 'Recorded events matching the specified process.', 'events for process|process events|process name', 'Show events for a process'),
  intent('host-events', 'events', 'Recorded events matching the specified host.', 'events for host|host events|computer name', 'Show events for a host'),
  intent('technique', 'coverage', 'Matching techniques from bundled rule metadata.', 'attack technique|mitre technique|technique id', 'What is this ATT&CK technique?'),
  intent('report', 'cases', 'Open an investigation in ECHO and choose Export report.', 'export report|download report|report export', 'How do I export a report?'),
  intent('capture', 'guide', 'Open ATLAS, choose Packet traces, and select an authorized adapter or open a saved capture. Begin capture from that screen.', 'capture traffic|packet capture|capture packets|pcap', 'How do I capture traffic?'),
  intent('privacy', 'guide', 'This assistant reads snapshots already available in NORTH. It sends no requests. Other NORTH features can sync observations when a cloud collector is configured.', 'what leaves|privacy|upload', 'What leaves my PC?'),
  intent('help', 'guide', 'Choose a question below or include a recorded device, app, host, address, or time range.', 'help|capabilities|can north assistant do', 'What can NORTH Assistant do?'),
  intent('glossary-process', 'guide', 'A process is a running instance of a program. A parent process can start another process.', 'what is a process|define process', 'What is a process?'),
  intent('glossary-dns', 'guide', 'DNS maps names to network records such as IP addresses. A DNS query alone does not show that a connection succeeded.', 'what is dns|define dns', 'What is DNS?'),
  intent('glossary-mac', 'guide', 'A MAC address identifies a network interface on a local link. Devices can use randomized addresses.', 'what is a mac|define mac', 'What is a MAC address?'),
  intent('glossary-sysmon', 'guide', 'Sysmon is a Windows monitoring service that writes selected system activity to a Windows event log.', 'what is sysmon|define sysmon', 'What is Sysmon?'),
  intent('glossary-attack', 'guide', 'MITRE ATT&CK describes observed adversary tactics and techniques. A rule mapping indicates what a signal can help investigate.', 'what is attack|define attck|mitre framework', 'What is ATT&CK?'),
  intent('glossary-ip', 'guide', 'An IP address identifies a network endpoint. It does not by itself establish the owner or physical location.', 'what is an ip|define ip address', 'What is an IP address?'),
  intent('verify-pc', 'verification', 'Latest local PC verification report.', 'verify pc|verify computer|check this pc|run pc check|verify workstation', 'Verify my PC'),
  intent('sensor-self-test', 'sensor', 'Open Detections and confirm the recorded evidence check there.', 'sensor self test|test sensors|sensor evidence check|test detections', 'Run the sensor self-test'),
  intent('known-good-changes', 'verification', 'Recorded differences from the selected known-good snapshot.', 'known good changes|baseline differences|drift since baseline|changed since known good', 'What changed since known good?'),
  intent('posture-score', 'posture', 'The latest posture score counts only readable checks.', 'posture score|security score|lost points|score dropped', 'What is my security score and why did it drop?'),
  intent('defender-state', 'posture', 'Defender status from the latest local posture check.', 'defender running|defender protection|antivirus enabled|defender on', 'Is Defender on?'),
  intent('updates-pending', 'posture', 'Pending updates from the local Windows Update cache.', 'pending updates|windows update queue|missing updates|updates waiting', 'Are updates pending?'),
  intent('posture-fix', 'posture', 'Review the failed settings and use the posture panel to preview an available repair.', 'fix failing check|repair posture|remediate a setting|posture fix', 'How do I fix a failing check?'),
  intent('cloudtrail-summary', 'cloudtrail', 'Coverage of CloudTrail events imported on this PC.', 'cloudtrail import|aws trail summary|cloudtrail coverage|cloudtrail report', 'Summarize my CloudTrail import'),
  intent('finding-score', 'findings', 'Finding severity, evidence confidence and baseline rarity.', 'finding score|finding confidence|finding rarity|alert score', 'Explain a finding’s score'),
  intent('investigations', 'cases', 'Investigations loaded in ECHO.', 'list investigations|open cases|echo cases', 'List investigations'),
];

const normalize = (value: string) => value.toLowerCase().normalize('NFKC').replace(/att\s*&\s*ck/g, 'attack')
  .replace(/[^\p{L}\p{N}]+/gu, ' ').trim()
  .replace(/^(?:hey north |please |could you )+/, '').replace(/ (?:please|thanks)$/, '');
const words = (value: string) => normalize(value).split(/\s+/).filter(Boolean)
  .map((word) => word.length > 4 ? word.replace(/(?:ing|ed|s)$/, '') : word);
function similarity(a: string, b: string) {
  const x = words(a), y = words(b);
  if (!x.length || !y.length) return 0;
  const overlap = y.reduce((score, token) => {
    if (x.includes(token)) return score + 1;
    const transposed = token.length >= 5 && x.some((word) => {
      if (word.length !== token.length) return false;
      let index = 0;
      while (index < token.length && word[index] === token[index]) index++;
      return index + 1 < token.length && word[index] === token[index + 1] &&
        word[index + 1] === token[index] && word.slice(index + 2) === token.slice(index + 2);
    });
    return score + (transposed ? 0.85 : 0);
  }, 0);
  const trigrams = (input: string) => new Set(Array.from(
    { length: Math.max(0, input.length - 2) }, (_, i) => input.slice(i, i + 3)));
  const t = trigrams(normalize(a)), u = trigrams(normalize(b));
  const fuzzy = [...u].filter((part) => t.has(part)).length * 2 / Math.max(1, t.size + u.size);
  return Math.max(overlap / y.length * 0.78 + overlap / x.length * 0.22, fuzzy * 0.9);
}

const localRoutes: [string, RegExp, RegExp][] = [
  ['cloudtrail-summary', /cloud\s*trail|aws/, /import|audit|export|file|summari|report|scope|events|records|dataset/],
  ['known-good-changes', /baseline|known good|reference|trusted|snapshot/, /compar|differ|drift|chang|saved|added|vanish|marked/],
  ['finding-score', /finding|alert|detection/, /confiden|severit|rari|rarity|rated|rating|graded|score|scoring|unusual|points/],
  ['posture-fix', /posture|check|setting|configuration/, /repair|fix|correct|remedia/],
  ['posture-score', /posture|security|windows|setting|checks|readable/, /score|grade|rating|points|marks|weighted/],
  ['updates-pending', /updates?|patches|upgrades|updater/, /pend|queued|queue|waiting|uninstall|missing|not installed|behind|backlog|available|cache/],
  ['defender-state', /defender|anti\s*virus|windows av|virus protection|malware protection|real time|tamper protection/, /active|running|on|off|enable|disable|state|observed|switched|up|protection/],
  ['sensor-self-test', /sensor|telemetry|pipeline|log reader|collector signals|detection self|stored events/, /test|verify|validat|prove|check|exercise/],
  ['blind', /activity|coverage|sources|collector|events|monitoring|telemetry|logging|north|windows|app|visibility/, /gap|blind|invisib|unobserv|dark|can t see|not observe|no visibility|missing|slip past|fail to observe/],
  ['verify-pc', /pc|laptop|computer|machine|workstation|endpoint|desktop/, /verif|check|once over|assessment|inspection|verdict/],
];

function localIntent(query: string) {
  const normalized = normalize(query);
  const matched = localRoutes.find(([, subject, request]) => subject.test(normalized) && request.test(normalized));
  return matched ? intents.find((item) => item.id === matched[0]) : undefined;
}

export function matchIntent(question: string) {
  const query = question.slice(0, 240).trim();
  const ranked = intents.map((item) => ({ item, score: Math.max(
    ...item.examples.map((example) => similarity(query, example)),
    ...item.keywords.map((phrase) => similarity(query, phrase) * 0.91),
  ) })).sort((a, b) => b.score - a.score);
  const top = ranked[0];
  const confident = !!query && top.score >= 0.67 && (top.score >= 0.98 || top.score - ranked[1].score >= 0.035);
  const local = localIntent(query);
  const answer = !confident || (top.item.id === 'visibility' && local?.id === 'blind') ? local : top.item;
  return { query, intent: answer,
    suggestions: ranked.slice(0, 3).map(({item}) => item.examples[0]) };
}

export function answer(question: string, source: Snapshot, context?: { area: Area; row: Row }, now = Date.now()) {
  const { query, intent, suggestions } = matchIntent(question);
  if ((intent?.id === 'status' || intent?.id === 'verify-pc') && source.verification) {
    const { at, counts: [fine, review, unknown] } = source.verification;
    return { text: `Latest Verify my PC report (${at}): ${fine} checked and fine, ${review} need a look, ${unknown} could not be checked.`,
      suggestions: ['What needs attention?'], rows: source.verificationRows?.slice(0, 1) ?? [], area: 'verification' as Area };
  }
  if (!intent) return { text: 'I couldn’t confidently match that question.', suggestions, rows: [] };
  const normalized = normalize(query);
  const knownCountry = source.events?.some((row) => row.country &&
    (' ' + normalized + ' ').includes(' ' + normalize(row.country) + ' '));
  const { id, tool, template, follow } = intent.id === 'domain' && knownCountry
    ? intents.find((entry) => entry.id === 'country')! : intent;
  if (tool === 'guide') return { text: template, suggestions: follow, rows: [] };
  const useContext = context?.area === tool && [
    'explain-finding', 'danger', 'false-positive', 'next', 'why-alert', 'known-device', 'new-device',
    'trust', 'process-events', 'host-events', 'finding-score',
  ].includes(id);
  const available = useContext ? [context.row] : tool === 'verification' ? source.verificationRows : source[tool];
  if (id === 'sensor-self-test' && !available?.length) return {
    text: template, rows: [{ id: 'check', label: 'Sensor evidence check' }], area: tool, suggestions: follow,
  };
  if (!available || !available.length && source.unavailable?.[tool]) return {
    text: source.unavailable?.[tool] ?? 'This data has not been loaded into the current snapshot. Open the relevant NORTH page to check its source.',
    suggestions: follow, rows: [], area: tool,
  };
  let rows = available.slice(0, 200);
  const addresses = query.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b|(?:[a-f\d]{2}[:-]){5}[a-f\d]{2}|(?:[a-f\d]{0,4}:){2,}[a-f\d]{0,4}|\b(?:[a-z\d-]+\.)+[a-z]{2,}\b/gi) ?? [];
  const exact = rows.flatMap((row) => [row.label, ...(row.terms ?? [])]).filter((name) => name && normalize(name).length > 2 &&
    (' ' + normalized + ' ').includes(' ' + normalize(name) + ' '));
  const entities = [...new Set([...addresses, ...exact])];
  const namedSlot = /^(?:is device (.+) known|show events for (?:process|host) (.+)|which app talked to (.+))$/.exec(normalized)
    ?.slice(1).find(Boolean);
  if (!useContext && !entities.length && namedSlot && !['a domain', 'a country'].includes(namedSlot)) {
    return { text: 'I could not find that name in the available records. Check the spelling or open the relevant NORTH page.',
      suggestions: follow, rows: [], area: tool };
  }
  if (entities.length && !useContext) rows = rows.filter((row) =>
    [row.label, ...(row.terms ?? [])].some((field) => entities.some((entity) => normalize(field).includes(normalize(entity)))));
  if (/\b(last hour|today|yesterday)\b/.test(normalized)) {
    const midnight = new Date(now); midnight.setHours(0, 0, 0, 0);
    const yesterday = new Date(midnight); yesterday.setDate(yesterday.getDate() - 1);
    const from = normalized.includes('last hour') ? now - 3600000 : normalized.includes('yesterday') ? yesterday.getTime() : midnight.getTime();
    const until = normalized.includes('yesterday') && !normalized.includes('since yesterday') ? midnight.getTime() : now + 1;
    rows = rows.filter((row) => { const time = Date.parse(row.timestamp ?? ''); return time >= from && time < until; });
  }
  if (id === 'attention' || id === 'status') rows = rows.filter((row) => row.status === 'new' || row.status === 'open' || row.status === 'investigating');
  if (id === 'known-good-changes') rows = rows.filter((row) => row.id === 'changes');
  if (id === 'posture-score') rows = rows.filter((row) => row.id === 'score' || row.status === 'fail');
  if (id === 'defender-state') rows = rows.filter((row) => row.id === 'defender-realtime' || row.id === 'defender-tamper');
  if (id === 'updates-pending') rows = rows.filter((row) => row.id === 'updates');
  if (id === 'posture-fix') rows = rows.filter((row) => row.status === 'fail');
  if (id === 'new-device') rows = rows.filter((row) => row.status === 'new');
  if (id === 'blind' || id === 'fix') rows = rows.filter((row) => row.status !== 'covered' && row.status !== 'verified');
  if (id === 'sysmon') rows = rows.filter((row) => row.terms?.some((term) => term.startsWith('sysmon')));
  if (id === 'country') {
    if (!rows.some((row) => row.country)) return { text: 'No matching country attribution is in the available snapshot. Check ATLAS remote endpoints.', suggestions: follow, rows: [], area: tool };
    rows = rows.filter((row) => row.country).map((row) => ({ ...row, detail: [row.detail, row.country].filter(Boolean).join(' · ') }));
  }
  const shown = rows.slice(0, 8).map((row) => ({ ...row,
    detail: id === 'finding-score' ? row.score ?? 'This finding has no linked score details.' : id === 'next' || id === 'fix' || id === 'posture-fix' ? row.guidance || row.detail : id === 'false-positive' ? row.alternative || row.detail :
      id === 'danger' ? [row.terms?.[0], row.detail].filter(Boolean).join(' · ') : row.detail,
  }));
  return { text: shown.length ? template : 'No matching records in the available snapshot. This does not establish that nothing happened.',
    suggestions: follow, rows: shown, area: tool };
}
