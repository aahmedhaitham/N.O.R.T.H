type ProcessEvidence = {
  id: string; kind: number; process?: string;
  process_guid?: string; parent_guid?: string; raw: unknown;
};
type ProcessNode = {
  guid: string; parent: string; label: string; evidenceId: string; creation: boolean;
};
export type ProcessRow = ProcessNode & { depth: number; gap: string };

const record = (value: unknown): Record<string, unknown> =>
  value && typeof value === 'object' ? value as Record<string, unknown> : {};
const guid = (value: unknown) => {
  if (typeof value !== 'string') return '';
  const key = value.trim().replace(/^\{|\}$/g, '').toLowerCase();
  return /^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$/.test(key) && /[1-9a-f]/.test(key) ? key : '';
};

export function processTree(events: ProcessEvidence[]) {
  const nodes = new Map<string, ProcessNode>();
  let truncated = false;
  for (const event of events) {
    const raw = record(event.raw);
    const fields = record(record(record(raw.data).win).eventdata);
    const key = guid(event.process_guid || fields.processGuid || raw.ProcessGuid);
    if (!key) continue;
    const parent = guid(event.parent_guid || fields.parentProcessGuid || raw.ParentProcessGuid);
    const known = nodes.get(key);
    if (!known && nodes.size >= 500) { truncated = true; continue; }
    const creation = event.kind === 1;
    const preferred = !known || (creation && !known.creation);
    if (!preferred) {
      if (!known.parent && parent) known.parent = parent;
      continue;
    }
    const image = event.process || fields.image || raw.Image;
    const label = typeof image === 'string' ? image.split(/[\\/]/).at(-1) : undefined;
    nodes.set(key, { guid: key, parent: parent || known?.parent || '', label: label || known?.label || 'Unknown process',
      evidenceId: event.id, creation });
  }

  const children = new Map<string, ProcessNode[]>();
  const roots: { node: ProcessNode; gap: string }[] = [];
  for (const node of nodes.values()) {
    if (node.parent && node.parent !== node.guid && nodes.has(node.parent)) {
      const siblings = children.get(node.parent) ?? [];
      siblings.push(node);
      children.set(node.parent, siblings);
    } else {
      roots.push({ node, gap: node.parent === node.guid ? 'Invalid parent reference' :
        node.parent ? 'Parent outside case evidence' : '' });
    }
  }
  const rows: ProcessRow[] = [];
  const visited = new Set<string>();
  function append(root: ProcessNode, gap: string) {
    const pending: ProcessRow[] = [{ ...root, depth: 0, gap }];
    while (pending.length) {
      const next = pending.pop()!;
      if (visited.has(next.guid)) continue;
      visited.add(next.guid);
      rows.push(next);
      for (const child of [...(children.get(next.guid) ?? [])].reverse()) {
        pending.push({ ...child, depth: next.depth + 1, gap: '' });
      }
    }
  }
  for (const { node, gap } of roots) append(node, gap);
  for (const node of nodes.values()) if (!visited.has(node.guid)) append(node, 'Parent chain could not be resolved');
  return { rows, truncated };
}
