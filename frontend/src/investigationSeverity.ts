export function investigationSeverity(evidence: { kind: number }[]) {
  if (evidence.some((event) => event.kind === 1001)) return 'medium';
  if (evidence.some((event) => event.kind === 11)) return 'low';
  return 'info';
}
