export type SimpleInputs = {
  ready: boolean;
  openCases: number;
  unreviewed: number;
  severe: boolean;
  unknownDevices: number;
};

// Stronger evidence takes priority. Missing or stale telemetry never produces Good.
export function simpleStatus(inputs: SimpleInputs) {
  if (inputs.severe) return { level: 'urgent', reason: 'urgentReason' } as const;
  if (inputs.unreviewed || inputs.openCases) return { level: 'look', reason: 'findingsReason' } as const;
  if (inputs.unknownDevices) return { level: 'look', reason: 'devicesReason' } as const;
  if (!inputs.ready) return { level: 'look', reason: 'visibilityReason' } as const;
  return { level: 'good', reason: 'goodReason' } as const;
}
