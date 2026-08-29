export type MitreMapping = {
  id: string;
  tactic: string;
  color: string;
};

const MITRE_MAP: Record<string, MitreMapping> = {
  'Failed Login': { id: 'T1110', tactic: 'Credential Access', color: '#f43f5e' },
  BRUTE_FORCE_DETECTED: { id: 'T1110', tactic: 'Credential Access', color: '#f43f5e' },
  'Malware Detection': { id: 'T1204', tactic: 'Execution', color: '#a78bfa' },
  'Port Scan': { id: 'T1046', tactic: 'Discovery', color: '#38bdf8' },
  'Critical Alert': { id: 'T1486', tactic: 'Impact', color: '#f97316' }
};

export const getMitreMapping = (eventType: string): MitreMapping => {
  return MITRE_MAP[eventType] ?? { id: 'N/A', tactic: 'Unmapped', color: '#475569' };
};
