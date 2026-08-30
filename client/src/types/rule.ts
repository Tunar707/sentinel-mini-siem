import type { Severity } from './log';

export type DetectionRule = {
  id: string;
  name: string;
  source: string;
  eventType: string;
  severity: Severity;
  mitreTechnique: string;
  thresholdCount: number;
  timeWindowMinutes: number;
  enabled: boolean;
  createdAt: string;
  hitCount: number;
  lastTriggered?: string;
};

export type RuleMatch = {
  rule: DetectionRule;
  triggerTimestamp: string;
  eventCount: number;
};
