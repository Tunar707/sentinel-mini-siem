export type Severity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
export type SeverityFilter = 'ALL' | Severity;

export type LogEntry = {
  id: string;
  timestamp: string;
  source: string;
  eventType: string;
  severity: Severity;
  message: string;
};

export type LogTemplate = {
  source: string;
  eventType: string;
  severity: Severity;
  message: string;
};
