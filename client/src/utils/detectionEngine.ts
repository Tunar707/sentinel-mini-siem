import type { LogEntry } from '../types/log';
import type { DetectionRule, RuleMatch } from '../types/rule';

export function evaluateDetectionRules(event: LogEntry, history: LogEntry[], rules: DetectionRule[]): RuleMatch[] {
  const eventTime = new Date(event.timestamp).getTime();

  return rules
    .filter((rule) => rule.enabled)
    .filter((rule) => rule.source === 'Any Source' || rule.source === event.source)
    .filter((rule) => rule.eventType === event.eventType)
    .map((rule) => {
      const windowStart = eventTime - rule.timeWindowMinutes * 60 * 1000;
      const eventCount = history.filter((candidate) => {
        const candidateTime = new Date(candidate.timestamp).getTime();
        return candidate.source === event.source
          && candidate.eventType === event.eventType
          && candidateTime >= windowStart
          && candidateTime <= eventTime;
      }).length + 1;

      return { rule, eventCount };
    })
    .filter(({ rule, eventCount }) => eventCount >= rule.thresholdCount)
    .map(({ rule, eventCount }) => ({
      rule,
      eventCount,
      triggerTimestamp: event.timestamp
    }));
}
