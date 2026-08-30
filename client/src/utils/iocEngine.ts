import type { LogEntry } from '../types/log';
import type { IOC, IOCMatch } from '../types/ioc';

export function evaluateIOCs(event: LogEntry, iocs: IOC[]): IOCMatch[] {
  const searchableEvent = `${event.source} ${event.message}`.toLowerCase();

  return iocs
    .filter((ioc) => ioc.enabled)
    .filter((ioc) => searchableEvent.includes(ioc.value.trim().toLowerCase()))
    .map((ioc) => ({
      ioc,
      triggerTimestamp: event.timestamp
    }));
}
