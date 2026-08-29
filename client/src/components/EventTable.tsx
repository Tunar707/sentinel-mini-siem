import { LogEntry, Severity } from '../types/log';
import { getMitreMapping } from '../utils/mitre';
import SeverityBadge from './SeverityBadge';

type EventTableProps = {
  logs: LogEntry[];
  selectedIncidentId: string | null;
};

function EventTable({ logs, selectedIncidentId }: EventTableProps) {
  return (
    <div style={{ overflowX: 'auto', borderRadius: '12px', border: '1px solid rgba(148, 163, 184, 0.2)' }}>
      <table style={{ width: '100%', borderCollapse: 'collapse', minWidth: '980px' }}>
        <thead style={{ background: '#111827' }}>
          <tr>
            <th style={{ textAlign: 'left', padding: '0.85rem 1rem', borderBottom: '1px solid rgba(148, 163, 184, 0.2)' }}>Timestamp</th>
            <th style={{ textAlign: 'left', padding: '0.85rem 1rem', borderBottom: '1px solid rgba(148, 163, 184, 0.2)' }}>Source</th>
            <th style={{ textAlign: 'left', padding: '0.85rem 1rem', borderBottom: '1px solid rgba(148, 163, 184, 0.2)' }}>Event Type</th>
            <th style={{ textAlign: 'left', padding: '0.85rem 1rem', borderBottom: '1px solid rgba(148, 163, 184, 0.2)' }}>Severity</th>
            <th style={{ textAlign: 'left', padding: '0.85rem 1rem', borderBottom: '1px solid rgba(148, 163, 184, 0.2)' }}>MITRE</th>
            <th style={{ textAlign: 'left', padding: '0.85rem 1rem', borderBottom: '1px solid rgba(148, 163, 184, 0.2)' }}>Message</th>
          </tr>
        </thead>
        <tbody>
          {logs.map((log) => {
            const mitre = getMitreMapping(log.eventType);

            return (
              <tr
                id={`log-row-${log.id}`}
                key={log.id}
                style={{
                  background: selectedIncidentId === log.id ? 'rgba(239, 68, 68, 0.18)' : 'rgba(15, 23, 42, 0.7)'
                }}
              >
                <td style={{ padding: '0.85rem 1rem', borderBottom: '1px solid rgba(148, 163, 184, 0.15)', verticalAlign: 'top', color: '#cbd5e1' }}>
                  {new Date(log.timestamp).toLocaleString()}
                </td>
                <td style={{ padding: '0.85rem 1rem', borderBottom: '1px solid rgba(148, 163, 184, 0.15)', verticalAlign: 'top', color: '#e2e8f0' }}>{log.source}</td>
                <td style={{ padding: '0.85rem 1rem', borderBottom: '1px solid rgba(148, 163, 184, 0.15)', verticalAlign: 'top', color: '#e2e8f0' }}>{log.eventType}</td>
                <td style={{ padding: '0.85rem 1rem', borderBottom: '1px solid rgba(148, 163, 184, 0.15)', verticalAlign: 'top' }}>
                  <SeverityBadge severity={log.severity as Severity} />
                </td>
                <td style={{ padding: '0.85rem 1rem', borderBottom: '1px solid rgba(148, 163, 184, 0.15)', verticalAlign: 'top' }}>
                  <span
                    style={{
                      display: 'inline-flex',
                      flexDirection: 'column',
                      alignItems: 'flex-start',
                      gap: '0.2rem',
                      padding: '0.4rem 0.55rem',
                      borderRadius: '10px',
                      background: 'rgba(15, 23, 42, 0.9)',
                      border: '1px solid rgba(148, 163, 184, 0.2)',
                      boxShadow: 'inset 0 0 0 1px rgba(15, 23, 42, 0.6)'
                    }}
                  >
                    <span
                      style={{
                        display: 'inline-block',
                        padding: '0.2rem 0.5rem',
                        borderRadius: '9999px',
                        background: mitre.color,
                        color: '#f8fafc',
                        fontWeight: 700,
                        fontSize: '0.72rem',
                        letterSpacing: '0.04em'
                      }}
                    >
                      {mitre.id}
                    </span>
                    <span style={{ color: '#cbd5e1', fontSize: '0.68rem', textTransform: 'uppercase', letterSpacing: '0.08em' }}>
                      {mitre.tactic}
                    </span>
                  </span>
                </td>
                <td style={{ padding: '0.85rem 1rem', borderBottom: '1px solid rgba(148, 163, 184, 0.15)', verticalAlign: 'top', maxWidth: '420px', whiteSpace: 'pre-wrap', color: '#dbeafe' }}>
                  {log.message}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

export default EventTable;
