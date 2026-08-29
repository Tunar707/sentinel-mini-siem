import { LogEntry } from '../types/log';

type IncidentPanelProps = {
  incidents: LogEntry[];
  selectedIncidentId: string | null;
  onSelect: (incidentId: string) => void;
};

function IncidentPanel({ incidents, selectedIncidentId, onSelect }: IncidentPanelProps) {
  return (
    <section style={{ marginTop: '2rem', background: 'rgba(15, 23, 42, 0.9)', border: '1px solid rgba(148, 163, 184, 0.2)', borderRadius: '18px', padding: '1.25rem' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '1rem', flexWrap: 'wrap', marginBottom: '1rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
          <h2 style={{ margin: 0 }}>Incidents</h2>
          <span style={{
            display: 'inline-flex',
            alignItems: 'center',
            justifyContent: 'center',
            minWidth: '2rem',
            height: '2rem',
            padding: '0 0.5rem',
            borderRadius: '9999px',
            background: '#dc2626',
            color: '#fef2f2',
            fontWeight: 700
          }}>{incidents.length}</span>
        </div>
      </div>

      {incidents.length === 0 ? (
        <p style={{ color: '#cbd5e1', margin: 0 }}>No critical incidents.</p>
      ) : (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '0.75rem' }}>
          {incidents.map((incident) => (
            <button
              key={incident.id}
              type="button"
              onClick={() => onSelect(incident.id)}
              style={{
                textAlign: 'left',
                background: selectedIncidentId === incident.id ? 'rgba(239, 68, 68, 0.18)' : 'rgba(15, 23, 42, 0.8)',
                border: '1px solid rgba(239, 68, 68, 0.5)',
                borderRadius: '12px',
                padding: '0.9rem',
                color: '#f8fafc',
                cursor: 'pointer'
              }}
            >
              <div style={{ fontWeight: 700, marginBottom: '0.4rem' }}>{incident.eventType}</div>
              <div style={{ color: '#cbd5e1', fontSize: '0.9rem', marginBottom: '0.2rem' }}>{incident.source}</div>
              <div style={{ color: '#fca5a5', fontSize: '0.8rem', marginBottom: '0.4rem' }}>{new Date(incident.timestamp).toLocaleString()}</div>
              <div style={{ color: '#e2e8f0', fontSize: '0.85rem', lineHeight: 1.4 }}>{incident.message}</div>
            </button>
          ))}
        </div>
      )}
    </section>
  );
}

export default IncidentPanel;
