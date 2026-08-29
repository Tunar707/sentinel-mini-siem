import { useEffect, useState } from 'react';
import { APP_NAME, HealthStatus, AuthResponse } from '@sentinel/shared';
import Login from './Login';

type Severity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

type LogEntry = {
  id: string;
  timestamp: string;
  source: string;
  eventType: string;
  severity: Severity;
  message: string;
};

type LogTemplate = {
  source: string;
  eventType: string;
  severity: Severity;
  message: string;
};

type SeverityFilter = 'ALL' | Severity;

const severityColors: Record<Severity, { background: string; color: string }> = {
  LOW: { background: '#374151', color: '#f3f4f6' },
  MEDIUM: { background: '#1d4ed8', color: '#eff6ff' },
  HIGH: { background: '#f59e0b', color: '#111827' },
  CRITICAL: { background: '#dc2626', color: '#fef2f2' }
};

const logTemplates: Record<string, LogTemplate> = {
  'Failed Login': {
    source: 'Auth Gateway',
    eventType: 'Failed Login',
    severity: 'MEDIUM',
    message: 'User admin attempted login from 192.168.1.21 with invalid password after 3 retries.'
  },
  'Malware Detection': {
    source: 'Endpoint Agent',
    eventType: 'Malware Detection',
    severity: 'HIGH',
    message: 'Suspicious PowerShell process matched ransomware family indicators on workstation WS-17.'
  },
  'Port Scan': {
    source: 'Firewall',
    eventType: 'Port Scan',
    severity: 'HIGH',
    message: 'External host 45.76.102.18 scanned 150 TCP ports across DMZ segment in 12 seconds.'
  },
  'Brute Force': {
    source: 'VPN',
    eventType: 'Brute Force',
    severity: 'CRITICAL',
    message: 'Repeated SSH login attempts against root account exceeded threshold from 203.0.113.9.'
  },
  'Critical Alert': {
    source: 'SIEM Correlation',
    eventType: 'Critical Alert',
    severity: 'CRITICAL',
    message: 'Alert correlation triggered: privilege escalation + suspicious outbound beaconing on finance node.'
  }
};

function App() {
  const [auth, setAuth] = useState<AuthResponse | null>(null);
  const [backendHealth, setBackendHealth] = useState<HealthStatus | null>(null);
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [logsLoading, setLogsLoading] = useState(false);
  const [error, setError] = useState('');
  const [search, setSearch] = useState('');
  const [severityFilter, setSeverityFilter] = useState<SeverityFilter>('ALL');

  const fetchHealth = async (token: string) => {
    try {
      const res = await fetch('/api/health', {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (!res.ok) throw new Error('Unauthorized or fetch failed');
      const data = await res.json();
      setBackendHealth(data);
    } catch (err: any) {
      setError(err.message);
    }
  };

  const fetchLogs = async (token: string) => {
    setLogsLoading(true);
    try {
      const res = await fetch('/api/logs', {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (!res.ok) throw new Error('Unable to fetch logs');
      const data = await res.json();
      setLogs(data as LogEntry[]);
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLogsLoading(false);
    }
  };

  const generateLog = async (templateName: keyof typeof logTemplates) => {
    if (!auth) return;

    const template = logTemplates[templateName];
    try {
      const res = await fetch('/api/logs', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${auth.token}`
        },
        body: JSON.stringify(template)
      });

      if (!res.ok) {
        const body = await res.json();
        throw new Error(body.error || 'Failed to generate log');
      }

      await fetchLogs(auth.token);
    } catch (err: any) {
      setError(err.message);
    }
  };

  const filteredLogs = logs.filter((log) => {
    const matchesSearch = !search || [log.source, log.eventType, log.message].some((value) =>
      value.toLowerCase().includes(search.toLowerCase())
    );

    const matchesSeverity = severityFilter === 'ALL' || log.severity === severityFilter;

    return matchesSearch && matchesSeverity;
  });

  const totalEvents = logs.length;
  const criticalCount = logs.filter((log) => log.severity === 'CRITICAL').length;
  const highCount = logs.filter((log) => log.severity === 'HIGH').length;
  const todayCount = logs.filter((log) => {
    const logDate = new Date(log.timestamp);
    const today = new Date();
    return logDate.toDateString() === today.toDateString();
  }).length;

  useEffect(() => {
    const token = localStorage.getItem('token');
    if (token) {
      fetchHealth(token);
      fetchLogs(token);
      setAuth({
        token,
        user: { id: 'cached', email: 'cached@local', role: 'analyst' }
      });
    }
  }, []);

  if (!auth) {
    return <Login onLogin={(data) => {
      setAuth(data);
      fetchHealth(data.token);
      fetchLogs(data.token);
    }} />;
  }

  return (
    <div style={{
      minHeight: '100vh',
      background: 'radial-gradient(circle at top, #0f172a 0%, #020817 55%, #020617 100%)',
      color: '#e2e8f0',
      padding: '2rem 1rem 3rem'
    }}>
      <div style={{ maxWidth: '1400px', margin: '0 auto' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '1rem', flexWrap: 'wrap', marginBottom: '2rem' }}>
          <div>
            <p style={{ margin: 0, color: '#67e8f9', textTransform: 'uppercase', letterSpacing: '0.12em', fontSize: '0.75rem' }}>SOC Console</p>
            <h1 style={{ margin: '0.25rem 0 0', fontSize: '2rem' }}>{APP_NAME}</h1>
            <p style={{ margin: '0.5rem 0 0', color: '#94a3b8' }}>Logged in as: {auth.user.email} (Role: {auth.user.role})</p>
            <p style={{ margin: '0.5rem 0 0', color: '#67e8f9' }}>
              Backend status: {backendHealth ? backendHealth.status : 'Loading...'}
            </p>
          </div>
          <button onClick={() => {
            localStorage.removeItem('token');
            setAuth(null);
            setBackendHealth(null);
            setLogs([]);
            setError('');
            setSearch('');
            setSeverityFilter('ALL');
          }} style={{
            background: '#1e293b',
            color: '#f8fafc',
            border: '1px solid #334155',
            borderRadius: '10px',
            padding: '0.75rem 1rem',
            cursor: 'pointer'
          }}>Logout</button>
        </div>

        <section style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '1rem', marginBottom: '2rem' }}>
          {[
            { label: 'Total Events', value: totalEvents, accent: '#38bdf8' },
            { label: 'Critical', value: criticalCount, accent: '#ef4444' },
            { label: 'High', value: highCount, accent: '#f59e0b' },
            { label: 'Events Today', value: todayCount, accent: '#22c55e' }
          ].map((card) => (
            <div key={card.label} style={{
              background: 'rgba(15, 23, 42, 0.9)',
              border: '1px solid rgba(148, 163, 184, 0.2)',
              borderRadius: '16px',
              padding: '1rem 1.25rem',
              boxShadow: '0 8px 20px rgba(15, 23, 42, 0.35)'
            }}>
              <div style={{ color: '#94a3b8', fontSize: '0.8rem', textTransform: 'uppercase', letterSpacing: '0.08em' }}>{card.label}</div>
              <div style={{ marginTop: '0.5rem', fontSize: '2rem', fontWeight: 700, color: card.accent }}>{card.value}</div>
            </div>
          ))}
        </section>

        <section style={{ marginTop: '2rem' }}>
          <h2 style={{ marginBottom: '1rem' }}>Log Generator</h2>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.75rem', marginBottom: '1.5rem' }}>
            {Object.keys(logTemplates).map((name) => (
              <button
                key={name}
                type="button"
                onClick={() => generateLog(name as keyof typeof logTemplates)}
                style={{
                  padding: '0.7rem 1rem',
                  borderRadius: '10px',
                  border: '1px solid #334155',
                  background: 'linear-gradient(135deg, #1e293b, #0f172a)',
                  color: '#f8fafc',
                  cursor: 'pointer',
                  fontWeight: 600
                }}
              >
                {name}
              </button>
            ))}
          </div>
        </section>

        <section style={{ marginTop: '2rem', background: 'rgba(15, 23, 42, 0.9)', border: '1px solid rgba(148, 163, 184, 0.2)', borderRadius: '18px', padding: '1.25rem' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '1rem', flexWrap: 'wrap', marginBottom: '1rem' }}>
            <h2 style={{ margin: 0 }}>Analyst Dashboard</h2>
            <div style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap', alignItems: 'center' }}>
              <input
                type="text"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder="Search source, event type, or message"
                style={{
                  minWidth: '260px',
                  padding: '0.7rem 0.9rem',
                  borderRadius: '10px',
                  border: '1px solid #334155',
                  background: '#0f172a',
                  color: '#e2e8f0'
                }}
              />
              <select
                value={severityFilter}
                onChange={(e) => setSeverityFilter(e.target.value as SeverityFilter)}
                style={{
                  padding: '0.7rem 0.9rem',
                  borderRadius: '10px',
                  border: '1px solid #334155',
                  background: '#0f172a',
                  color: '#e2e8f0'
                }}
              >
                {['ALL', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'].map((severity) => (
                  <option key={severity} value={severity}>{severity}</option>
                ))}
              </select>
            </div>
          </div>

          {error && <p style={{ color: '#fca5a5', marginBottom: '1rem' }}>Error: {error}</p>}

          {logsLoading ? (
            <p style={{ color: '#cbd5e1' }}>Loading logs...</p>
          ) : filteredLogs.length === 0 ? (
            <p style={{ color: '#cbd5e1' }}>No logs available.</p>
          ) : (
            <div style={{ overflowX: 'auto', borderRadius: '12px', border: '1px solid rgba(148, 163, 184, 0.2)' }}>
              <table style={{ width: '100%', borderCollapse: 'collapse', minWidth: '900px' }}>
                <thead style={{ background: '#111827' }}>
                  <tr>
                    <th style={{ textAlign: 'left', padding: '0.85rem 1rem', borderBottom: '1px solid rgba(148, 163, 184, 0.2)' }}>Timestamp</th>
                    <th style={{ textAlign: 'left', padding: '0.85rem 1rem', borderBottom: '1px solid rgba(148, 163, 184, 0.2)' }}>Source</th>
                    <th style={{ textAlign: 'left', padding: '0.85rem 1rem', borderBottom: '1px solid rgba(148, 163, 184, 0.2)' }}>Event Type</th>
                    <th style={{ textAlign: 'left', padding: '0.85rem 1rem', borderBottom: '1px solid rgba(148, 163, 184, 0.2)' }}>Severity</th>
                    <th style={{ textAlign: 'left', padding: '0.85rem 1rem', borderBottom: '1px solid rgba(148, 163, 184, 0.2)' }}>Message</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredLogs.map((log) => (
                    <tr key={log.id} style={{ background: 'rgba(15, 23, 42, 0.7)' }}>
                      <td style={{ padding: '0.85rem 1rem', borderBottom: '1px solid rgba(148, 163, 184, 0.15)', verticalAlign: 'top', color: '#cbd5e1' }}>
                        {new Date(log.timestamp).toLocaleString()}
                      </td>
                      <td style={{ padding: '0.85rem 1rem', borderBottom: '1px solid rgba(148, 163, 184, 0.15)', verticalAlign: 'top', color: '#e2e8f0' }}>{log.source}</td>
                      <td style={{ padding: '0.85rem 1rem', borderBottom: '1px solid rgba(148, 163, 184, 0.15)', verticalAlign: 'top', color: '#e2e8f0' }}>{log.eventType}</td>
                      <td style={{ padding: '0.85rem 1rem', borderBottom: '1px solid rgba(148, 163, 184, 0.15)', verticalAlign: 'top' }}>
                        <span
                          style={{
                            display: 'inline-block',
                            padding: '0.3rem 0.6rem',
                            borderRadius: '9999px',
                            fontWeight: 700,
                            fontSize: '0.75rem',
                            background: severityColors[log.severity].background,
                            color: severityColors[log.severity].color
                          }}
                        >
                          {log.severity}
                        </span>
                      </td>
                      <td style={{ padding: '0.85rem 1rem', borderBottom: '1px solid rgba(148, 163, 184, 0.15)', verticalAlign: 'top', maxWidth: '420px', whiteSpace: 'pre-wrap', color: '#dbeafe' }}>
                        {log.message}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>
      </div>
    </div>
  );
}

export default App;
