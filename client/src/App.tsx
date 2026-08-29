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

const severityColors: Record<Severity, { background: string; color: string }> = {
  LOW: { background: '#e5e7eb', color: '#111827' },
  MEDIUM: { background: '#dbeafe', color: '#1d4ed8' },
  HIGH: { background: '#fed7aa', color: '#c2410c' },
  CRITICAL: { background: '#fecaca', color: '#b91c1c' }
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
    <div style={{ padding: '2rem', maxWidth: '1400px', margin: '0 auto' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '1rem', flexWrap: 'wrap' }}>
        <div>
          <h1 style={{ marginBottom: '0.5rem' }}>{APP_NAME}</h1>
          <p style={{ margin: 0 }}>Logged in as: {auth.user.email} (Role: {auth.user.role})</p>
        </div>
        <button onClick={() => {
          localStorage.removeItem('token');
          setAuth(null);
          setBackendHealth(null);
          setLogs([]);
          setError('');
        }}>Logout</button>
      </div>

      <section style={{ marginTop: '2rem' }}>
        <h2>System Status</h2>
        {error && <p style={{ color: 'red' }}>Error: {error}</p>}
        <p>Frontend: OK</p>
        <p>Backend: {backendHealth ? backendHealth.status : 'Loading...'}</p>
        {backendHealth?.user && (
          <pre>{JSON.stringify(backendHealth.user, null, 2)}</pre>
        )}
      </section>

      <section style={{ marginTop: '2rem' }}>
        <h2>Log Generator</h2>
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.75rem', marginBottom: '1.5rem' }}>
          {Object.keys(logTemplates).map((name) => (
            <button
              key={name}
              type="button"
              onClick={() => generateLog(name as keyof typeof logTemplates)}
              style={{
                padding: '0.7rem 1rem',
                borderRadius: '8px',
                border: '1px solid #d1d5db',
                background: '#f9fafb',
                cursor: 'pointer',
                fontWeight: 600
              }}
            >
              {name}
            </button>
          ))}
        </div>
      </section>

      <section style={{ marginTop: '2rem' }}>
        <h2>Analyst Dashboard</h2>

        {logsLoading ? (
          <p>Loading logs...</p>
        ) : logs.length === 0 ? (
          <p>No logs available.</p>
        ) : (
          <div style={{ overflowX: 'auto', border: '1px solid #d1d5db', borderRadius: '8px' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', minWidth: '900px' }}>
              <thead style={{ background: '#f3f4f6' }}>
                <tr>
                  <th style={{ textAlign: 'left', padding: '0.75rem', borderBottom: '1px solid #d1d5db' }}>Timestamp</th>
                  <th style={{ textAlign: 'left', padding: '0.75rem', borderBottom: '1px solid #d1d5db' }}>Source</th>
                  <th style={{ textAlign: 'left', padding: '0.75rem', borderBottom: '1px solid #d1d5db' }}>Event Type</th>
                  <th style={{ textAlign: 'left', padding: '0.75rem', borderBottom: '1px solid #d1d5db' }}>Severity</th>
                  <th style={{ textAlign: 'left', padding: '0.75rem', borderBottom: '1px solid #d1d5db' }}>Message</th>
                </tr>
              </thead>
              <tbody>
                {logs.map((log) => (
                  <tr key={log.id}>
                    <td style={{ padding: '0.75rem', borderBottom: '1px solid #e5e7eb', verticalAlign: 'top' }}>
                      {new Date(log.timestamp).toLocaleString()}
                    </td>
                    <td style={{ padding: '0.75rem', borderBottom: '1px solid #e5e7eb', verticalAlign: 'top' }}>{log.source}</td>
                    <td style={{ padding: '0.75rem', borderBottom: '1px solid #e5e7eb', verticalAlign: 'top' }}>{log.eventType}</td>
                    <td style={{ padding: '0.75rem', borderBottom: '1px solid #e5e7eb', verticalAlign: 'top' }}>
                      <span
                        style={{
                          display: 'inline-block',
                          padding: '0.25rem 0.5rem',
                          borderRadius: '9999px',
                          fontWeight: 600,
                          fontSize: '0.8rem',
                          background: severityColors[log.severity].background,
                          color: severityColors[log.severity].color
                        }}
                      >
                        {log.severity}
                      </span>
                    </td>
                    <td style={{ padding: '0.75rem', borderBottom: '1px solid #e5e7eb', verticalAlign: 'top', maxWidth: '360px', whiteSpace: 'pre-wrap' }}>
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
  );
}

export default App;
