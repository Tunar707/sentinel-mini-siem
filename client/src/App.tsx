import { useEffect, useState } from 'react';
import { APP_NAME, HealthStatus, AuthResponse } from '@sentinel/shared';
import Login from './Login';
import KPIGrid from './components/KPIGrid';
import IncidentPanel from './components/IncidentPanel';
import LogGenerator from './components/LogGenerator';
import EventTable from './components/EventTable';
import SearchBar from './components/SearchBar';
import { LogEntry, LogTemplate, SeverityFilter } from './types/log';

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
  const [selectedIncidentId, setSelectedIncidentId] = useState<string | null>(null);

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

  const incidentLogs = logs.filter((log) => log.severity === 'CRITICAL');

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

  const handleIncidentSelect = (incidentId: string) => {
    setSelectedIncidentId(incidentId);
    const row = document.getElementById(`log-row-${incidentId}`);
    if (row) {
      row.scrollIntoView({ behavior: 'smooth', block: 'center' });
      row.style.background = 'rgba(239, 68, 68, 0.18)';
      row.style.boxShadow = 'inset 0 0 0 1px rgba(239, 68, 68, 0.7)';
      setTimeout(() => {
        row.style.background = 'rgba(15, 23, 42, 0.7)';
        row.style.boxShadow = 'none';
      }, 1800);
    }
  };

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

        <KPIGrid
          totalEvents={totalEvents}
          criticalCount={criticalCount}
          highCount={highCount}
          todayCount={todayCount}
        />

        <LogGenerator
          templates={logTemplates}
          onGenerate={(name) => generateLog(name as keyof typeof logTemplates)}
        />

        <IncidentPanel
          incidents={incidentLogs}
          selectedIncidentId={selectedIncidentId}
          onSelect={handleIncidentSelect}
        />

        <section style={{ marginTop: '2rem', background: 'rgba(15, 23, 42, 0.9)', border: '1px solid rgba(148, 163, 184, 0.2)', borderRadius: '18px', padding: '1.25rem' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '1rem', flexWrap: 'wrap', marginBottom: '1rem' }}>
            <h2 style={{ margin: 0 }}>Analyst Dashboard</h2>
            <div style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap', alignItems: 'center' }}>
              <SearchBar value={search} onChange={setSearch} />
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
            <EventTable logs={filteredLogs} selectedIncidentId={selectedIncidentId} />
          )}
        </section>
      </div>
    </div>
  );
}

export default App;
