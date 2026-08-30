import { useEffect, useState } from 'react';
import { APP_NAME, HealthStatus, AuthResponse } from '@sentinel/shared';
import Login from './Login';
import KPIGrid from './components/KPIGrid';
import IncidentPanel from './components/IncidentPanel';
import LogGenerator from './components/LogGenerator';
import EventTable from './components/EventTable';
import SearchBar from './components/SearchBar';
import { LogEntry, LogTemplate, SeverityFilter } from './types/log';

type PageName = 'Dashboard' | 'Incidents' | 'Events' | 'Threat Intel' | 'Analyst';

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
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [activePage, setActivePage] = useState<PageName>('Dashboard');

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

  const filterLogs = (items: LogEntry[]) => items.filter((log) => {
    const matchesSearch = !search || [log.source, log.eventType, log.message].some((value) =>
      value.toLowerCase().includes(search.toLowerCase())
    );

    const matchesSeverity = severityFilter === 'ALL' || log.severity === severityFilter;
    return matchesSearch && matchesSeverity;
  });

  const incidentLogs = logs.filter((log) => log.severity === 'CRITICAL');
  const filteredLogs = filterLogs(logs);
  const filteredCriticalLogs = filterLogs(incidentLogs);

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

  useEffect(() => {
    if (!auth) return;

    const source = new EventSource(`/api/logs/stream?token=${encodeURIComponent(auth.token)}`);

    const handleLogEvent = (event: MessageEvent<string>) => {
      try {
        const incoming = JSON.parse(event.data) as LogEntry;
        setLogs((current) => {
          const exists = current.some((log) => log.id === incoming.id);
          if (exists) return current;
          return [incoming, ...current];
        });
      } catch {
        // ignore heartbeat / metadata payloads
      }
    };

    source.addEventListener('log', handleLogEvent);
    source.onmessage = handleLogEvent;

    source.onerror = () => {
      setError('Live log stream disconnected. Refresh to reconnect.');
    };

    return () => source.close();
  }, [auth?.token]);

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

  const sidebarItems: { label: PageName; icon: string }[] = [
    { label: 'Dashboard', icon: '▣' },
    { label: 'Incidents', icon: '⚑' },
    { label: 'Events', icon: '◫' },
    { label: 'Threat Intel', icon: '✦' },
    { label: 'Analyst', icon: '◌' }
  ];

  const renderPageContent = () => {
    if (activePage === 'Incidents') {
      return (
        <section style={{ display: 'flex', flexDirection: 'column', gap: '1.2rem' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '1rem', flexWrap: 'wrap', padding: '0.1rem 0' }}>
            <h2 style={{ margin: 0, fontSize: '1.5rem' }}>Critical Incidents</h2>
            <div style={{ display: 'flex', gap: '0.75rem', alignItems: 'center', flexWrap: 'wrap' }}>
              <SearchBar value={search} onChange={setSearch} />
              <select
                value={severityFilter}
                onChange={(e) => setSeverityFilter(e.target.value as SeverityFilter)}
                style={{
                  padding: '0.7rem 0.9rem',
                  borderRadius: '10px',
                  border: '1px solid rgba(148, 163, 184, 0.2)',
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

          <IncidentPanel
            incidents={filteredCriticalLogs}
            selectedIncidentId={selectedIncidentId}
            onSelect={handleIncidentSelect}
          />

          {error && <p style={{ color: '#fca5a5', marginBottom: '1rem' }}>Error: {error}</p>}

          {logsLoading ? (
            <p style={{ color: '#cbd5e1' }}>Loading incidents...</p>
          ) : filteredCriticalLogs.length === 0 ? (
            <p style={{ color: '#cbd5e1' }}>No critical incidents match the current filters.</p>
          ) : (
            <div style={{ background: 'rgba(15, 23, 42, 0.38)', border: '1px solid rgba(148, 163, 184, 0.2)', borderRadius: '18px', padding: '1.25rem' }}>
              <EventTable logs={filteredCriticalLogs} selectedIncidentId={selectedIncidentId} />
            </div>
          )}
        </section>
      );
    }

    if (activePage === 'Events') {
      return (
        <section style={{ background: 'rgba(15, 23, 42, 0.38)', border: '1px solid rgba(148, 163, 184, 0.2)', borderRadius: '18px', padding: '1.25rem' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '1rem', flexWrap: 'wrap', marginBottom: '1rem' }}>
            <h2 style={{ margin: 0, fontSize: '1.5rem' }}>Events</h2>
            <div style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap', alignItems: 'center' }}>
              <SearchBar value={search} onChange={setSearch} />
              <select
                value={severityFilter}
                onChange={(e) => setSeverityFilter(e.target.value as SeverityFilter)}
                style={{
                  padding: '0.7rem 0.9rem',
                  borderRadius: '10px',
                  border: '1px solid rgba(148, 163, 184, 0.2)',
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
            <p style={{ color: '#cbd5e1' }}>Loading events...</p>
          ) : filteredLogs.length === 0 ? (
            <p style={{ color: '#cbd5e1' }}>No events match the current filters.</p>
          ) : (
            <EventTable logs={filteredLogs} selectedIncidentId={selectedIncidentId} />
          )}
        </section>
      );
    }

    if (activePage === 'Threat Intel') {
      return (
        <section style={{ display: 'grid', gap: '1.2rem' }}>
          <div style={{ background: 'rgba(15, 23, 42, 0.38)', border: '1px solid rgba(148, 163, 184, 0.2)', borderRadius: '18px', padding: '1.5rem' }}>
            <h2 style={{ margin: '0 0 0.75rem', fontSize: '1.5rem' }}>Threat Intelligence</h2>
            <p style={{ margin: 0, color: '#cbd5e1', lineHeight: 1.7 }}>
              MITRE ATT&CK coverage for the current monitored environment, with emphasis on credential access,
              execution, discovery, and impact activity.
            </p>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(210px, 1fr))', gap: '1rem' }}>
            {[
              { label: 'Credential Access', value: 'T1110', detail: 'Brute Force' },
              { label: 'Execution', value: 'T1204', detail: 'User Execution' },
              { label: 'Discovery', value: 'T1046', detail: 'Network Service Discovery' },
              { label: 'Impact', value: 'T1486', detail: 'Data Encrypted for Impact' }
            ].map((item) => (
              <div key={item.label} style={{ background: 'rgba(15, 23, 42, 0.38)', border: '1px solid rgba(148, 163, 184, 0.2)', borderRadius: '16px', padding: '1rem' }}>
                <div style={{ color: '#93c5fd', fontSize: '0.75rem', letterSpacing: '0.08em', textTransform: 'uppercase' }}>{item.label}</div>
                <div style={{ marginTop: '0.7rem', fontSize: '1.8rem', fontWeight: 800, color: '#e2e8f0' }}>{item.value}</div>
                <div style={{ marginTop: '0.35rem', color: '#cbd5e1' }}>{item.detail}</div>
              </div>
            ))}
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: '1rem' }}>
            <div style={{ background: 'rgba(15, 23, 42, 0.38)', border: '1px solid rgba(148, 163, 184, 0.2)', borderRadius: '16px', padding: '1rem' }}>
              <h3 style={{ marginTop: 0, marginBottom: '0.75rem' }}>IOC Summary</h3>
              <ul style={{ margin: 0, paddingLeft: '1.2rem', color: '#dbeafe', lineHeight: 1.8 }}>
                <li>192.168.1.21</li>
                <li>203.0.113.9</li>
                <li>45.76.102.18</li>
                <li>WS-17</li>
              </ul>
            </div>
            <div style={{ background: 'rgba(15, 23, 42, 0.38)', border: '1px solid rgba(148, 163, 184, 0.2)', borderRadius: '16px', padding: '1rem' }}>
              <h3 style={{ marginTop: 0, marginBottom: '0.75rem' }}>Recent Tactics</h3>
              <ul style={{ margin: 0, paddingLeft: '1.2rem', color: '#dbeafe', lineHeight: 1.8 }}>
                <li>Credential Access</li>
                <li>Execution</li>
                <li>Discovery</li>
                <li>Impact</li>
              </ul>
            </div>
          </div>
        </section>
      );
    }

    if (activePage === 'Analyst') {
      return (
        <section style={{ display: 'grid', gap: '1.2rem' }}>
          <div style={{ background: 'rgba(15, 23, 42, 0.38)', border: '1px solid rgba(148, 163, 184, 0.2)', borderRadius: '18px', padding: '1.5rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '1rem', flexWrap: 'wrap' }}>
              <div style={{ width: '56px', height: '56px', borderRadius: '50%', display: 'flex', alignItems: 'center', justifyContent: 'center', background: 'linear-gradient(135deg, #38bdf8, #2563eb)', color: '#eff6ff', fontWeight: 800 }}>A</div>
              <div>
                <div style={{ color: '#93c5fd', fontSize: '0.75rem', letterSpacing: '0.1em', textTransform: 'uppercase' }}>Analyst</div>
                <h2 style={{ margin: '0.2rem 0 0', fontSize: '1.7rem' }}>Alicia Morgan</h2>
              </div>
            </div>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '1rem' }}>
            {[
              { label: 'Shift', value: 'Monitoring' },
              { label: 'Queue', value: '12 alerts' },
              { label: 'Escalations', value: '3 pending' },
              { label: 'Threat Score', value: '91/100' }
            ].map((stat) => (
              <div key={stat.label} style={{ background: 'rgba(15, 23, 42, 0.38)', border: '1px solid rgba(148, 163, 184, 0.2)', borderRadius: '16px', padding: '1rem' }}>
                <div style={{ color: '#93c5fd', fontSize: '0.72rem', letterSpacing: '0.08em', textTransform: 'uppercase' }}>{stat.label}</div>
                <div style={{ marginTop: '0.7rem', fontSize: '1.6rem', fontWeight: 800 }}>{stat.value}</div>
              </div>
            ))}
          </div>

          <div style={{ background: 'rgba(15, 23, 42, 0.38)', border: '1px solid rgba(148, 163, 184, 0.2)', borderRadius: '18px', padding: '1.25rem' }}>
            <h3 style={{ marginTop: 0 }}>Recent Activity</h3>
            <ul style={{ margin: 0, paddingLeft: '1.2rem', color: '#dbeafe', lineHeight: 2 }}>
              <li>Reviewed 18 new events from Endpoint Agent</li>
              <li>Validated 2 suspicious authentication events</li>
              <li>Escalated a ransomware precursor from finance subnet</li>
              <li>Marked one packet capture for threat-hunting follow-up</li>
            </ul>
          </div>
        </section>
      );
    }

    return (
      <div style={{ display: 'flex', flexDirection: 'column', gap: '1.2rem' }}>
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

        <section style={{ background: 'rgba(15, 23, 42, 0.38)', border: '1px solid rgba(148, 163, 184, 0.2)', borderRadius: '18px', padding: '1.25rem' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '1rem', flexWrap: 'wrap', marginBottom: '1rem' }}>
            <h2 style={{ margin: 0, fontSize: '1.2rem' }}>Analyst Dashboard</h2>
            <div style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap', alignItems: 'center' }}>
              <SearchBar value={search} onChange={setSearch} />
              <select
                value={severityFilter}
                onChange={(e) => setSeverityFilter(e.target.value as SeverityFilter)}
                style={{
                  padding: '0.7rem 0.9rem',
                  borderRadius: '10px',
                  border: '1px solid rgba(148, 163, 184, 0.2)',
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
    );
  };

  return (
    <div style={{
      minHeight: '100vh',
      background: 'linear-gradient(135deg, #0f172a 0%, #0b1f3a 30%, #123a72 100%)',
      color: '#e2e8f0',
      fontFamily: 'Inter, system-ui, sans-serif'
    }}>
      <div style={{ display: 'flex', minHeight: '100vh', padding: '1.25rem' }}>
        <aside style={{
          width: sidebarCollapsed ? '88px' : '248px',
          transition: 'width 0.2s ease',
          background: 'rgba(15, 23, 42, 0.42)',
          border: '1px solid rgba(148, 163, 184, 0.2)',
          backdropFilter: 'blur(18px)',
          WebkitBackdropFilter: 'blur(18px)',
          borderRadius: '22px',
          padding: '1rem 0.9rem',
          marginRight: '1rem',
          boxShadow: '0 25px 50px rgba(8, 15, 31, 0.4)',
          overflow: 'hidden'
        }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1.5rem', padding: '0 0.5rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.7rem' }}>
              <div style={{ width: '36px', height: '36px', borderRadius: '12px', background: 'linear-gradient(135deg, #38bdf8, #2563eb)', display: 'flex', alignItems: 'center', justifyContent: 'center', fontWeight: 800, color: '#eff6ff' }}>S</div>
              {!sidebarCollapsed && <div>
                <div style={{ fontSize: '0.72rem', letterSpacing: '0.14em', color: '#93c5fd', textTransform: 'uppercase' }}>Sentinel</div>
                <div style={{ fontSize: '0.8rem', fontWeight: 700 }}>{APP_NAME}</div>
              </div>}
            </div>
            <button
              type="button"
              onClick={() => setSidebarCollapsed((v) => !v)}
              style={{
                width: '32px',
                height: '32px',
                borderRadius: '10px',
                border: '1px solid rgba(148, 163, 184, 0.2)',
                background: 'rgba(15, 23, 42, 0.8)',
                color: '#e2e8f0',
                cursor: 'pointer'
              }}
            >
              {sidebarCollapsed ? '»' : '«'}
            </button>
          </div>

          <nav style={{ display: 'flex', flexDirection: 'column', gap: '0.55rem' }}>
            {sidebarItems.map((item) => {
              const isActive = activePage === item.label;
              return (
                <button
                  key={item.label}
                  type="button"
                  onClick={() => setActivePage(item.label)}
                  style={{
                    position: 'relative',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: sidebarCollapsed ? 'center' : 'flex-start',
                    gap: '0.8rem',
                    borderRadius: '12px',
                    padding: sidebarCollapsed ? '0.8rem 0.2rem' : '0.8rem 0.8rem',
                    border: '1px solid transparent',
                    background: isActive && !sidebarCollapsed ? 'linear-gradient(135deg, rgba(59,130,246,0.22), rgba(14,165,233,0.12))' : 'transparent',
                    color: isActive ? '#f8fafc' : '#cbd5e1',
                    cursor: 'pointer',
                    textAlign: 'left',
                    width: '100%',
                    boxShadow: isActive && sidebarCollapsed ? 'inset 2px 0 0 rgba(96,165,250,0.9), 0 0 18px rgba(59,130,246,0.20)' : 'none',
                    transition: 'all 0.2s ease'
                  }}
                >
                  {isActive && !sidebarCollapsed && (
                    <span style={{ position: 'absolute', left: 6, top: '20%', bottom: '20%', width: '3px', borderRadius: '9999px', background: '#60a5fa' }} />
                  )}
                  <span style={{ width: '18px', display: 'inline-flex', justifyContent: 'center', fontSize: '1rem' }}>{item.icon}</span>
                  {!sidebarCollapsed && <span style={{ fontWeight: 600, marginLeft: isActive ? '0.5rem' : '0' }}>{item.label}</span>}
                </button>
              );
            })}
          </nav>
        </aside>

        <main style={{ flex: 1, minWidth: 0 }}>
          <header style={{
            background: 'rgba(15, 23, 42, 0.38)',
            border: '1px solid rgba(148, 163, 184, 0.2)',
            borderRadius: '20px',
            padding: '1rem 1.25rem',
            backdropFilter: 'blur(18px)',
            WebkitBackdropFilter: 'blur(18px)',
            boxShadow: '0 24px 40px rgba(8, 15, 31, 0.28)',
            marginBottom: '1.2rem'
          }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '1rem', flexWrap: 'wrap' }}>
              <div>
                <div style={{ fontSize: '0.72rem', letterSpacing: '0.14em', color: '#93c5fd', textTransform: 'uppercase' }}>Operations Center</div>
                <div style={{ fontSize: '1.5rem', fontWeight: 800, marginTop: '0.2rem' }}>{activePage}</div>
              </div>

              <div style={{ display: 'flex', alignItems: 'center', gap: '0.85rem', flexWrap: 'wrap' }}>
                <div style={{
                  border: '1px solid rgba(148, 163, 184, 0.2)',
                  borderRadius: '12px',
                  background: 'rgba(15, 23, 42, 0.55)',
                  padding: '0.7rem 0.9rem',
                  color: '#cbd5e1',
                  fontSize: '0.85rem'
                }}>
                  Backend: {backendHealth ? backendHealth.status : 'Loading...'}
                </div>
                <div style={{
                  border: '1px solid rgba(148, 163, 184, 0.2)',
                  borderRadius: '12px',
                  background: 'rgba(15, 23, 42, 0.55)',
                  padding: '0.7rem 0.9rem',
                  color: '#dbeafe'
                }}>
                  {auth.user.email}
                </div>
                <button onClick={() => {
                  localStorage.removeItem('token');
                  setAuth(null);
                  setBackendHealth(null);
                  setLogs([]);
                  setError('');
                  setSearch('');
                  setSeverityFilter('ALL');
                  setActivePage('Dashboard');
                }} style={{
                  background: 'linear-gradient(135deg, #2563eb, #0ea5e9)',
                  color: '#eff6ff',
                  border: 'none',
                  borderRadius: '12px',
                  padding: '0.75rem 1rem',
                  cursor: 'pointer',
                  fontWeight: 700
                }}>Logout</button>
              </div>
            </div>
          </header>

          {renderPageContent()}
        </main>
      </div>
    </div>
  );
}

export default App;
