import { useEffect, useRef, useState } from 'react';
import { APP_NAME, HealthStatus, AuthResponse } from '@sentinel/shared';
import Login from './Login';
import KPIGrid from './components/KPIGrid';
import IncidentPanel from './components/IncidentPanel';
import EventTable from './components/EventTable';
import SearchBar from './components/SearchBar';
import { LogEntry, Severity, SeverityFilter } from './types/log';
import { getMitreMapping } from './utils/mitre';

type PageName = 'Dashboard' | 'Incidents' | 'Cases' | 'Events' | 'Threat Intel' | 'Analyst';
type EventComposerState = {
  source: string;
  eventType: string;
  severity: Severity;
  sourceIp: string;
  asset: string;
  username: string;
  description: string;
};

type ScenarioTemplate = {
  id: string;
  category: string;
  title: string;
  source: string;
  eventType: string;
  severity: Severity;
  sourceIp: string;
  asset: string;
  username: string;
  description: string;
};

type WorkflowStatus = 'New' | 'Investigating' | 'Contained' | 'Resolved';
type AnalystName = 'Tunar' | 'Sarah' | 'Michael' | 'Emma';

type IncidentNote = {
  id: string;
  timestamp: string;
  analyst: string;
  content: string;
};

type TimelineEntry = {
  id: string;
  type: 'created' | 'status' | 'assignment' | 'note';
  timestamp: string;
  message: string;
  analyst?: string;
};

type CaseStatus = 'New' | 'Triage' | 'Investigating' | 'Contained' | 'Recovery' | 'Resolved';
type CasePriority = 'P1' | 'P2' | 'P3' | 'P4';
type CaseTimelineEntry = {
  id: string;
  type: 'created' | 'status' | 'assignment' | 'note';
  timestamp: string;
  message: string;
  analyst?: string;
};
type CaseNote = {
  id: string;
  timestamp: string;
  analyst: string;
  content: string;
};
type CaseRecord = {
  id: string;
  incidentId: string;
  incident: LogEntry;
  priority: CasePriority;
  status: CaseStatus;
  assignedAnalyst: AnalystName;
  sla: string;
  createdAt: string;
  timeline: CaseTimelineEntry[];
  notes: CaseNote[];
};

type IncidentDetail = {
  id: string;
  logId: string;
  status: WorkflowStatus;
  assignedAnalyst: AnalystName;
  createdAt: string;
  updatedAt: string;
  source?: string;
  eventType?: string;
  severity?: string;
  timestamp?: string;
  message?: string;
  notes: IncidentNote[];
  timeline: TimelineEntry[];
};

const sourceOptions = ['Auth Gateway', 'Firewall', 'Endpoint Agent', 'VPN', 'SIEM Correlation', 'Identity Provider', 'CloudTrail', 'Web Proxy', 'Kubernetes', 'Email Gateway'];
const eventTypeOptions = ['Failed Login', 'Malware Detection', 'Port Scan', 'Brute Force', 'Critical Alert', 'Privilege Escalation', 'Suspicious Process', 'Data Exfiltration', 'Lateral Movement', 'Shadow IT'];
const severityOptions: Severity[] = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
const workflowStatuses: WorkflowStatus[] = ['New', 'Investigating', 'Contained', 'Resolved'];
const caseStatuses: CaseStatus[] = ['New', 'Triage', 'Investigating', 'Contained', 'Recovery', 'Resolved'];
const casePriorities: CasePriority[] = ['P1', 'P2', 'P3', 'P4'];
const caseSlaOptions = ['4 hours', '8 hours', '24 hours', '72 hours'];
const demoAnalysts: AnalystName[] = ['Tunar', 'Sarah', 'Michael', 'Emma'];
const ipv4Regex = /^((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.|$)){4}$/;
const commonSourceOptions = [...sourceOptions];

const SOC_TEMPLATE_LIBRARY: ScenarioTemplate[] = [
  { id: 'auth-1', category: 'Identity', title: 'Repeated MFA Fatigue', source: 'Identity Provider', eventType: 'Failed Login', severity: 'HIGH', sourceIp: '10.10.44.18', asset: 'SSO Portal', username: 'j.smith', description: 'Multiple push approval requests are being generated against a user account from a foreign IP and the responses are being denied.' },
  { id: 'auth-2', category: 'Identity', title: 'Service Account Lockout', source: 'Auth Gateway', eventType: 'Failed Login', severity: 'MEDIUM', sourceIp: '192.168.33.22', asset: 'Identity Broker', username: 'svc_backup', description: 'Service account authentication is failing repeatedly due to stale cached credentials after a recent password rotation.' },
  { id: 'auth-3', category: 'Identity', title: 'Impossible Travel', source: 'Auth Gateway', eventType: 'Critical Alert', severity: 'CRITICAL', sourceIp: '203.0.113.41', asset: 'VPN Gateway', username: 'a.morgan', description: 'User login is detected from two distant geolocations within a short timeframe, suggesting possible credential theft.' },
  { id: 'endpoint-1', category: 'Endpoint', title: 'PowerShell Beaconing', source: 'Endpoint Agent', eventType: 'Malware Detection', severity: 'HIGH', sourceIp: '172.16.10.8', asset: 'FIN-WKS-06', username: 'm.brown', description: 'PowerShell process initiated encoded network traffic to an external domain consistent with command-and-control beaconing.' },
  { id: 'endpoint-2', category: 'Endpoint', title: 'Suspicious Script Execution', source: 'Endpoint Agent', eventType: 'Suspicious Process', severity: 'HIGH', sourceIp: '10.42.9.55', asset: 'Analyst-VM-3', username: 's.rivera', description: 'A script interpreted by rundll32 is invoking remote file download behavior and registry persistence commands.' },
  { id: 'endpoint-3', category: 'Endpoint', title: 'Ransomware Prep', source: 'Endpoint Agent', eventType: 'Malware Detection', severity: 'CRITICAL', sourceIp: '172.20.8.11', asset: 'FILE-SVR-12', username: 'svc_sql', description: 'File encryption behavior and shadow copy deletion were observed on the same host shortly after a PowerShell lateral movement sequence.' },
  { id: 'network-1', category: 'Network', title: 'SSH Brute Force', source: 'VPN', eventType: 'Brute Force', severity: 'CRITICAL', sourceIp: '198.51.100.24', asset: 'Jump Host', username: 'root', description: 'Multiple failed login attempts across the root account exceeded the threshold and originated from a single external IP.' },
  { id: 'network-2', category: 'Network', title: 'DMZ Port Sweep', source: 'Firewall', eventType: 'Port Scan', severity: 'HIGH', sourceIp: '45.76.102.18', asset: 'DMZ Segment', username: 'n/a', description: 'The perimeter firewall recorded an aggressive TCP scan across 180 ports on the DMZ segment over a brief interval.' },
  { id: 'network-3', category: 'Network', title: 'Outbound C2 Channel', source: 'Web Proxy', eventType: 'Critical Alert', severity: 'CRITICAL', sourceIp: '10.24.8.14', asset: 'Finance Laptop', username: 'd.lee', description: 'Outbound HTTP traffic to a newly registered domain used encoded payloads and was correlated with beaconing patterns.' },
  { id: 'network-4', category: 'Network', title: 'DNS Tunneling', source: 'Firewall', eventType: 'Critical Alert', severity: 'HIGH', sourceIp: '10.77.3.22', asset: 'Research Workstation', username: 'c.martin', description: 'Unusually long DNS replies and high-volume subdomain requests indicate tunneling behavior across the enterprise resolver.' },
  { id: 'identity-1', category: 'Identity', title: 'Privilege Change', source: 'Identity Provider', eventType: 'Privilege Escalation', severity: 'HIGH', sourceIp: '10.14.7.19', asset: 'Azure AD', username: 't.kelly', description: 'A user role assignment changed to include elevated permissions without a scheduled maintenance window or approval ticket.' },
  { id: 'identity-2', category: 'Identity', title: 'Token Replay', source: 'SIEM Correlation', eventType: 'Critical Alert', severity: 'CRITICAL', sourceIp: '172.20.8.5', asset: 'SAML Gateway', username: 'l.perez', description: 'An authentication token was reused from a separate device after the user had already logged out from the original client.' },
  { id: 'cloud-1', category: 'Cloud', title: 'CloudTrail Suspicious AssumeRole', source: 'CloudTrail', eventType: 'Privilege Escalation', severity: 'HIGH', sourceIp: '52.14.58.22', asset: 'AWS Prod', username: 'ops-admin', description: 'A new IAM role assumption was created for a cross-account session and used immediately to enumerate S3 buckets.' },
  { id: 'cloud-2', category: 'Cloud', title: 'Bucket Enumeration', source: 'CloudTrail', eventType: 'Data Exfiltration', severity: 'CRITICAL', sourceIp: '10.180.22.4', asset: 'S3 Storage', username: 's3-reader', description: 'Large numbers of object listing requests were issued from a non-production host and followed by a burst of outbound transfer volume.' },
  { id: 'cloud-3', category: 'Cloud', title: 'Kubernetes Secret Access', source: 'CloudTrail', eventType: 'Critical Alert', severity: 'CRITICAL', sourceIp: '10.9.13.31', asset: 'EKS Cluster', username: 'svc-kube-monitor', description: 'A pod was granted read access to Kubernetes secrets and then executed a command intended to retrieve credentials from the API server.' },
  { id: 'cloud-4', category: 'Cloud', title: 'Unusual Console Login', source: 'CloudTrail', eventType: 'Failed Login', severity: 'MEDIUM', sourceIp: '18.118.33.8', asset: 'AWS Console', username: 's.chen', description: 'A console login from a previously unseen geolocation triggered MFA challenge exhaustion and unusual IAM policy access.' },
  { id: 'data-1', category: 'Data', title: 'Large Archive Upload', source: 'Firewall', eventType: 'Data Exfiltration', severity: 'HIGH', sourceIp: '10.10.6.12', asset: 'Data Lake Node', username: 'j.park', description: 'An internal system transferred a large archive bundle to an external S3-compatible endpoint during off-hours.' },
  { id: 'data-2', category: 'Data', title: 'Mass File Staging', source: 'Endpoint Agent', eventType: 'Data Exfiltration', severity: 'CRITICAL', sourceIp: '10.17.88.16', asset: 'Finance Shares', username: 'r.tam', description: 'A user account compressed hundreds of files and staged them into a single archive prior to external transfer attempts.' },
  { id: 'data-3', category: 'Data', title: 'Credential Dumping', source: 'Endpoint Agent', eventType: 'Malware Detection', severity: 'CRITICAL', sourceIp: '172.16.55.14', asset: 'Workstation-17', username: 'r.hughes', description: 'LSASS memory scraping behavior was detected followed by rapid off-host copy actions and hash extraction attempts.' },
  { id: 'lateral-1', category: 'Lateral', title: 'SMB Admin Share Access', source: 'Firewall', eventType: 'Lateral Movement', severity: 'HIGH', sourceIp: '172.30.9.18', asset: 'Domain Controllers', username: 'svc_ad', description: 'Multiple authenticated SMB connections to privileged hosts occurred after a suspicious user login on a payroll workstation.' },
  { id: 'lateral-2', category: 'Endpoint', title: 'WinRM Pivot Attempt', source: 'Endpoint Agent', eventType: 'Lateral Movement', severity: 'HIGH', sourceIp: '10.50.2.90', asset: 'Engineering Segment', username: 'j.turner', description: 'WinRM remote execution was observed from a user workstation to a second device that had not communicated with the host previously.' },
  { id: 'saas-1', category: 'SaaS', title: 'Shadow IT Upload', source: 'Web Proxy', eventType: 'Shadow IT', severity: 'MEDIUM', sourceIp: '10.28.45.15', asset: 'Sales Laptop', username: 's.green', description: 'The user accessed an unapproved file-sharing service and uploaded a sensitive finance spreadsheet outside the sanctioned policy.' },
  { id: 'saas-2', category: 'SaaS', title: 'New Browser Extension', source: 'Endpoint Agent', eventType: 'Shadow IT', severity: 'MEDIUM', sourceIp: '10.64.7.8', asset: 'Marketing PC', username: 'n.garcia', description: 'A browser extension was installed from an untrusted source and began collecting browsing metadata and clipboard state.' },
  { id: 'web-1', category: 'Web', title: 'SQL Injection Probe', source: 'Web Proxy', eventType: 'Critical Alert', severity: 'HIGH', sourceIp: '203.0.113.84', asset: 'Public Web App', username: 'anonymous', description: 'Web requests contained SQL injection signatures and malformed parameters targeting the customer-facing application login endpoint.' },
  { id: 'web-2', category: 'Web', title: 'Web Shell Upload', source: 'Firewall', eventType: 'Malware Detection', severity: 'CRITICAL', sourceIp: '198.51.100.76', asset: 'Customer Portal', username: 'web-root', description: 'A suspicious web shell was uploaded to the portal document directory and then executed from a previously unseen script path.' }
];

const defaultComposerState: EventComposerState = {
  source: 'Auth Gateway',
  eventType: 'Failed Login',
  severity: 'MEDIUM',
  sourceIp: '192.168.1.10',
  asset: 'Gateway-01',
  username: 'analyst',
  description: 'User login failed after repeated credential attempts.'
};

const buildHourlySeries = (logs: LogEntry[]) => {
  const counts = Array.from({ length: 24 }, () => 0);

  logs.forEach((log) => {
    const hour = new Date(log.timestamp).getHours();
    counts[hour] += 1;
  });

  const max = Math.max(...counts, 1);
  const points = counts.map((count, index) => {
    const x = (index / 23) * 100;
    const y = 100 - (count / max) * 72 - 10;
    return { hour: index, count, x, y };
  });

  const path = points.map((point, index) => {
    const command = index === 0 ? 'M' : 'L';
    return `${command} ${point.x} ${point.y}`;
  }).join(' ');

  const areaPath = `${path} L 100 100 L 0 100 Z`;

  return { counts, points, max, path, areaPath };
};

const escapeMarkdownHtml = (value: string) => value
  .replace(/&/g, '&amp;')
  .replace(/</g, '&lt;')
  .replace(/>/g, '&gt;')
  .replace(/"/g, '&quot;')
  .replace(/'/g, '&#039;');

const renderMarkdownText = (value: string) => {
  const html = escapeMarkdownHtml(value)
    .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
    .replace(/\*(.+?)\*/g, '<em>$1</em>')
    .replace(/`([^`]+)`/g, '<code>$1</code>')
    .replace(/\n/g, '<br />');

  return <div dangerouslySetInnerHTML={{ __html: html }} />;
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
  const [composer, setComposer] = useState<EventComposerState>(defaultComposerState);
  const [composerError, setComposerError] = useState('');
  const [composerSuccess, setComposerSuccess] = useState('');
  const [chartHoverIndex, setChartHoverIndex] = useState<number | null>(null);
  const [templateCategory, setTemplateCategory] = useState<'All' | string>('All');
  const [sourceMenuOpen, setSourceMenuOpen] = useState(false);
  const [selectedIncidentDetail, setSelectedIncidentDetail] = useState<IncidentDetail | null>(null);
  const [incidentNoteDraft, setIncidentNoteDraft] = useState('');
  const [cases, setCases] = useState<CaseRecord[]>(() => {
    try {
      const savedCases = localStorage.getItem('sentinel-cases');
      return savedCases ? JSON.parse(savedCases) as CaseRecord[] : [];
    } catch {
      return [];
    }
  });
  const [selectedCaseId, setSelectedCaseId] = useState<string | null>(null);
  const [caseNoteDraft, setCaseNoteDraft] = useState('');
  const sourceMenuRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    localStorage.setItem('sentinel-cases', JSON.stringify(cases));
  }, [cases]);

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

  const filterLogs = (items: LogEntry[]) => items.filter((log) => {
    const matchesSearch = !search || [log.source, log.eventType, log.message].some((value) =>
      value.toLowerCase().includes(search.toLowerCase())
    );

    const matchesSeverity = severityFilter === 'ALL' || log.severity === severityFilter;
    return matchesSearch && matchesSeverity;
  });

  const fetchIncidentDetail = async (incidentId: string): Promise<IncidentDetail | null> => {
    if (!auth) return null;
    const res = await fetch(`/api/incidents/${incidentId}`, {
      headers: { Authorization: `Bearer ${auth.token}` }
    });

    if (!res.ok) {
      throw new Error('Unable to load incident details');
    }

    const data = await res.json() as IncidentDetail;
    setSelectedIncidentDetail(data);
    return data;
  };

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

  const hourlySeries = buildHourlySeries(logs);
  const severityDistribution = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'].map((label) => ({
    label,
    value: logs.filter((log) => log.severity === label).length
  }));
  const totalSeverity = severityDistribution.reduce((sum, item) => sum + item.value, 0) || 1;
  const sourceCounts = Object.entries(logs.reduce<Record<string, number>>((acc, log) => {
    acc[log.source] = (acc[log.source] || 0) + 1;
    return acc;
  }, {})).sort((a, b) => b[1] - a[1]).slice(0, 5);
  const filteredSourceSuggestions = composer.source.trim()
    ? commonSourceOptions.filter((source) => source.toLowerCase().includes(composer.source.toLowerCase().trim()))
    : commonSourceOptions;

  const templateCategories = ['All', ...Array.from(new Set(SOC_TEMPLATE_LIBRARY.map((template) => template.category)))];
  const filteredTemplates = templateCategory === 'All'
    ? SOC_TEMPLATE_LIBRARY
    : SOC_TEMPLATE_LIBRARY.filter((template) => template.category === templateCategory);

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
    const handleClickOutside = (event: MouseEvent) => {
      if (sourceMenuRef.current && !sourceMenuRef.current.contains(event.target as Node)) {
        setSourceMenuOpen(false);
      }
    };

    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
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

  const handleIncidentSelect = async (incidentId: string) => {
    setSelectedIncidentId(incidentId);
    try {
      await fetchIncidentDetail(incidentId);
    } catch {
      setSelectedIncidentDetail(null);
    }
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

  const selectedWorkflow = selectedIncidentDetail
    ? {
        status: selectedIncidentDetail.status,
        assignedAnalyst: selectedIncidentDetail.assignedAnalyst,
        notes: selectedIncidentDetail.notes ?? [],
        timeline: selectedIncidentDetail.timeline ?? []
      }
    : null;

  const addIncidentNote = async () => {
    if (!selectedIncidentDetail || !selectedWorkflow) return;
    const note = incidentNoteDraft.trim();
    if (!note) return;

    try {
      const res = await fetch(`/api/incidents/${selectedIncidentDetail.id}/notes`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${auth!.token}`
        },
        body: JSON.stringify({
          analyst: selectedWorkflow.assignedAnalyst,
          content: note
        })
      });

      if (!res.ok) {
        throw new Error('Unable to save note');
      }

      const nextDetail = await res.json();
      setSelectedIncidentDetail(nextDetail as IncidentDetail);
      setIncidentNoteDraft('');
    } catch {
      setError('Unable to save note.');
    }
  };

  const updateWorkflowStatus = async (status: WorkflowStatus) => {
    if (!selectedIncidentDetail || !auth) return;

    try {
      const res = await fetch(`/api/incidents/${selectedIncidentDetail.id}`, {
        method: 'PATCH',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${auth.token}`
        },
        body: JSON.stringify({ status })
      });

      if (!res.ok) {
        throw new Error('Unable to update status');
      }

      setSelectedIncidentDetail(await res.json() as IncidentDetail);
    } catch {
      setError('Unable to update incident status.');
    }
  };

  const updateAssignedAnalyst = async (analyst: AnalystName) => {
    if (!selectedIncidentDetail || !auth) return;

    try {
      const res = await fetch(`/api/incidents/${selectedIncidentDetail.id}`, {
        method: 'PATCH',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${auth.token}`
        },
        body: JSON.stringify({ assignedAnalyst: analyst })
      });

      if (!res.ok) {
        throw new Error('Unable to update analyst');
      }

      setSelectedIncidentDetail(await res.json() as IncidentDetail);
    } catch {
      setError('Unable to update analyst assignment.');
    }
  };

  const createCaseFromIncident = (incident: LogEntry) => {
    if (cases.some((item) => item.incidentId === incident.id)) return;

    const createdAt = new Date().toISOString();
    const caseId = `CASE-${createdAt.slice(0, 10).replace(/-/g, '')}-${Math.random().toString(36).slice(2, 7).toUpperCase()}`;
    const nextCase: CaseRecord = {
      id: caseId,
      incidentId: incident.id,
      incident,
      priority: incident.severity === 'CRITICAL' ? 'P1' : 'P2',
      status: 'New',
      assignedAnalyst: 'Tunar',
      sla: incident.severity === 'CRITICAL' ? '4 hours' : '8 hours',
      createdAt,
      timeline: [{
        id: `${caseId}-created`,
        type: 'created',
        timestamp: createdAt,
        message: 'Case created from critical incident',
        analyst: auth.user.email
      }],
      notes: []
    };

    setCases((current) => [nextCase, ...current]);
    setSelectedCaseId(caseId);
    setSelectedIncidentId(null);
    setActivePage('Cases');
  };

  const updateCase = (caseId: string, updates: Partial<CaseRecord>, timelineEntry?: CaseTimelineEntry) => {
    setCases((current) => current.map((item) => item.id === caseId ? {
      ...item,
      ...updates,
      timeline: timelineEntry ? [...item.timeline, timelineEntry].sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime()) : item.timeline
    } : item));
  };

  const updateCaseStatus = (status: CaseStatus) => {
    const selectedCase = cases.find((item) => item.id === selectedCaseId);
    if (!selectedCase) return;
    updateCase(selectedCase.id, { status }, {
      id: `${selectedCase.id}-status-${Date.now()}`,
      type: 'status',
      timestamp: new Date().toISOString(),
      message: `Status changed to ${status}`,
      analyst: auth.user.email
    });
  };

  const updateCaseAssignment = (assignedAnalyst: AnalystName) => {
    const selectedCase = cases.find((item) => item.id === selectedCaseId);
    if (!selectedCase) return;
    updateCase(selectedCase.id, { assignedAnalyst }, {
      id: `${selectedCase.id}-assignment-${Date.now()}`,
      type: 'assignment',
      timestamp: new Date().toISOString(),
      message: `Assigned to ${assignedAnalyst}`,
      analyst: auth.user.email
    });
  };

  const addCaseNote = () => {
    const selectedCase = cases.find((item) => item.id === selectedCaseId);
    const content = caseNoteDraft.trim();
    if (!selectedCase || !content) return;
    const timestamp = new Date().toISOString();
    updateCase(selectedCase.id, {
      notes: [...selectedCase.notes, {
        id: `${selectedCase.id}-note-${Date.now()}`,
        timestamp,
        analyst: auth.user.email,
        content
      }].sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime())
    }, {
      id: `${selectedCase.id}-note-timeline-${Date.now()}`,
      type: 'note',
      timestamp,
      message: `Note added by ${auth.user.email}`,
      analyst: auth.user.email
    });
    setCaseNoteDraft('');
  };

  const handleComposerChange = (field: keyof EventComposerState, value: string) => {
    setComposer((current) => ({ ...current, [field]: value }));
    setComposerError('');
    setComposerSuccess('');
  };

  const resetComposer = () => {
    setComposer(defaultComposerState);
    setComposerError('');
    setComposerSuccess('');
  };

  const applyTemplate = (template: ScenarioTemplate) => {
    setComposer({
      source: template.source,
      eventType: template.eventType,
      severity: template.severity,
      sourceIp: template.sourceIp,
      asset: template.asset,
      username: template.username,
      description: template.description
    });
    setComposerError('');
    setComposerSuccess('');
  };

  const handleComposerSubmit = async (event: React.FormEvent) => {
    event.preventDefault();
    setComposerError('');
    setComposerSuccess('');

    const sourceValue = composer.source.trim();
    if (!composer.eventType.trim()) {
      setComposerError('Event type is required.');
      return;
    }
    if (!sourceValue) {
      setComposerError('Source is required.');
      return;
    }
    if (!composer.sourceIp.trim() || !ipv4Regex.test(composer.sourceIp.trim())) {
      setComposerError('Please enter a valid IPv4 source address.');
      return;
    }
    if (!composer.asset.trim()) {
      setComposerError('Asset or endpoint is required.');
      return;
    }
    if (!composer.username.trim()) {
      setComposerError('Username is required.');
      return;
    }
    if (!composer.description.trim() || composer.description.trim().length < 10) {
      setComposerError('Description must be at least 10 characters.');
      return;
    }

    try {
      const payload = {
        source: sourceValue,
        eventType: composer.eventType,
        severity: composer.severity,
        message: `${composer.description.trim()} | Source IP: ${composer.sourceIp.trim()} | Asset: ${composer.asset.trim()} | Username: ${composer.username.trim()}`
      };

      const res = await fetch('/api/logs', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${auth.token}`
        },
        body: JSON.stringify(payload)
      });

      if (!res.ok) {
        const body = await res.json();
        throw new Error(body.error || 'Failed to submit event');
      }

      await fetchLogs(auth.token);
      setComposerSuccess('Event submitted successfully.');
      resetComposer();
    } catch (err: any) {
      setComposerError(err.message || 'Unable to submit event.');
    }
  };

  const sidebarItems: { label: PageName; icon: string }[] = [
    { label: 'Dashboard', icon: '▣' },
    { label: 'Incidents', icon: '⚑' },
    { label: 'Cases', icon: '▤' },
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
            onCreateCase={createCaseFromIncident}
            caseIncidentIds={new Set(cases.map((item) => item.incidentId))}
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

    if (activePage === 'Cases') {
      return (
        <section style={{ display: 'flex', flexDirection: 'column', gap: '1.2rem' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'end', gap: '1rem', flexWrap: 'wrap' }}>
            <div>
              <div style={{ color: '#93c5fd', fontSize: '0.72rem', letterSpacing: '0.12em', textTransform: 'uppercase' }}>Case Management</div>
              <h2 style={{ margin: '0.25rem 0 0', fontSize: '1.5rem' }}>Active Cases</h2>
            </div>
            <div style={{ color: '#cbd5e1', fontSize: '0.85rem' }}>{cases.length} {cases.length === 1 ? 'case' : 'cases'} tracked locally</div>
          </div>

          {cases.length === 0 ? (
            <div style={{ background: 'rgba(15, 23, 42, 0.38)', border: '1px solid rgba(148, 163, 184, 0.2)', borderRadius: '18px', padding: '2rem', color: '#cbd5e1' }}>
              No cases yet. Create one from a critical incident in the Incidents page.
            </div>
          ) : (
            <div style={{ display: 'grid', gap: '0.75rem' }}>
              {cases.map((item) => (
                <button
                  key={item.id}
                  type="button"
                  onClick={() => setSelectedCaseId(item.id)}
                  style={{
                    display: 'grid',
                    gridTemplateColumns: 'minmax(180px, 1.2fr) repeat(4, minmax(90px, 0.7fr))',
                    alignItems: 'center',
                    gap: '1rem',
                    textAlign: 'left',
                    width: '100%',
                    background: selectedCaseId === item.id ? 'rgba(59, 130, 246, 0.16)' : 'rgba(15, 23, 42, 0.42)',
                    border: '1px solid rgba(148, 163, 184, 0.2)',
                    borderRadius: '14px',
                    padding: '1rem',
                    color: '#e2e8f0',
                    cursor: 'pointer'
                  }}
                >
                  <div>
                    <div style={{ color: '#bfdbfe', fontSize: '0.72rem', fontWeight: 800, letterSpacing: '0.08em' }}>{item.id}</div>
                    <div style={{ marginTop: '0.35rem', fontWeight: 700 }}>{item.incident.eventType}</div>
                    <div style={{ marginTop: '0.2rem', color: '#94a3b8', fontSize: '0.78rem' }}>Incident {item.incident.id}</div>
                  </div>
                  <div><div style={{ color: '#94a3b8', fontSize: '0.68rem', textTransform: 'uppercase' }}>Priority</div><strong style={{ color: item.priority === 'P1' ? '#fca5a5' : '#fcd34d' }}>{item.priority}</strong></div>
                  <div><div style={{ color: '#94a3b8', fontSize: '0.68rem', textTransform: 'uppercase' }}>Status</div><strong>{item.status}</strong></div>
                  <div><div style={{ color: '#94a3b8', fontSize: '0.68rem', textTransform: 'uppercase' }}>Analyst</div><strong>{item.assignedAnalyst}</strong></div>
                  <div><div style={{ color: '#94a3b8', fontSize: '0.68rem', textTransform: 'uppercase' }}>SLA</div><strong>{item.sla}</strong></div>
                </button>
              ))}
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
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '1rem' }}>
          <KPIGrid
            totalEvents={totalEvents}
            criticalCount={criticalCount}
            highCount={highCount}
            todayCount={todayCount}
          />
        </div>

        <section
          style={{
            background: 'rgba(15, 23, 42, 0.36)',
            border: '1px solid rgba(148, 163, 184, 0.22)',
            borderRadius: '22px',
            boxShadow: '0 24px 45px rgba(15, 23, 42, 0.28)',
            backdropFilter: 'blur(18px)',
            WebkitBackdropFilter: 'blur(18px)',
            overflow: 'hidden',
            padding: '1.2rem'
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1rem', flexWrap: 'wrap', gap: '0.8rem' }}>
            <div>
              <div style={{ color: '#93c5fd', fontSize: '0.72rem', letterSpacing: '0.12em', textTransform: 'uppercase' }}>Workflow</div>
              <h2 style={{ margin: '0.25rem 0 0', fontSize: '1.5rem', fontWeight: 700 }}>Event Composer</h2>
            </div>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'minmax(0, 1.7fr) minmax(280px, 0.9fr)', gap: '1rem' }}>
            <div style={{ background: 'rgba(15, 23, 42, 0.26)', border: '1px solid rgba(148, 163, 184, 0.18)', borderRadius: '18px', padding: '1rem' }}>
              <form onSubmit={handleComposerSubmit} style={{ display: 'grid', gap: '0.9rem' }}>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '0.8rem' }}>
                  <div ref={sourceMenuRef} style={{ position: 'relative' }}>
                    <label style={{ display: 'block', marginBottom: '0.45rem', color: '#cbd5e1', fontSize: '0.78rem', letterSpacing: '0.04em', textTransform: 'uppercase' }}>Source</label>
                    <input
                      value={composer.source}
                      onChange={(e) => {
                        handleComposerChange('source', e.target.value);
                        setSourceMenuOpen(true);
                      }}
                      onFocus={() => setSourceMenuOpen(true)}
                      placeholder="Search or type a source"
                      style={{ ...fieldStyle, height: '42px', minHeight: '42px' }}
                    />
                    {sourceMenuOpen && filteredSourceSuggestions.length > 0 && (
                      <div style={{
                        position: 'absolute',
                        top: 'calc(100% + 0.45rem)',
                        left: 0,
                        right: 0,
                        zIndex: 30,
                        background: 'rgba(15, 23, 42, 0.96)',
                        border: '1px solid rgba(148, 163, 184, 0.18)',
                        borderRadius: '12px',
                        overflow: 'hidden',
                        boxShadow: '0 18px 32px rgba(8, 15, 31, 0.28)'
                      }}>
                        {filteredSourceSuggestions.slice(0, 8).map((source) => (
                          <button
                            key={source}
                            type="button"
                            onClick={() => {
                              handleComposerChange('source', source);
                              setSourceMenuOpen(false);
                            }}
                            style={{
                              width: '100%',
                              textAlign: 'left',
                              background: 'transparent',
                              border: 'none',
                              color: '#e2e8f0',
                              padding: '0.6rem 0.7rem',
                              cursor: 'pointer',
                              borderBottom: '1px solid rgba(148, 163, 184, 0.08)'
                            }}
                          >
                            {source}
                          </button>
                        ))}
                        <button
                          type="button"
                          onClick={() => {
                            setSourceMenuOpen(false);
                            handleComposerChange('source', composer.source.trim() || '');
                          }}
                          style={{
                            width: '100%',
                            textAlign: 'left',
                            background: 'rgba(59, 130, 246, 0.12)',
                            border: 'none',
                            color: '#dbeafe',
                            padding: '0.6rem 0.7rem',
                            cursor: 'pointer',
                            fontWeight: 700
                          }}
                        >
                          + Create custom source
                        </button>
                      </div>
                    )}
                  </div>

                  <div>
                    <label style={{ display: 'block', marginBottom: '0.45rem', color: '#cbd5e1', fontSize: '0.78rem', letterSpacing: '0.04em', textTransform: 'uppercase' }}>Event Type</label>
                    <select
                      value={composer.eventType}
                      onChange={(e) => handleComposerChange('eventType', e.target.value)}
                      style={fieldStyle}
                    >
                      {eventTypeOptions.map((option) => (
                        <option key={option} value={option}>{option}</option>
                      ))}
                    </select>
                  </div>

                  <div>
                    <label style={{ display: 'block', marginBottom: '0.45rem', color: '#cbd5e1', fontSize: '0.78rem', letterSpacing: '0.04em', textTransform: 'uppercase' }}>Severity</label>
                    <select
                      value={composer.severity}
                      onChange={(e) => handleComposerChange('severity', e.target.value as Severity)}
                      style={fieldStyle}
                    >
                      {severityOptions.map((option) => (
                        <option key={option} value={option}>{option}</option>
                      ))}
                    </select>
                  </div>

                  <div>
                    <label style={{ display: 'block', marginBottom: '0.45rem', color: '#cbd5e1', fontSize: '0.78rem', letterSpacing: '0.04em', textTransform: 'uppercase' }}>Source IP</label>
                    <input
                      type="text"
                      value={composer.sourceIp}
                      onChange={(e) => handleComposerChange('sourceIp', e.target.value)}
                      placeholder="192.168.1.10"
                      style={fieldStyle}
                    />
                  </div>

                  <div>
                    <label style={{ display: 'block', marginBottom: '0.45rem', color: '#cbd5e1', fontSize: '0.78rem', letterSpacing: '0.04em', textTransform: 'uppercase' }}>Asset / Endpoint</label>
                    <input
                      type="text"
                      value={composer.asset}
                      onChange={(e) => handleComposerChange('asset', e.target.value)}
                      placeholder="web-01"
                      style={fieldStyle}
                    />
                  </div>

                  <div>
                    <label style={{ display: 'block', marginBottom: '0.45rem', color: '#cbd5e1', fontSize: '0.78rem', letterSpacing: '0.04em', textTransform: 'uppercase' }}>Username</label>
                    <input
                      type="text"
                      value={composer.username}
                      onChange={(e) => handleComposerChange('username', e.target.value)}
                      placeholder="username"
                      style={fieldStyle}
                    />
                  </div>
                </div>

                <div>
                  <label style={{ display: 'block', marginBottom: '0.45rem', color: '#cbd5e1', fontSize: '0.78rem', letterSpacing: '0.04em', textTransform: 'uppercase' }}>Description</label>
                  <textarea
                    rows={4}
                    value={composer.description}
                    onChange={(e) => handleComposerChange('description', e.target.value)}
                    placeholder="Describe the threat or observable in detail"
                    style={{ ...fieldStyle, minHeight: '110px', resize: 'vertical' }}
                  />
                </div>

                {(composerError || composerSuccess) && (
                  <div style={{ color: composerError ? '#fda4af' : '#86efac', fontSize: '0.88rem', fontWeight: 600 }}>
                    {composerError || composerSuccess}
                  </div>
                )}

                <div style={{ display: 'flex', gap: '0.7rem', flexWrap: 'wrap' }}>
                  <button type="submit" style={{
                    background: 'linear-gradient(135deg, #2563eb, #0ea5e9)',
                    border: 'none',
                    color: '#eff6ff',
                    borderRadius: '12px',
                    padding: '0.8rem 1.1rem',
                    cursor: 'pointer',
                    fontWeight: 700,
                    boxShadow: '0 12px 24px rgba(37, 99, 235, 0.32)'
                  }}>
                    Submit Event
                  </button>
                  <button type="button" onClick={resetComposer} style={{
                    background: 'rgba(15, 23, 42, 0.8)',
                    border: '1px solid rgba(148, 163, 184, 0.2)',
                    color: '#f8fafc',
                    borderRadius: '12px',
                    padding: '0.8rem 1.1rem',
                    cursor: 'pointer',
                    fontWeight: 600
                  }}>
                    Clear Form
                  </button>
                </div>
              </form>
            </div>

            <div style={{ background: 'rgba(15, 23, 42, 0.26)', border: '1px solid rgba(148, 163, 184, 0.18)', borderRadius: '18px', padding: '1rem' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '0.75rem', marginBottom: '0.8rem' }}>
                <div style={{ color: '#cbd5e1', fontSize: '0.75rem', letterSpacing: '0.1em', textTransform: 'uppercase' }}>Template Library</div>
                <div style={{ color: '#93c5fd', fontSize: '0.72rem' }}>{filteredTemplates.length} scenarios</div>
              </div>

              <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.45rem', marginBottom: '0.8rem' }}>
                {templateCategories.map((category) => (
                  <button
                    key={category}
                    type="button"
                    onClick={() => setTemplateCategory(category)}
                    style={{
                      border: '1px solid rgba(148, 163, 184, 0.18)',
                      background: templateCategory === category ? 'rgba(59, 130, 246, 0.14)' : 'rgba(15, 23, 42, 0.6)',
                      color: templateCategory === category ? '#e2e8f0' : '#cbd5e1',
                      borderRadius: '999px',
                      padding: '0.45rem 0.7rem',
                      cursor: 'pointer',
                      fontSize: '0.72rem'
                    }}
                  >
                    {category}
                  </button>
                ))}
              </div>

              <div style={{ display: 'grid', gap: '0.55rem', maxHeight: '430px', overflowY: 'auto', paddingRight: '0.2rem' }}>
                {filteredTemplates.map((template) => (
                  <button
                    key={template.id}
                    type="button"
                    onClick={() => applyTemplate(template)}
                    style={{
                      textAlign: 'left',
                      background: 'rgba(15, 23, 42, 0.5)',
                      border: '1px solid rgba(148, 163, 184, 0.18)',
                      borderRadius: '12px',
                      padding: '0.7rem 0.8rem',
                      cursor: 'pointer',
                      color: '#e2e8f0',
                      transition: 'border-color 0.2s ease, transform 0.2s ease'
                    }}
                  >
                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '0.5rem' }}>
                      <div style={{ fontWeight: 700, fontSize: '0.85rem' }}>{template.title}</div>
                      <span style={{
                        background: template.severity === 'CRITICAL' ? 'rgba(239,68,68,0.16)' : template.severity === 'HIGH' ? 'rgba(245,158,11,0.14)' : 'rgba(59,130,246,0.12)',
                        borderRadius: '999px',
                        color: template.severity === 'CRITICAL' ? '#fca5a5' : template.severity === 'HIGH' ? '#fbbf24' : '#93c5fd',
                        padding: '0.18rem 0.45rem',
                        fontSize: '0.66rem',
                        fontWeight: 700
                      }}>
                        {template.severity}
                      </span>
                    </div>
                    <div style={{ marginTop: '0.35rem', color: '#cbd5e1', fontSize: '0.72rem' }}>{template.category}</div>
                  </button>
                ))}
              </div>
            </div>
          </div>
        </section>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: '1rem' }}>
          <div
            onMouseEnter={(e) => {
              e.currentTarget.style.transform = 'translateY(-2px)';
              e.currentTarget.style.boxShadow = '0 20px 30px rgba(59,130,246,0.18)';
            }}
            onMouseLeave={(e) => {
              e.currentTarget.style.transform = 'translateY(0)';
              e.currentTarget.style.boxShadow = 'none';
            }}
            style={{
              background: 'rgba(15, 23, 42, 0.38)',
              border: '1px solid rgba(148, 163, 184, 0.2)',
              borderRadius: '18px',
              padding: '1rem 1.1rem',
              minHeight: '220px',
              transition: 'transform 0.2s ease, box-shadow 0.2s ease',
              position: 'relative'
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '0.75rem', marginBottom: '0.7rem' }}>
              <h3 style={{ margin: 0, fontSize: '1rem', fontWeight: 700 }}>Events per Hour</h3>
              <span style={{ color: '#93c5fd', fontSize: '0.72rem', letterSpacing: '0.08em', textTransform: 'uppercase' }}>24h</span>
            </div>

            <div style={{ position: 'relative', height: '150px' }}>
              <svg viewBox="0 0 100 100" width="100%" height="100%" preserveAspectRatio="none" style={{ display: 'block' }}>
                {[20, 40, 60, 80].map((line) => (
                  <line key={line} x1="0" y1={line} x2="100" y2={line} stroke="rgba(148,163,184,0.15)" strokeWidth="0.6" />
                ))}
                <path d={hourlySeries.areaPath} fill="url(#areaGradient)" opacity="0.9" />
                <path d={hourlySeries.path} fill="none" stroke="url(#lineGradient)" strokeWidth="2.1" strokeLinecap="round" strokeLinejoin="round" />
                {hourlySeries.points.map((point) => (
                  <circle
                    key={point.hour}
                    cx={point.x}
                    cy={point.y}
                    r={chartHoverIndex === point.hour ? 2.9 : 1.7}
                    fill={chartHoverIndex === point.hour ? '#f8fafc' : '#7dd3fc'}
                    stroke="#38bdf8"
                    strokeWidth="0.8"
                    onMouseEnter={() => setChartHoverIndex(point.hour)}
                    onMouseLeave={() => setChartHoverIndex(null)}
                    style={{ cursor: 'pointer' }}
                  />
                ))}
                <defs>
                  <linearGradient id="lineGradient" x1="0%" y1="0%" x2="100%" y2="0%">
                    <stop offset="0%" stopColor="#38bdf8" />
                    <stop offset="100%" stopColor="#60a5fa" />
                  </linearGradient>
                  <linearGradient id="areaGradient" x1="0%" y1="0%" x2="0%" y2="100%">
                    <stop offset="0%" stopColor="rgba(56,189,248,0.45)" />
                    <stop offset="100%" stopColor="rgba(56,189,248,0.02)" />
                  </linearGradient>
                </defs>
              </svg>

              {chartHoverIndex !== null && (
                <div
                  style={{
                    position: 'absolute',
                    left: `${((chartHoverIndex / 23) * 100).toFixed(2)}%`,
                    top: `${Math.max(18, 100 - ((hourlySeries.counts[chartHoverIndex] / Math.max(...hourlySeries.counts, 1)) * 72 + 10)).toFixed(2)}%`,
                    transform: 'translate(-50%, -120%)',
                    background: 'rgba(15, 23, 42, 0.92)',
                    border: '1px solid rgba(96,165,250,0.35)',
                    borderRadius: '10px',
                    padding: '0.42rem 0.55rem',
                    color: '#f8fafc',
                    fontSize: '0.68rem',
                    whiteSpace: 'nowrap',
                    boxShadow: '0 12px 24px rgba(15, 23, 42, 0.3)'
                  }}
                >
                  {chartHoverIndex}:00 · {hourlySeries.counts[chartHoverIndex]}
                </div>
              )}
            </div>

            <div style={{ display: 'flex', justifyContent: 'space-between', color: '#cbd5e1', fontSize: '0.7rem', marginTop: '0.1rem' }}>
              {[0, 6, 12, 18, 23].map((hour) => (
                <span key={hour}>{hour}</span>
              ))}
            </div>
          </div>

          <div
            onMouseEnter={(e) => {
              e.currentTarget.style.transform = 'translateY(-2px)';
              e.currentTarget.style.boxShadow = '0 20px 30px rgba(59,130,246,0.18)';
            }}
            onMouseLeave={(e) => {
              e.currentTarget.style.transform = 'translateY(0)';
              e.currentTarget.style.boxShadow = 'none';
            }}
            style={{
              background: 'rgba(15, 23, 42, 0.38)',
              border: '1px solid rgba(148, 163, 184, 0.2)',
              borderRadius: '18px',
              padding: '1rem 1.1rem',
              minHeight: '220px',
              transition: 'transform 0.2s ease, box-shadow 0.2s ease'
            }}
          >
            <h3 style={{ margin: '0 0 0.85rem', fontSize: '1rem', fontWeight: 700 }}>Severity Distribution</h3>
            <div style={{ display: 'flex', alignItems: 'center', gap: '1rem', minHeight: '160px' }}>
              <div style={{
                position: 'relative',
                width: '110px',
                height: '110px',
                borderRadius: '50%',
                background: `conic-gradient(
                  #64748b 0% ${((severityDistribution[0].value / totalSeverity) * 100).toFixed(1)}%,
                  #3b82f6 ${((severityDistribution[0].value / totalSeverity) * 100).toFixed(1)}% ${(((severityDistribution[0].value + severityDistribution[1].value) / totalSeverity) * 100).toFixed(1)}%,
                  #f59e0b ${(((severityDistribution[0].value + severityDistribution[1].value) / totalSeverity) * 100).toFixed(1)}% ${(((severityDistribution[0].value + severityDistribution[1].value + severityDistribution[2].value) / totalSeverity) * 100).toFixed(1)}%,
                  #ef4444 ${(((severityDistribution[0].value + severityDistribution[1].value + severityDistribution[2].value) / totalSeverity) * 100).toFixed(1)}% 100%
                )`,
                boxShadow: 'inset 0 0 0 1px rgba(148,163,184,0.08)'
              }}>
                <div style={{
                  position: 'absolute',
                  inset: '18px',
                  background: 'rgba(15, 23, 42, 0.88)',
                  borderRadius: '50%',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  flexDirection: 'column',
                  border: '1px solid rgba(148,163,184,0.1)'
                }}>
                  <span style={{ fontSize: '1.1rem', fontWeight: 800 }}>{logs.length}</span>
                  <span style={{ color: '#94a3b8', fontSize: '0.62rem', letterSpacing: '0.08em', textTransform: 'uppercase' }}>Total</span>
                </div>
              </div>

              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem', flex: 1 }}>
                {severityDistribution.map((item) => {
                  const percentage = ((item.value / totalSeverity) * 100).toFixed(0);
                  const colors: Record<string, string> = {
                    LOW: '#64748b',
                    MEDIUM: '#3b82f6',
                    HIGH: '#f59e0b',
                    CRITICAL: '#ef4444'
                  };
                  return (
                    <div key={item.label} style={{ display: 'flex', alignItems: 'center', gap: '0.55rem' }}>
                      <span style={{ width: '9px', height: '9px', borderRadius: '50%', background: colors[item.label], display: 'inline-block' }} />
                      <span style={{ flex: 1, color: '#cbd5e1', fontSize: '0.76rem' }}>{item.label}</span>
                      <span style={{ color: '#f8fafc', fontSize: '0.76rem', fontWeight: 700 }}>{percentage}%</span>
                    </div>
                  );
                })}
              </div>
            </div>
          </div>

          <div
            onMouseEnter={(e) => {
              e.currentTarget.style.transform = 'translateY(-2px)';
              e.currentTarget.style.boxShadow = '0 20px 30px rgba(59,130,246,0.18)';
            }}
            onMouseLeave={(e) => {
              e.currentTarget.style.transform = 'translateY(0)';
              e.currentTarget.style.boxShadow = 'none';
            }}
            style={{
              background: 'rgba(15, 23, 42, 0.38)',
              border: '1px solid rgba(148, 163, 184, 0.2)',
              borderRadius: '18px',
              padding: '1rem 1.1rem',
              minHeight: '220px',
              transition: 'transform 0.2s ease, box-shadow 0.2s ease'
            }}
          >
            <h3 style={{ margin: '0 0 0.85rem', fontSize: '1rem', fontWeight: 700 }}>Top 5 Event Sources</h3>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.8rem', marginTop: '0.2rem' }}>
              {sourceCounts.length === 0 ? (
                <p style={{ margin: 0, color: '#cbd5e1' }}>No sources yet.</p>
              ) : sourceCounts.map(([source, count]) => (
                <div key={source}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '0.35rem', color: '#cbd5e1', fontSize: '0.77rem' }}>
                    <span>{source}</span>
                    <span>{count}</span>
                  </div>
                  <div style={{ height: '10px', width: '100%', borderRadius: '9999px', background: 'rgba(148,163,184,0.14)', overflow: 'hidden' }}>
                    <div
                      style={{
                        width: `${(count / Math.max(...sourceCounts.map(([, value]) => value), 1)) * 100}%`,
                        height: '100%',
                        background: 'linear-gradient(90deg, #38bdf8, #60a5fa)',
                        borderRadius: '9999px'
                      }}
                    />
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>

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

  const fieldStyle: React.CSSProperties = {
    width: '100%',
    borderRadius: '10px',
    border: '1px solid rgba(148, 163, 184, 0.18)',
    background: 'rgba(15, 23, 42, 0.7)',
    color: '#e2e8f0',
    padding: '0.7rem 0.8rem',
    outline: 'none',
    fontSize: '0.9rem',
    boxSizing: 'border-box'
  };

  const drawerIncident = selectedIncidentDetail && selectedWorkflow ? {
    incident: selectedIncidentDetail,
    workflow: selectedWorkflow
  } : null;

  const drawerMitre = drawerIncident && drawerIncident.incident.eventType
    ? getMitreMapping(drawerIncident.incident.eventType)
    : { id: 'N/A', tactic: 'Unknown', color: '#64748b' };
  const selectedCase = cases.find((item) => item.id === selectedCaseId) ?? null;
  const drawerCaseIncident = drawerIncident
    ? logs.find((log) => log.id === drawerIncident.incident.logId) ?? {
        id: drawerIncident.incident.logId,
        timestamp: drawerIncident.incident.timestamp ?? drawerIncident.incident.createdAt,
        source: drawerIncident.incident.source ?? 'Unknown',
        eventType: drawerIncident.incident.eventType ?? 'Unknown',
        severity: (drawerIncident.incident.severity ?? 'CRITICAL') as Severity,
        message: drawerIncident.incident.message ?? 'No description available.'
      }
    : null;
  const drawerCaseExists = drawerCaseIncident ? cases.some((item) => item.incidentId === drawerCaseIncident.id) : false;

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
                    background: 'transparent',
                    color: isActive ? '#f8fafc' : '#cbd5e1',
                    cursor: 'pointer',
                    textAlign: 'left',
                    width: '100%',
                    transition: 'all 0.2s ease'
                  }}
                >
                  {isActive && (
                    <span style={{
                      position: 'absolute',
                      left: sidebarCollapsed ? '3px' : '0.35rem',
                      top: '50%',
                      transform: 'translateY(-50%)',
                      width: '2px',
                      height: sidebarCollapsed ? '22px' : '22px',
                      borderRadius: '999px',
                      background: '#60a5fa',
                      boxShadow: '0 0 12px rgba(96, 165, 250, 0.65)',
                    }} />
                  )}
                  <span style={{
                    width: '18px',
                    display: 'inline-flex',
                    justifyContent: 'center',
                    fontSize: '1rem',
                    opacity: isActive ? 1 : 0.8,
                    textShadow: isActive ? '0 0 10px rgba(96, 165, 250, 0.7)' : 'none',
                    marginLeft: isActive && !sidebarCollapsed ? '0.5rem' : '0'
                  }}>{item.icon}</span>
                  {!sidebarCollapsed && <span style={{ fontWeight: 600 }}>{item.label}</span>}
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

        {drawerIncident && (
          <aside style={{
            position: 'fixed',
            top: '1.25rem',
            right: '1.25rem',
            width: 'min(420px, calc(100vw - 2rem))',
            height: 'calc(100vh - 2.5rem)',
            background: 'rgba(15, 23, 42, 0.82)',
            border: '1px solid rgba(148, 163, 184, 0.22)',
            borderRadius: '22px',
            boxShadow: '0 35px 60px rgba(8, 15, 31, 0.5)',
            backdropFilter: 'blur(18px)',
            WebkitBackdropFilter: 'blur(18px)',
            zIndex: 40,
            padding: '1.1rem',
            overflowY: 'auto',
            animation: 'drawerSlideIn 0.25s ease',
            transform: 'translateX(0)'
          }}>
            <style>{`
              @keyframes drawerSlideIn {
                from { opacity: 0; transform: translateX(30px); }
                to { opacity: 1; transform: translateX(0); }
              }
            `}</style>

            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '1rem', marginBottom: '1rem' }}>
              <div>
                <div style={{ color: '#93c5fd', fontSize: '0.7rem', letterSpacing: '0.12em', textTransform: 'uppercase' }}>Incident Detail</div>
                <h3 style={{ margin: '0.3rem 0 0', fontSize: '1.2rem' }}>{drawerIncident.incident.id}</h3>
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.55rem' }}>
                {drawerCaseIncident && (
                  <button
                    type="button"
                    disabled={drawerCaseExists}
                    onClick={() => createCaseFromIncident(drawerCaseIncident)}
                    style={{
                      border: drawerCaseExists ? '1px solid rgba(134, 239, 172, 0.25)' : '1px solid rgba(96, 165, 250, 0.55)',
                      borderRadius: '9px',
                      background: drawerCaseExists ? 'rgba(34, 197, 94, 0.12)' : 'linear-gradient(135deg, #2563eb, #0ea5e9)',
                      color: drawerCaseExists ? '#86efac' : '#eff6ff',
                      padding: '0.5rem 0.7rem',
                      fontSize: '0.72rem',
                      fontWeight: 700,
                      cursor: drawerCaseExists ? 'not-allowed' : 'pointer',
                      boxShadow: drawerCaseExists ? 'none' : '0 8px 16px rgba(37, 99, 235, 0.24)'
                    }}
                  >
                    {drawerCaseExists ? 'Case Created' : 'Create Case'}
                  </button>
                )}
                <button
                  type="button"
                  onClick={() => setSelectedIncidentId(null)}
                  style={{
                    width: '32px',
                    height: '32px',
                    borderRadius: '10px',
                    border: '1px solid rgba(148, 163, 184, 0.2)',
                    background: 'rgba(15, 23, 42, 0.7)',
                    color: '#e2e8f0',
                    cursor: 'pointer'
                  }}
                >
                  ×
                </button>
              </div>
            </div>

            <div style={{ display: 'grid', gap: '1rem' }}>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, minmax(0, 1fr))', gap: '0.75rem' }}>
                <div style={{ background: 'rgba(15, 23, 42, 0.52)', border: '1px solid rgba(148, 163, 184, 0.16)', borderRadius: '12px', padding: '0.75rem' }}>
                  <div style={{ color: '#93c5fd', fontSize: '0.68rem', letterSpacing: '0.08em', textTransform: 'uppercase', marginBottom: '0.32rem' }}>Event Type</div>
                  <div style={{ color: '#f8fafc', fontWeight: 700 }}>{drawerIncident.incident.eventType ?? 'Unknown'}</div>
                </div>
                <div style={{ background: 'rgba(15, 23, 42, 0.52)', border: '1px solid rgba(148, 163, 184, 0.16)', borderRadius: '12px', padding: '0.75rem' }}>
                  <div style={{ color: '#93c5fd', fontSize: '0.68rem', letterSpacing: '0.08em', textTransform: 'uppercase', marginBottom: '0.32rem' }}>Source</div>
                  <div style={{ color: '#f8fafc', fontWeight: 700 }}>{drawerIncident.incident.source ?? 'Unknown'}</div>
                </div>
                <div style={{ background: 'rgba(15, 23, 42, 0.52)', border: '1px solid rgba(148, 163, 184, 0.16)', borderRadius: '12px', padding: '0.75rem' }}>
                  <div style={{ color: '#93c5fd', fontSize: '0.68rem', letterSpacing: '0.08em', textTransform: 'uppercase', marginBottom: '0.32rem' }}>Severity</div>
                  <div style={{ color: '#f8fafc', fontWeight: 700 }}>{drawerIncident.incident.severity ?? 'Unknown'}</div>
                </div>
                <div style={{ background: 'rgba(15, 23, 42, 0.52)', border: '1px solid rgba(148, 163, 184, 0.16)', borderRadius: '12px', padding: '0.75rem' }}>
                  <div style={{ color: '#93c5fd', fontSize: '0.68rem', letterSpacing: '0.08em', textTransform: 'uppercase', marginBottom: '0.32rem' }}>Timestamp</div>
                  <div style={{ color: '#f8fafc', fontWeight: 700 }}>{new Date(drawerIncident.incident.timestamp ?? drawerIncident.incident.createdAt).toLocaleString()}</div>
                </div>
              </div>

              <div style={{ background: 'rgba(15, 23, 42, 0.52)', border: '1px solid rgba(148, 163, 184, 0.16)', borderRadius: '12px', padding: '0.85rem' }}>
                <div style={{ color: '#93c5fd', fontSize: '0.68rem', letterSpacing: '0.08em', textTransform: 'uppercase', marginBottom: '0.45rem' }}>MITRE Mapping</div>
                <div style={{ display: 'inline-flex', flexDirection: 'column', gap: '0.2rem', padding: '0.45rem 0.7rem', borderRadius: '10px', background: 'rgba(15, 23, 42, 0.8)', border: '1px solid rgba(148, 163, 184, 0.2)' }}>
                  <span style={{ display: 'inline-block', padding: '0.2rem 0.5rem', borderRadius: '9999px', background: drawerMitre.color, color: '#f8fafc', fontWeight: 700, fontSize: '0.72rem', letterSpacing: '0.04em', width: 'fit-content' }}>
                    {drawerMitre.id}
                  </span>
                  <span style={{ color: '#cbd5e1', fontSize: '0.7rem', letterSpacing: '0.08em', textTransform: 'uppercase' }}>
                    {drawerMitre.tactic}
                  </span>
                </div>
              </div>

              <div style={{ background: 'rgba(15, 23, 42, 0.52)', border: '1px solid rgba(148, 163, 184, 0.16)', borderRadius: '12px', padding: '0.85rem' }}>
                <div style={{ color: '#93c5fd', fontSize: '0.68rem', letterSpacing: '0.08em', textTransform: 'uppercase', marginBottom: '0.45rem' }}>Description</div>
                <div style={{ color: '#e2e8f0', lineHeight: 1.7, whiteSpace: 'pre-wrap' }}>{drawerIncident.incident.message ?? 'No description available.'}</div>
              </div>

              <div style={{ background: 'rgba(15, 23, 42, 0.52)', border: '1px solid rgba(148, 163, 184, 0.16)', borderRadius: '12px', padding: '0.85rem' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '0.75rem', marginBottom: '0.75rem' }}>
                  <div style={{ color: '#93c5fd', fontSize: '0.68rem', letterSpacing: '0.08em', textTransform: 'uppercase' }}>Workflow</div>
                  <select
                    value={drawerIncident.workflow.status}
                    onChange={(event) => updateWorkflowStatus(event.target.value as WorkflowStatus)}
                    style={{
                      border: '1px solid rgba(148, 163, 184, 0.2)',
                      background: '#0f172a',
                      color: '#e2e8f0',
                      borderRadius: '10px',
                      padding: '0.45rem 0.7rem'
                    }}
                  >
                    {workflowStatuses.map((status) => (
                      <option key={status} value={status}>{status}</option>
                    ))}
                  </select>
                </div>

                <div style={{ display: 'grid', gap: '0.7rem' }}>
                  <div>
                    <div style={{ color: '#93c5fd', fontSize: '0.68rem', letterSpacing: '0.08em', textTransform: 'uppercase', marginBottom: '0.4rem' }}>Assigned Analyst</div>
                    <select
                      value={drawerIncident.workflow.assignedAnalyst}
                      onChange={(event) => updateAssignedAnalyst(event.target.value as AnalystName)}
                      style={{
                        width: '100%',
                        border: '1px solid rgba(148, 163, 184, 0.2)',
                        background: '#0f172a',
                        color: '#e2e8f0',
                        borderRadius: '10px',
                        padding: '0.6rem 0.7rem'
                      }}
                    >
                      {demoAnalysts.map((analyst) => (
                        <option key={analyst} value={analyst}>{analyst}</option>
                      ))}
                    </select>
                  </div>

                  <div>
                    <div style={{ color: '#93c5fd', fontSize: '0.68rem', letterSpacing: '0.08em', textTransform: 'uppercase', marginBottom: '0.4rem' }}>Investigation Notes</div>
                    <textarea
                      value={incidentNoteDraft}
                      onChange={(event) => setIncidentNoteDraft(event.target.value)}
                      placeholder="Add markdown notes..."
                      style={{
                        width: '100%',
                        minHeight: '90px',
                        resize: 'vertical',
                        borderRadius: '10px',
                        border: '1px solid rgba(148, 163, 184, 0.2)',
                        background: 'rgba(15, 23, 42, 0.75)',
                        color: '#e2e8f0',
                        padding: '0.7rem 0.8rem',
                        boxSizing: 'border-box'
                      }}
                    />
                    <button
                      type="button"
                      onClick={addIncidentNote}
                      style={{
                        marginTop: '0.6rem',
                        width: '100%',
                        background: 'linear-gradient(135deg, #2563eb, #0ea5e9)',
                        border: 'none',
                        color: '#eff6ff',
                        borderRadius: '12px',
                        padding: '0.7rem 1rem',
                        cursor: 'pointer',
                        fontWeight: 700
                      }}
                    >
                      Add Note
                    </button>
                  </div>
                </div>
              </div>

              <div style={{ background: 'rgba(15, 23, 42, 0.52)', border: '1px solid rgba(148, 163, 184, 0.16)', borderRadius: '12px', padding: '0.85rem' }}>
                <div style={{ color: '#93c5fd', fontSize: '0.68rem', letterSpacing: '0.08em', textTransform: 'uppercase', marginBottom: '0.7rem' }}>Timeline</div>
                <div style={{ display: 'grid', gap: '0.8rem', position: 'relative', paddingLeft: '0.85rem' }}>
                  <div style={{ position: 'absolute', left: '4px', top: '8px', bottom: '8px', width: '2px', background: 'rgba(96, 165, 250, 0.34)' }} />
                  {drawerIncident.workflow.timeline.map((entry: TimelineEntry) => (
                    <div key={entry.id} style={{ display: 'flex', gap: '0.75rem', position: 'relative' }}>
                      <div style={{ width: '10px', height: '10px', borderRadius: '50%', background: '#60a5fa', border: '2px solid rgba(15,23,42,0.9)', marginTop: '0.3rem', position: 'relative', zIndex: 1 }} />
                      <div style={{ flex: 1, background: 'rgba(15, 23, 42, 0.7)', border: '1px solid rgba(148, 163, 184, 0.18)', borderRadius: '10px', padding: '0.55rem 0.65rem' }}>
                        <div style={{ color: '#f8fafc', fontWeight: 700, fontSize: '0.82rem', marginBottom: '0.2rem' }}>{entry.message}</div>
                        <div style={{ color: '#cbd5e1', fontSize: '0.68rem' }}>{new Date(entry.timestamp).toLocaleString()} {entry.analyst ? `• ${entry.analyst}` : ''}</div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {drawerIncident.workflow.notes.length > 0 && (
                <div style={{ background: 'rgba(15, 23, 42, 0.52)', border: '1px solid rgba(148, 163, 184, 0.16)', borderRadius: '12px', padding: '0.85rem' }}>
                  <div style={{ color: '#93c5fd', fontSize: '0.68rem', letterSpacing: '0.08em', textTransform: 'uppercase', marginBottom: '0.7rem' }}>Notes</div>
                  <div style={{ display: 'grid', gap: '0.7rem' }}>
                    {drawerIncident.workflow.notes
                      .slice()
                      .sort((a: IncidentNote, b: IncidentNote) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime())
                      .map((note: IncidentNote) => (
                        <div key={note.id} style={{ background: 'rgba(15, 23, 42, 0.7)', border: '1px solid rgba(148, 163, 184, 0.16)', borderRadius: '10px', padding: '0.65rem 0.7rem' }}>
                          <div style={{ display: 'flex', justifyContent: 'space-between', gap: '0.5rem', marginBottom: '0.35rem', color: '#cbd5e1', fontSize: '0.68rem' }}>
                            <span>{note.analyst}</span>
                            <span>{new Date(note.timestamp).toLocaleString()}</span>
                          </div>
                          <div style={{ color: '#e2e8f0', lineHeight: 1.6 }}>{renderMarkdownText(note.content)}</div>
                        </div>
                      ))}
                  </div>
                </div>
              )}
            </div>
          </aside>
        )}

        {selectedCase && (
          <aside style={{
            position: 'fixed',
            top: '1.25rem',
            right: '1.25rem',
            width: 'min(440px, calc(100vw - 2rem))',
            height: 'calc(100vh - 2.5rem)',
            background: 'rgba(15, 23, 42, 0.84)',
            border: '1px solid rgba(148, 163, 184, 0.22)',
            borderRadius: '22px',
            boxShadow: '0 35px 60px rgba(8, 15, 31, 0.5)',
            backdropFilter: 'blur(18px)',
            WebkitBackdropFilter: 'blur(18px)',
            zIndex: 45,
            padding: '1.1rem',
            overflowY: 'auto',
            animation: 'drawerSlideIn 0.25s ease'
          }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '1rem', marginBottom: '1rem' }}>
              <div>
                <div style={{ color: '#93c5fd', fontSize: '0.7rem', letterSpacing: '0.12em', textTransform: 'uppercase' }}>Case Drawer</div>
                <h3 style={{ margin: '0.3rem 0 0', fontSize: '1.2rem' }}>{selectedCase.id}</h3>
              </div>
              <button type="button" onClick={() => setSelectedCaseId(null)} style={{ width: '32px', height: '32px', borderRadius: '10px', border: '1px solid rgba(148, 163, 184, 0.2)', background: 'rgba(15, 23, 42, 0.7)', color: '#e2e8f0', cursor: 'pointer' }}>×</button>
            </div>

            <div style={{ display: 'grid', gap: '1rem' }}>
              <div style={{ background: 'rgba(15, 23, 42, 0.52)', border: '1px solid rgba(148, 163, 184, 0.16)', borderRadius: '12px', padding: '0.85rem' }}>
                <div style={{ color: '#93c5fd', fontSize: '0.68rem', letterSpacing: '0.08em', textTransform: 'uppercase', marginBottom: '0.45rem' }}>Linked Incident</div>
                <div style={{ color: '#f8fafc', fontWeight: 700 }}>{selectedCase.incident.eventType} · {selectedCase.incident.id}</div>
                <div style={{ color: '#cbd5e1', fontSize: '0.8rem', lineHeight: 1.5, marginTop: '0.35rem' }}>{selectedCase.incident.message}</div>
              </div>

              <div style={{ background: 'rgba(15, 23, 42, 0.52)', border: '1px solid rgba(148, 163, 184, 0.16)', borderRadius: '12px', padding: '0.85rem' }}>
                <div style={{ color: '#93c5fd', fontSize: '0.68rem', letterSpacing: '0.08em', textTransform: 'uppercase', marginBottom: '0.7rem' }}>Case Workflow</div>
                <div style={{ display: 'grid', gap: '0.7rem' }}>
                  <label style={{ color: '#cbd5e1', fontSize: '0.78rem' }}>Priority
                    <select value={selectedCase.priority} onChange={(event) => updateCase(selectedCase.id, { priority: event.target.value as CasePriority })} style={{ ...fieldStyle, marginTop: '0.35rem' }}>
                      {casePriorities.map((priority) => <option key={priority} value={priority}>{priority}</option>)}
                    </select>
                  </label>
                  <label style={{ color: '#cbd5e1', fontSize: '0.78rem' }}>Status
                    <select value={selectedCase.status} onChange={(event) => updateCaseStatus(event.target.value as CaseStatus)} style={{ ...fieldStyle, marginTop: '0.35rem' }}>
                      {caseStatuses.map((status) => <option key={status} value={status}>{status}</option>)}
                    </select>
                  </label>
                  <label style={{ color: '#cbd5e1', fontSize: '0.78rem' }}>Assigned Analyst
                    <select value={selectedCase.assignedAnalyst} onChange={(event) => updateCaseAssignment(event.target.value as AnalystName)} style={{ ...fieldStyle, marginTop: '0.35rem' }}>
                      {demoAnalysts.map((analyst) => <option key={analyst} value={analyst}>{analyst}</option>)}
                    </select>
                  </label>
                  <label style={{ color: '#cbd5e1', fontSize: '0.78rem' }}>SLA
                    <select value={selectedCase.sla} onChange={(event) => updateCase(selectedCase.id, { sla: event.target.value })} style={{ ...fieldStyle, marginTop: '0.35rem' }}>
                      {caseSlaOptions.map((sla) => <option key={sla} value={sla}>{sla}</option>)}
                    </select>
                  </label>
                </div>
              </div>

              <div style={{ background: 'rgba(15, 23, 42, 0.52)', border: '1px solid rgba(148, 163, 184, 0.16)', borderRadius: '12px', padding: '0.85rem' }}>
                <div style={{ color: '#93c5fd', fontSize: '0.68rem', letterSpacing: '0.08em', textTransform: 'uppercase', marginBottom: '0.45rem' }}>Case Notes</div>
                <textarea value={caseNoteDraft} onChange={(event) => setCaseNoteDraft(event.target.value)} placeholder="Add markdown notes..." style={{ ...fieldStyle, minHeight: '90px', resize: 'vertical' }} />
                <button type="button" onClick={addCaseNote} style={{ marginTop: '0.6rem', width: '100%', background: 'linear-gradient(135deg, #2563eb, #0ea5e9)', border: 'none', color: '#eff6ff', borderRadius: '12px', padding: '0.7rem 1rem', cursor: 'pointer', fontWeight: 700 }}>Add Note</button>
                {selectedCase.notes.length > 0 && <div style={{ display: 'grid', gap: '0.7rem', marginTop: '0.8rem' }}>
                  {selectedCase.notes.map((note) => <div key={note.id} style={{ background: 'rgba(15, 23, 42, 0.7)', border: '1px solid rgba(148, 163, 184, 0.16)', borderRadius: '10px', padding: '0.65rem 0.7rem' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', gap: '0.5rem', color: '#cbd5e1', fontSize: '0.68rem', marginBottom: '0.35rem' }}><span>{note.analyst}</span><span>{new Date(note.timestamp).toLocaleString()}</span></div>
                    <div style={{ color: '#e2e8f0', lineHeight: 1.6 }}>{renderMarkdownText(note.content)}</div>
                  </div>)}
                </div>}
              </div>

              <div style={{ background: 'rgba(15, 23, 42, 0.52)', border: '1px solid rgba(148, 163, 184, 0.16)', borderRadius: '12px', padding: '0.85rem' }}>
                <div style={{ color: '#93c5fd', fontSize: '0.68rem', letterSpacing: '0.08em', textTransform: 'uppercase', marginBottom: '0.7rem' }}>Timeline · Created {new Date(selectedCase.createdAt).toLocaleString()}</div>
                <div style={{ display: 'grid', gap: '0.8rem', position: 'relative', paddingLeft: '0.85rem' }}>
                  <div style={{ position: 'absolute', left: '4px', top: '8px', bottom: '8px', width: '2px', background: 'rgba(96, 165, 250, 0.34)' }} />
                  {selectedCase.timeline.map((entry) => <div key={entry.id} style={{ display: 'flex', gap: '0.75rem', position: 'relative' }}>
                    <div style={{ width: '10px', height: '10px', borderRadius: '50%', background: '#60a5fa', border: '2px solid rgba(15,23,42,0.9)', marginTop: '0.3rem', position: 'relative', zIndex: 1 }} />
                    <div style={{ flex: 1, background: 'rgba(15, 23, 42, 0.7)', border: '1px solid rgba(148, 163, 184, 0.18)', borderRadius: '10px', padding: '0.55rem 0.65rem' }}>
                      <div style={{ color: '#f8fafc', fontWeight: 700, fontSize: '0.82rem', marginBottom: '0.2rem' }}>{entry.message}</div>
                      <div style={{ color: '#cbd5e1', fontSize: '0.68rem' }}>{new Date(entry.timestamp).toLocaleString()} {entry.analyst ? `· ${entry.analyst}` : ''}</div>
                    </div>
                  </div>)}
                </div>
              </div>
            </div>
          </aside>
        )}
      </div>
    </div>
  );
}

export default App;
