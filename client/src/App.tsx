import { useEffect, useRef, useState } from 'react';
import { APP_NAME, HealthStatus, AuthResponse, type UserRole } from '@sentinel/shared';
import Login from './Login';
import KPIGrid from './components/KPIGrid';
import IncidentPanel from './components/IncidentPanel';
import EventTable from './components/EventTable';
import SearchBar from './components/SearchBar';
import RulesPage, { defaultRules } from './components/RulesPage';
import ThreatIntelPage, { defaultIocs } from './components/ThreatIntelPage';
import ReportsPage from './components/ReportsPage';
import EmployeePortal, { type EmployeeTicket, type TicketStatus } from './components/EmployeePortal';
import { LogEntry, Severity, SeverityFilter } from './types/log';
import type { DetectionRule } from './types/rule';
import type { IOC } from './types/ioc';
import { evaluateDetectionRules } from './utils/detectionEngine';
import { evaluateIOCs } from './utils/iocEngine';
import { getMitreMapping } from './utils/mitre';

type PageName = 'Dashboard' | 'Incidents' | 'Cases' | 'Assets' | 'Users' | 'Notifications' | 'Events' | 'Rules' | 'Threat Intel' | 'Reports' | 'Analyst';
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

type CaseStatus = 'Reported' | 'New' | 'Triage' | 'Investigating' | 'Contained' | 'Recovery' | 'Resolved';
type CaseSource = 'SOC Console' | 'Employee Portal';
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
  source: CaseSource;
  timeline: CaseTimelineEntry[];
  notes: CaseNote[];
};

type NotificationKind = 'Incident' | 'Case' | 'IOC' | 'Employee' | 'System';
type NotificationFilter = 'All' | NotificationKind;
type NotificationRecord = {
  id: string;
  kind: NotificationKind;
  title: string;
  message: string;
  createdAt: string;
  read: boolean;
  relatedId?: string;
};

type AssetStatus = 'Active' | 'Monitoring' | 'Isolated' | 'Offline';
type AssetType = 'Workstation' | 'Server' | 'Laptop' | 'Firewall' | 'Kubernetes' | 'VM' | 'Database' | 'Endpoint';
type AssetCriticality = 'Low' | 'Medium' | 'High' | 'Critical';
type AssetNote = {
  id: string;
  timestamp: string;
  analyst: string;
  content: string;
};
type AssetRecord = {
  id: string;
  hostname: string;
  ip: string;
  type: AssetType;
  owner: string;
  department: string;
  status: AssetStatus;
  criticality: AssetCriticality;
  riskScore: number;
  lastSeen: string;
  notes: AssetNote[];
};

type UserStatus = 'Active' | 'Monitoring' | 'Restricted' | 'Offboarded';
type UserNote = {
  id: string;
  timestamp: string;
  analyst: string;
  content: string;
};
type UserRecord = {
  id: string;
  name: string;
  email: string;
  department: string;
  role: string;
  devices: string[];
  status: UserStatus;
  riskScore: number;
  lastLogin: string;
  notes: UserNote[];
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
  triggeredByRule?: {
    name: string;
    mitreTechnique: string;
    triggerTimestamp: string;
  };
  iocMatches?: {
    value: string;
    threatFamily: string;
  }[];
};

type DetectedIncident = {
  log: LogEntry;
  ruleName?: string;
  mitreTechnique?: string;
  triggerTimestamp: string;
  iocMatches?: {
    value: string;
    threatFamily: string;
  }[];
};

const normaliseRole = (role?: string): UserRole => (role === 'employee' ? 'employee' : role === 'analyst' ? 'analyst' : 'admin');
const roleDisplayMap: Record<UserRole, string> = { admin: 'Admin', analyst: 'Analyst', employee: 'Employee' };
const rolePageAccess: Record<UserRole, PageName[]> = {
  admin: ['Dashboard', 'Incidents', 'Events', 'Rules', 'Threat Intel', 'Assets', 'Users', 'Reports', 'Cases', 'Notifications'],
  analyst: ['Dashboard', 'Incidents', 'Events', 'Assets', 'Cases', 'Reports', 'Notifications'],
  employee: []
};
const getDefaultPageForRole = (role: UserRole): PageName => role === 'admin' ? 'Dashboard' : role === 'analyst' ? 'Dashboard' : 'Dashboard';
const sourceOptions = ['Auth Gateway', 'Firewall', 'Endpoint Agent', 'VPN', 'SIEM Correlation', 'Identity Provider', 'CloudTrail', 'Web Proxy', 'Kubernetes', 'Email Gateway'];
const eventTypeOptions = ['Failed Login', 'Malware Detection', 'Port Scan', 'Brute Force', 'Critical Alert', 'Privilege Escalation', 'Suspicious Process', 'Data Exfiltration', 'Lateral Movement', 'Shadow IT'];
const severityOptions: Severity[] = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
const workflowStatuses: WorkflowStatus[] = ['New', 'Investigating', 'Contained', 'Resolved'];
const caseStatuses: CaseStatus[] = ['Reported', 'New', 'Triage', 'Investigating', 'Contained', 'Recovery', 'Resolved'];
const casePriorities: CasePriority[] = ['P1', 'P2', 'P3', 'P4'];
const caseSlaOptions = ['4 hours', '8 hours', '24 hours', '72 hours'];
const demoAnalysts: AnalystName[] = ['Tunar', 'Sarah', 'Michael', 'Emma'];
const assetStatuses: AssetStatus[] = ['Active', 'Monitoring', 'Isolated', 'Offline'];
const assetTypes: AssetType[] = ['Workstation', 'Server', 'Laptop', 'Firewall', 'Kubernetes', 'VM', 'Database', 'Endpoint'];
const assetCriticalities: AssetCriticality[] = ['Low', 'Medium', 'High', 'Critical'];
const defaultAssets: AssetRecord[] = [
  { id: 'asset-01', hostname: 'FIN-WKS-06', ip: '172.16.10.8', type: 'Workstation', owner: 'M. Brown', department: 'Finance', status: 'Monitoring', criticality: 'High', riskScore: 82, lastSeen: '2026-08-31T14:10:00.000Z', notes: [] },
  { id: 'asset-02', hostname: 'FILE-SVR-12', ip: '172.20.8.11', type: 'Server', owner: 'S. Patel', department: 'Operations', status: 'Isolated', criticality: 'Critical', riskScore: 94, lastSeen: '2026-08-31T13:58:00.000Z', notes: [] },
  { id: 'asset-03', hostname: 'DMZ-FW-01', ip: '10.12.8.1', type: 'Firewall', owner: 'N. Reed', department: 'Network', status: 'Active', criticality: 'Critical', riskScore: 88, lastSeen: '2026-08-31T14:14:00.000Z', notes: [] },
  { id: 'asset-04', hostname: 'VPN-GW-01', ip: '10.10.44.18', type: 'Firewall', owner: 'R. Chen', department: 'Identity', status: 'Monitoring', criticality: 'High', riskScore: 79, lastSeen: '2026-08-31T13:49:00.000Z', notes: [] },
  { id: 'asset-05', hostname: 'AD-01', ip: '10.30.50.5', type: 'Server', owner: 'A. Singh', department: 'IT', status: 'Active', criticality: 'Critical', riskScore: 91, lastSeen: '2026-08-31T13:40:00.000Z', notes: [] },
  { id: 'asset-06', hostname: 'ENG-LAP-17', ip: '10.64.7.8', type: 'Laptop', owner: 'N. Garcia', department: 'Engineering', status: 'Monitoring', criticality: 'Medium', riskScore: 58, lastSeen: '2026-08-31T12:50:00.000Z', notes: [] },
  { id: 'asset-07', hostname: 'SQL-DB-01', ip: '10.90.14.22', type: 'Database', owner: 'L. Park', department: 'Data', status: 'Active', criticality: 'Critical', riskScore: 90, lastSeen: '2026-08-31T14:02:00.000Z', notes: [] },
  { id: 'asset-08', hostname: 'EKS-CLUSTER-01', ip: '10.9.13.31', type: 'Kubernetes', owner: 'K. Gomez', department: 'Cloud', status: 'Monitoring', criticality: 'Critical', riskScore: 92, lastSeen: '2026-08-31T13:47:00.000Z', notes: [] },
  { id: 'asset-09', hostname: 'FIN-LAP-22', ip: '10.28.45.15', type: 'Laptop', owner: 'S. Green', department: 'Finance', status: 'Monitoring', criticality: 'High', riskScore: 71, lastSeen: '2026-08-31T13:15:00.000Z', notes: [] },
  { id: 'asset-10', hostname: 'HR-PC-04', ip: '10.23.9.44', type: 'Workstation', owner: 'P. Nunez', department: 'Human Resources', status: 'Active', criticality: 'Medium', riskScore: 46, lastSeen: '2026-08-31T12:42:00.000Z', notes: [] },
  { id: 'asset-11', hostname: 'MAIL-GW-03', ip: '10.3.19.12', type: 'Endpoint', owner: 'D. Roberts', department: 'IT', status: 'Active', criticality: 'High', riskScore: 72, lastSeen: '2026-08-31T13:32:00.000Z', notes: [] },
  { id: 'asset-12', hostname: 'SALES-LAP-12', ip: '10.14.7.19', type: 'Laptop', owner: 'T. Kelly', department: 'Sales', status: 'Isolated', criticality: 'High', riskScore: 77, lastSeen: '2026-08-31T13:08:00.000Z', notes: [] },
  { id: 'asset-13', hostname: 'WEB-APP-01', ip: '203.0.113.84', type: 'Server', owner: 'C. Diaz', department: 'Web', status: 'Monitoring', criticality: 'Critical', riskScore: 96, lastSeen: '2026-08-31T13:11:00.000Z', notes: [] },
  { id: 'asset-14', hostname: 'SVR-DB-02', ip: '10.180.22.4', type: 'Database', owner: 'R. Flores', department: 'Data', status: 'Offline', criticality: 'High', riskScore: 65, lastSeen: '2026-08-31T12:20:00.000Z', notes: [] },
  { id: 'asset-15', hostname: 'WORKSTATION-17', ip: '172.16.55.14', type: 'Workstation', owner: 'R. Hughes', department: 'Operations', status: 'Isolated', criticality: 'Critical', riskScore: 88, lastSeen: '2026-08-31T13:53:00.000Z', notes: [] }
];
const defaultUsers: UserRecord[] = [
  { id: 'usr-01', name: 'Alicia Morgan', email: 'alicia.morgan@sentinel.local', department: 'Security Operations', role: 'Analyst', devices: ['LAP-ALICIA-01', 'PHONE-ALICIA'], status: 'Active', riskScore: 24, lastLogin: '2026-08-31T14:05:00.000Z', notes: [] },
  { id: 'usr-02', name: 'Marcus Lee', email: 'marcus.lee@sentinel.local', department: 'Finance', role: 'Finance Analyst', devices: ['FIN-WKS-06', 'MOBILE-ML-2'], status: 'Monitoring', riskScore: 46, lastLogin: '2026-08-31T13:20:00.000Z', notes: [] },
  { id: 'usr-03', name: 'Priya Sharma', email: 'priya.sharma@sentinel.local', department: 'IT', role: 'Systems Engineer', devices: ['AD-01', 'LAP-PRIYA-14'], status: 'Active', riskScore: 31, lastLogin: '2026-08-31T13:54:00.000Z', notes: [] },
  { id: 'usr-04', name: 'Daniel Brooks', email: 'daniel.brooks@sentinel.local', department: 'Engineering', role: 'Platform Engineer', devices: ['ENG-LAP-17', 'LAP-DB-09'], status: 'Active', riskScore: 38, lastLogin: '2026-08-31T12:48:00.000Z', notes: [] },
  { id: 'usr-05', name: 'Sophia Nguyen', email: 'sophia.nguyen@sentinel.local', department: 'Human Resources', role: 'HR Manager', devices: ['HR-PC-04', 'IPHONE-SN'], status: 'Monitoring', riskScore: 44, lastLogin: '2026-08-31T12:31:00.000Z', notes: [] },
  { id: 'usr-06', name: 'Rafael Torres', email: 'rafael.torres@sentinel.local', department: 'Operations', role: 'Operations Lead', devices: ['FILE-SVR-12', 'LAP-RAFAEL-07'], status: 'Active', riskScore: 53, lastLogin: '2026-08-31T13:41:00.000Z', notes: [] },
  { id: 'usr-07', name: 'Naomi Reed', email: 'naomi.reed@sentinel.local', department: 'Network', role: 'Network Engineer', devices: ['DMZ-FW-01', 'LAP-NAOMI-02'], status: 'Active', riskScore: 34, lastLogin: '2026-08-31T13:48:00.000Z', notes: [] },
  { id: 'usr-08', name: 'Kenji Sato', email: 'kenji.sato@sentinel.local', department: 'Cloud', role: 'Cloud Architect', devices: ['EKS-CLUSTER-01', 'LAP-KENJI-11'], status: 'Restricted', riskScore: 68, lastLogin: '2026-08-31T11:50:00.000Z', notes: [] },
  { id: 'usr-09', name: 'Samantha Green', email: 'samantha.green@sentinel.local', department: 'Finance', role: 'Accountant', devices: ['FIN-LAP-22', 'PHONE-SG-3'], status: 'Monitoring', riskScore: 57, lastLogin: '2026-08-31T13:02:00.000Z', notes: [] },
  { id: 'usr-10', name: 'Darius Roberts', email: 'darius.roberts@sentinel.local', department: 'IT', role: 'Endpoint Administrator', devices: ['MAIL-GW-03', 'LAP-DARIUS-06'], status: 'Active', riskScore: 30, lastLogin: '2026-08-31T14:07:00.000Z', notes: [] },
  { id: 'usr-11', name: 'Tanya Kelly', email: 'tanya.kelly@sentinel.local', department: 'Sales', role: 'Account Executive', devices: ['SALES-LAP-12', 'IPHONE-TK'], status: 'Restricted', riskScore: 62, lastLogin: '2026-08-31T12:18:00.000Z', notes: [] },
  { id: 'usr-12', name: 'Carlos Diaz', email: 'carlos.diaz@sentinel.local', department: 'Web', role: 'Web Engineer', devices: ['WEB-APP-01', 'LAP-CARLOS-05'], status: 'Active', riskScore: 40, lastLogin: '2026-08-31T13:11:00.000Z', notes: [] },
  { id: 'usr-13', name: 'Rosa Flores', email: 'rosa.flores@sentinel.local', department: 'Data', role: 'Database Administrator', devices: ['SVR-DB-02', 'LAP-ROSA-13'], status: 'Monitoring', riskScore: 55, lastLogin: '2026-08-31T12:39:00.000Z', notes: [] },
  { id: 'usr-14', name: 'Ryan Hughes', email: 'ryan.hughes@sentinel.local', department: 'Operations', role: 'Field Technician', devices: ['WORKSTATION-17', 'LAP-RYAN-04'], status: 'Restricted', riskScore: 73, lastLogin: '2026-08-31T11:42:00.000Z', notes: [] },
  { id: 'usr-15', name: 'Lina Park', email: 'lina.park@sentinel.local', department: 'Data', role: 'Data Analyst', devices: ['SQL-DB-01', 'LAP-LINA-10'], status: 'Active', riskScore: 33, lastLogin: '2026-08-31T13:36:00.000Z', notes: [] },
  { id: 'usr-16', name: 'Mason Brown', email: 'mason.brown@sentinel.local', department: 'Finance', role: 'Controller', devices: ['FIN-WKS-06', 'LAP-MASON-08'], status: 'Monitoring', riskScore: 52, lastLogin: '2026-08-31T13:06:00.000Z', notes: [] },
  { id: 'usr-17', name: 'Ava Patel', email: 'ava.patel@sentinel.local', department: 'Operations', role: 'Security Analyst', devices: ['FILE-SVR-12', 'PHONE-AVA'], status: 'Active', riskScore: 29, lastLogin: '2026-08-31T13:50:00.000Z', notes: [] },
  { id: 'usr-18', name: 'Jonathan Price', email: 'jonathan.price@sentinel.local', department: 'Security Operations', role: 'Incident Responder', devices: ['LAP-JONATHAN-03', 'PHONE-JP'], status: 'Active', riskScore: 27, lastLogin: '2026-08-31T14:11:00.000Z', notes: [] },
  { id: 'usr-19', name: 'Emma Chen', email: 'emma.chen@sentinel.local', department: 'Identity', role: 'IAM Engineer', devices: ['VPN-GW-01', 'LAP-EMMA-15'], status: 'Monitoring', riskScore: 49, lastLogin: '2026-08-31T13:23:00.000Z', notes: [] },
  { id: 'usr-20', name: 'Oliver Grant', email: 'oliver.grant@sentinel.local', department: 'Legal', role: 'Legal Counsel', devices: ['LAP-OLIVER-01', 'PHONE-OG'], status: 'Offboarded', riskScore: 76, lastLogin: '2026-08-30T17:48:00.000Z', notes: [] }
];
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
  const [portalMode, setPortalMode] = useState<'soc' | 'employee'>('soc');
  const [composer, setComposer] = useState<EventComposerState>(defaultComposerState);
  const [composerError, setComposerError] = useState('');
  const [composerSuccess, setComposerSuccess] = useState('');
  const [chartHoverIndex, setChartHoverIndex] = useState<number | null>(null);
  const [templateCategory, setTemplateCategory] = useState<'All' | string>('All');
  const [sourceMenuOpen, setSourceMenuOpen] = useState(false);
  const [selectedIncidentDetail, setSelectedIncidentDetail] = useState<IncidentDetail | null>(null);
  const [incidentNoteDraft, setIncidentNoteDraft] = useState('');
  const [notifications, setNotifications] = useState<NotificationRecord[]>(() => {
    try {
      const savedNotifications = localStorage.getItem('sentinel-notifications');
      return savedNotifications ? JSON.parse(savedNotifications) as NotificationRecord[] : [];
    } catch {
      return [];
    }
  });
  const [notificationsOpen, setNotificationsOpen] = useState(false);
  const [toastNotifications, setToastNotifications] = useState<NotificationRecord[]>([]);
  const [notificationFilter, setNotificationFilter] = useState<NotificationFilter>('All');
  const [now, setNow] = useState(Date.now());
  const [rules, setRules] = useState<DetectionRule[]>(() => {
    try {
      const savedRules = localStorage.getItem('sentinel-detection-rules');
      const parsedRules = savedRules ? JSON.parse(savedRules) as DetectionRule[] : defaultRules;
      return parsedRules.map((rule) => ({ ...rule, hitCount: rule.hitCount ?? 0 }));
    } catch {
      return defaultRules;
    }
  });
  const [iocs, setIOCs] = useState<IOC[]>(() => {
    try {
      const savedIOCs = localStorage.getItem('sentinel-iocs');
      return savedIOCs ? JSON.parse(savedIOCs) as IOC[] : defaultIocs;
    } catch {
      return defaultIocs;
    }
  });
  const [detectedIncidents, setDetectedIncidents] = useState<DetectedIncident[]>([]);
  const [ruleHitEvents, setRuleHitEvents] = useState<{ ruleId: string; timestamp: string }[]>([]);
  const [cases, setCases] = useState<CaseRecord[]>(() => {
    try {
      const savedCases = localStorage.getItem('sentinel-cases');
      return savedCases ? JSON.parse(savedCases) as CaseRecord[] : [];
    } catch {
      return [];
    }
  });
  const [assets, setAssets] = useState<AssetRecord[]>(() => {
    try {
      const savedAssets = localStorage.getItem('sentinel-assets');
      return savedAssets ? JSON.parse(savedAssets) as AssetRecord[] : defaultAssets;
    } catch {
      return defaultAssets;
    }
  });
  const [users, setUsers] = useState<UserRecord[]>(() => {
    try {
      const savedUsers = localStorage.getItem('sentinel-users');
      return savedUsers ? JSON.parse(savedUsers) as UserRecord[] : defaultUsers;
    } catch {
      return defaultUsers;
    }
  });
  const [employeeTickets, setEmployeeTickets] = useState<EmployeeTicket[]>(() => {
    try {
      const savedTickets = localStorage.getItem('sentinel-employee-tickets');
      return savedTickets ? JSON.parse(savedTickets) as EmployeeTicket[] : [];
    } catch {
      return [];
    }
  });
  const [selectedCaseId, setSelectedCaseId] = useState<string | null>(null);
  const [selectedAssetId, setSelectedAssetId] = useState<string | null>(null);
  const [selectedUserId, setSelectedUserId] = useState<string | null>(null);
  const currentUserRole = auth ? normaliseRole(auth.user.role) : 'admin';
  const currentUserRoleLabel = roleDisplayMap[currentUserRole];
  const canAccessPage = (page: PageName) => currentUserRole === 'employee' ? page === 'Dashboard' && portalMode === 'employee' : rolePageAccess[currentUserRole].includes(page);
  const canManageRules = currentUserRole === 'admin';
  const canManageUsers = currentUserRole === 'admin';
  const canEditCases = currentUserRole === 'admin' || currentUserRole === 'analyst';
  const [caseNoteDraft, setCaseNoteDraft] = useState('');
  const [assetNoteDraft, setAssetNoteDraft] = useState('');
  const [userNoteDraft, setUserNoteDraft] = useState('');
  const [assetSearch, setAssetSearch] = useState('');
  const [userSearch, setUserSearch] = useState('');
  const [userStatusFilter, setUserStatusFilter] = useState<'All' | UserStatus>('All');
  const [userDepartmentFilter, setUserDepartmentFilter] = useState<'All' | string>('All');
  const [userRoleFilter, setUserRoleFilter] = useState<'All' | string>('All');
  const [assetStatusFilter, setAssetStatusFilter] = useState<'All' | AssetStatus>('All');
  const [assetTypeFilter, setAssetTypeFilter] = useState<'All' | AssetType>('All');
  const [assetDepartmentFilter, setAssetDepartmentFilter] = useState<'All' | string>('All');
  const [assetCriticalityFilter, setAssetCriticalityFilter] = useState<'All' | AssetCriticality>('All');
  const [responseChecklist, setResponseChecklist] = useState<Record<string, boolean>>({});
  const [expandedEvidenceId, setExpandedEvidenceId] = useState<string | null>(null);
  const sourceMenuRef = useRef<HTMLDivElement | null>(null);
  const rulesRef = useRef(rules);
  const iocsRef = useRef(iocs);
  const logsRef = useRef(logs);
  const evaluatedEventIdsRef = useRef(new Set<string>());

  useEffect(() => {
    rulesRef.current = rules;
    localStorage.setItem('sentinel-detection-rules', JSON.stringify(rules));
  }, [rules]);

  useEffect(() => {
    iocsRef.current = iocs;
    localStorage.setItem('sentinel-iocs', JSON.stringify(iocs));
  }, [iocs]);

  useEffect(() => {
    logsRef.current = logs;
  }, [logs]);

  useEffect(() => {
    localStorage.setItem('sentinel-cases', JSON.stringify(cases));
  }, [cases]);

  useEffect(() => {
    localStorage.setItem('sentinel-notifications', JSON.stringify(notifications));
  }, [notifications]);

  useEffect(() => {
    localStorage.setItem('sentinel-assets', JSON.stringify(assets));
  }, [assets]);

  useEffect(() => {
    localStorage.setItem('sentinel-users', JSON.stringify(users));
  }, [users]);

  useEffect(() => {
    localStorage.setItem('sentinel-employee-tickets', JSON.stringify(employeeTickets));
  }, [employeeTickets]);

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

  const evaluateIncomingEvent = (incoming: LogEntry, history: LogEntry[]) => {
    if (evaluatedEventIdsRef.current.has(incoming.id)) return;
    evaluatedEventIdsRef.current.add(incoming.id);
    const ruleMatches = evaluateDetectionRules(incoming, history, rulesRef.current);
    const iocMatches = evaluateIOCs(incoming, iocsRef.current);
    if (ruleMatches.length === 0 && iocMatches.length === 0) return;

    const ruleIncidents = ruleMatches.map(({ rule, triggerTimestamp, eventCount }) => ({
      log: {
        id: `detected-${rule.id}-${incoming.id}`,
        timestamp: triggerTimestamp,
        source: incoming.source,
        eventType: incoming.eventType,
        severity: 'CRITICAL' as const,
        message: `Detection rule "${rule.name}" matched ${eventCount} ${incoming.eventType} event${eventCount === 1 ? '' : 's'} within ${rule.timeWindowMinutes} minute${rule.timeWindowMinutes === 1 ? '' : 's'}.`
      },
      ruleName: rule.name,
      mitreTechnique: rule.mitreTechnique,
      triggerTimestamp
    }));
    const iocIncidents = iocMatches.map(({ ioc, triggerTimestamp }) => ({
      log: {
        id: `detected-ioc-${ioc.id}-${incoming.id}`,
        timestamp: triggerTimestamp,
        source: incoming.source,
        eventType: incoming.eventType,
        severity: 'CRITICAL' as const,
        message: `IOC match detected for ${ioc.value} (${ioc.threatFamily}).`
      },
      triggerTimestamp,
      iocMatches: [{ value: ioc.value, threatFamily: ioc.threatFamily }]
    }));
    const createdIncidents = [...ruleIncidents, ...iocIncidents];

    if (createdIncidents.length > 0) {
      addNotification('Incident', 'New Critical Incident', `${incoming.eventType} from ${incoming.source} triggered a critical incident workflow.`, incoming.id);
    }

    if (ruleMatches.length > 0) {
      ruleMatches.forEach(({ rule }) => {
        addNotification('Incident', 'Detection Rule Trigger', `${rule.name} matched ${incoming.eventType} from ${incoming.source}.`, incoming.id);
      });
    }

    if (iocMatches.length > 0) {
      iocMatches.forEach(({ ioc }) => {
        addNotification('IOC', 'IOC Match', `${ioc.threatFamily} IOC ${ioc.value} matched ${incoming.source}.`, incoming.id);
      });
    }

    setDetectedIncidents((current) => {
      const existingIds = new Set(current.map((incident) => incident.log.id));
      return [...createdIncidents.filter((incident) => !existingIds.has(incident.log.id)), ...current];
    });
    setRules((current) => current.map((rule) => {
      const match = ruleMatches.find(({ rule: matchedRule }) => matchedRule.id === rule.id);
      return match ? { ...rule, hitCount: (rule.hitCount ?? 0) + 1, lastTriggered: match.triggerTimestamp } : rule;
    }));
    setRuleHitEvents((current) => [
      ...ruleMatches.map(({ rule, triggerTimestamp }) => ({ ruleId: rule.id, timestamp: triggerTimestamp })),
      ...current
    ]);
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
  const detectedIncidentLogs = detectedIncidents.map((incident) => incident.log);
  const filteredLogs = filterLogs(logs);
  const filteredCriticalLogs = filterLogs([...incidentLogs, ...detectedIncidentLogs]);

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
    const timer = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(timer);
  }, []);

  useEffect(() => {
    const token = localStorage.getItem('token');
    if (token) {
      fetchHealth(token);
      fetchLogs(token);
      const storedRole = normaliseRole(localStorage.getItem('sentinel-role') ?? undefined);
      setAuth({
        token,
        user: { id: 'cached', email: 'cached@local', role: storedRole }
      });
    }
  }, []);

  useEffect(() => {
    if (!auth) return;
    localStorage.setItem('sentinel-role', auth.user.role);
    if (auth.user.role === 'employee') {
      setPortalMode('employee');
    }
    if (!canAccessPage(activePage)) {
      setActivePage(getDefaultPageForRole(currentUserRole));
    }
  }, [auth, activePage, currentUserRole]);

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
        evaluateIncomingEvent(incoming, logsRef.current);
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

  const addNotification = (kind: NotificationKind, title: string, message: string, relatedId?: string) => {
    const nextNotification: NotificationRecord = {
      id: `${kind}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
      kind,
      title,
      message,
      createdAt: new Date().toISOString(),
      read: false,
      relatedId
    };

    setNotifications((current) => [nextNotification, ...current]);
    setToastNotifications((current) => [nextNotification, ...current].slice(0, 3));
    return nextNotification;
  };

  const markNotificationRead = (id: string) => {
    setNotifications((current) => current.map((item) => item.id === id ? { ...item, read: true } : item));
  };

  const markAllNotificationsRead = () => {
    setNotifications((current) => current.map((item) => ({ ...item, read: true })));
  };

  const unreadNotifications = notifications.filter((item) => !item.read);
  const unreadCount = unreadNotifications.length;

  function handleEmployeeTicketSubmit(ticket: EmployeeTicket) {
    const createdAt = new Date().toISOString();
    const caseId = `CASE-${createdAt.slice(0, 10).replace(/-/g, '')}-${Math.random().toString(36).slice(2, 7).toUpperCase()}`;
    const employeeTicket: EmployeeTicket = {
      ...ticket,
      caseId,
      status: 'Open',
      assignedAnalyst: 'Pending triage'
    };

    const incident: LogEntry = {
      id: `employee-${ticket.id}`,
      timestamp: createdAt,
      source: 'Employee Portal',
      eventType: ticket.incidentType,
      severity: ticket.priority === 'P1' ? 'CRITICAL' : ticket.priority === 'P2' ? 'HIGH' : ticket.priority === 'P3' ? 'MEDIUM' : 'LOW',
      message: `${ticket.department} employee report: ${ticket.description} | Device: ${ticket.device}`
    };

    const nextCase: CaseRecord = {
      id: caseId,
      incidentId: incident.id,
      incident,
      priority: ticket.priority,
      status: 'Reported',
      assignedAnalyst: 'Tunar',
      sla: ticket.priority === 'P1' ? '4 hours' : ticket.priority === 'P2' ? '8 hours' : '24 hours',
      createdAt,
      source: 'Employee Portal',
      timeline: [{
        id: `${caseId}-reported`,
        type: 'created',
        timestamp: createdAt,
        message: 'Employee-submitted case reported to SOC',
        analyst: 'Employee Portal'
      }],
      notes: []
    };

    setEmployeeTickets((current) => [employeeTicket, ...current]);
    setCases((current) => [nextCase, ...current]);
    addNotification('Employee', 'Employee Ticket Submitted', `Ticket ${employeeTicket.id} was submitted for ${ticket.incidentType}.`, employeeTicket.id);
    setSelectedCaseId(caseId);
    setActivePage('Cases');
  }

  useEffect(() => {
    if (toastNotifications.length === 0) return;

    const timers = toastNotifications.map((toast) => window.setTimeout(() => {
      setToastNotifications((current) => current.filter((item) => item.id !== toast.id));
    }, 5000));

    return () => {
      timers.forEach((timer) => window.clearTimeout(timer));
    };
  }, [toastNotifications]);

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

  const selectedWorkflow = selectedIncidentDetail
    ? {
        status: selectedIncidentDetail.status,
        assignedAnalyst: selectedIncidentDetail.assignedAnalyst,
        notes: selectedIncidentDetail.notes ?? [],
        timeline: selectedIncidentDetail.timeline ?? []
      }
    : null;

  const drawerIncident = selectedIncidentDetail && selectedWorkflow ? {
    incident: selectedIncidentDetail,
    workflow: selectedWorkflow
  } : null;

  const drawerMitre = drawerIncident && drawerIncident.incident.eventType
    ? getMitreMapping(drawerIncident.incident.eventType)
    : { id: 'N/A', tactic: 'Unknown', color: '#64748b' };
  const selectedCase = cases.find((item) => item.id === selectedCaseId) ?? null;
  const getSlaWindowMs = (priority: CasePriority) => {
    switch (priority) {
      case 'P1': return 15 * 60 * 1000;
      case 'P2': return 60 * 60 * 1000;
      case 'P3': return 4 * 60 * 60 * 1000;
      case 'P4': return 24 * 60 * 60 * 1000;
      default: return 4 * 60 * 60 * 1000;
    }
  };

  const getCaseSlaStatus = (item: CaseRecord) => {
    const totalMs = getSlaWindowMs(item.priority);
    const deadline = new Date(item.createdAt).getTime() + totalMs;
    const remainingMs = deadline - now;

    if (remainingMs <= 0) {
      return {
        label: 'Breached',
        remainingMs,
        severity: 'Red',
        color: '#ef4444',
        remainingText: 'Breached'
      };
    }

    const remainingSeconds = Math.max(0, Math.floor(remainingMs / 1000));
    const hours = Math.floor(remainingSeconds / 3600);
    const minutes = Math.floor((remainingSeconds % 3600) / 60);
    const seconds = remainingSeconds % 60;
    const state = remainingMs <= totalMs * 0.25 ? 'Amber' : 'Green';

    return {
      label: state === 'Amber' ? 'Warning' : 'Healthy',
      remainingMs,
      severity: state,
      color: state === 'Amber' ? '#fbbf24' : '#22c55e',
      remainingText: `${hours}h ${minutes}m ${seconds}s`
    };
  };

  const selectedCaseSla = selectedCase ? getCaseSlaStatus(selectedCase) : null;
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

  const caseChecklistItems = ['Isolate Host', 'Reset Credentials', 'Block Source IP', 'Notify User', 'Collect Forensic Evidence'];
  const caseChecklistKey = selectedCase ? `sentinel-case-checklist-${selectedCase.id}` : '';

  useEffect(() => {
    if (!selectedCase) return;

    try {
      const savedChecklist = localStorage.getItem(caseChecklistKey);
      setResponseChecklist(savedChecklist ? JSON.parse(savedChecklist) as Record<string, boolean> : {});
    } catch {
      setResponseChecklist({});
    }
  }, [caseChecklistKey, selectedCase?.id]);

  useEffect(() => {
    if (!selectedCase) return;
    localStorage.setItem(caseChecklistKey, JSON.stringify(responseChecklist));
  }, [caseChecklistKey, responseChecklist, selectedCase?.id]);

  const caseEvidenceLogs = selectedCase ? (() => {
    const caseTokens = new Set<string>();
    const candidateText = [selectedCase.incident.message ?? '', selectedCase.incident.source ?? '', selectedCase.incident.eventType ?? '']
      .join(' ')
      .toLowerCase();

    for (const match of candidateText.matchAll(/(?:source ip|ip|asset|endpoint|username|user|device):\s*([^|\n]+)/gi)) {
      const token = match[1].trim().toLowerCase();
      if (token) caseTokens.add(token);
    }

    const related = logs.filter((log) => {
      if (log.id === selectedCase.incidentId) return true;

      const haystack = [log.message, log.source, log.eventType].join(' ').toLowerCase();
      const candidates = Array.from(haystack.matchAll(/(?:source ip|ip|asset|endpoint|username|user|device):\s*([^|\n]+)/gi), (match) => match[1].trim().toLowerCase());
      const exactMatch = candidates.some((candidate) => caseTokens.has(candidate));
      const sourceMatch = log.source.toLowerCase() === selectedCase.incident.source?.toLowerCase();
      const eventMatch = log.eventType.toLowerCase() === selectedCase.incident.eventType?.toLowerCase();
      return exactMatch || sourceMatch || eventMatch;
    });

    return related.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());
  })() : [];

  const attackTimeline = selectedCase ? (() => {
    const items = [
      ...selectedCase.timeline.map((entry) => ({
        id: entry.id,
        timestamp: entry.timestamp,
        type: entry.type,
        label: entry.message,
        detail: entry.analyst ? `Analyst: ${entry.analyst}` : 'System event'
      })),
      ...selectedCase.notes.map((note) => ({
        id: note.id,
        timestamp: note.timestamp,
        type: 'note',
        label: `Note: ${note.content}`,
        detail: `Analyst: ${note.analyst}`
      })),
      ...caseEvidenceLogs.map((log) => ({
        id: log.id,
        timestamp: log.timestamp,
        type: 'log',
        label: `${log.eventType} · ${log.source}`,
        detail: log.message
      }))
    ];

    return items.sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());
  })() : [];

  const mitreProfile = selectedCase ? getMitreMapping(selectedCase.incident.eventType ?? 'Critical Alert') : { id: 'N/A', tactic: 'Unmapped', color: '#475569' };
  const mitreRecommendations: Record<string, string> = {
    T1110: 'Prioritize credential reset, MFA verification, and failed-login review across impacted accounts.',
    T1204: 'Isolate the endpoint, inspect execution chain, and block the execution path until malware analysis is complete.',
    T1046: 'Validate network segmentation and quickly review any host-to-host discovery activity that was observed.',
    T1486: 'Focus on rapid containment, backups validation, and impact assessment for affected assets.'
  };
  const caseRiskScore = selectedCase ? (() => {
    const severityScore = selectedCase.incident.severity === 'CRITICAL' ? 70 : selectedCase.incident.severity === 'HIGH' ? 55 : selectedCase.incident.severity === 'MEDIUM' ? 35 : 20;
    const iocScore = detectedIncidents.some((incident) => incident.log.id === selectedCase.incidentId && (incident.iocMatches?.length ?? 0) > 0) ? 20 : 0;
    const ruleScore = detectedIncidents.some((incident) => incident.log.id === selectedCase.incidentId) ? 20 : 0;
    const eventScore = Math.min(25, caseEvidenceLogs.length * 5);
    return Math.min(100, severityScore + iocScore + ruleScore + eventScore);
  })() : 0;

  const riskBand = caseRiskScore < 25 ? 'Low' : caseRiskScore < 50 ? 'Medium' : caseRiskScore < 75 ? 'High' : 'Critical';
  const riskColor = riskBand === 'Low' ? '#22c55e' : riskBand === 'Medium' ? '#fbbf24' : riskBand === 'High' ? '#f97316' : '#ef4444';

  if (!auth) {
    return <Login onLogin={(data) => {
      setAuth(data);
      fetchHealth(data.token);
      fetchLogs(data.token);
    }} />;
  }

if (portalMode === 'employee' || currentUserRole === 'employee') {
      return (
        <EmployeePortal
          employeeName={auth.user.email}
          tickets={employeeTickets}
          onTicketSubmit={handleEmployeeTicketSubmit}
          onSwitchToSOC={() => { if (currentUserRole !== 'employee') setPortalMode('soc'); }}
          onLogout={() => {
            localStorage.removeItem('token');
            localStorage.removeItem('sentinel-role');
          setAuth(null);
          setPortalMode('soc');
        }}
      />
    );
  }

  const handleIncidentSelect = async (incidentId: string) => {
    setSelectedIncidentId(incidentId);
    const detectedIncident = detectedIncidents.find((incident) => incident.log.id === incidentId);

    if (detectedIncident) {
      setSelectedIncidentDetail({
        id: detectedIncident.log.id,
        logId: detectedIncident.log.id,
        status: 'New',
        assignedAnalyst: 'Tunar',
        createdAt: detectedIncident.triggerTimestamp,
        updatedAt: detectedIncident.triggerTimestamp,
        source: detectedIncident.log.source,
        eventType: detectedIncident.log.eventType,
        severity: detectedIncident.log.severity,
        timestamp: detectedIncident.triggerTimestamp,
        message: detectedIncident.log.message,
        notes: [],
        timeline: [{
          id: `${detectedIncident.log.id}-created`,
          type: 'created',
          timestamp: detectedIncident.triggerTimestamp,
          message: 'Critical incident created by detection engine',
          analyst: 'Detection Engine'
        }],
        ...(detectedIncident.ruleName && detectedIncident.mitreTechnique ? {
          triggeredByRule: {
            name: detectedIncident.ruleName,
            mitreTechnique: detectedIncident.mitreTechnique,
            triggerTimestamp: detectedIncident.triggerTimestamp
          }
        } : {}),
        iocMatches: detectedIncident.iocMatches
      });
    } else {
      try {
        await fetchIncidentDetail(incidentId);
      } catch {
        setSelectedIncidentDetail(null);
      }
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
      source: 'SOC Console',
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

  const mapCaseStatusToTicketStatus = (status: CaseStatus): TicketStatus => {
    switch (status) {
      case 'Reported':
      case 'New':
      case 'Triage':
        return 'Open';
      case 'Investigating':
      case 'Contained':
      case 'Recovery':
        return 'Investigating';
      case 'Resolved':
        return 'Resolved';
      default:
        return 'Open';
    }
  };

  const syncEmployeeTicketFromCase = (nextCase: CaseRecord, timelineEntry?: CaseTimelineEntry) => {
    if (nextCase.source !== 'Employee Portal') return;

    setEmployeeTickets((current) => current.map((ticket) => ticket.caseId !== nextCase.id ? ticket : {
      ...ticket,
      status: mapCaseStatusToTicketStatus(nextCase.status),
      priority: nextCase.priority,
      assignedAnalyst: nextCase.assignedAnalyst,
      timeline: timelineEntry
        ? [...ticket.timeline, {
            id: timelineEntry.id,
            timestamp: timelineEntry.timestamp,
            message: timelineEntry.message
          }].sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime())
        : ticket.timeline
    }));
  };

  const updateCase = (caseId: string, updates: Partial<CaseRecord>, timelineEntry?: CaseTimelineEntry) => {
    setCases((current) => {
      const updatedCases = current.map((item) => item.id === caseId ? {
        ...item,
        ...updates,
        timeline: timelineEntry ? [...item.timeline, timelineEntry].sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime()) : item.timeline
      } : item);

      const updatedCase = updatedCases.find((item) => item.id === caseId);
      if (updatedCase) {
        syncEmployeeTicketFromCase(updatedCase, timelineEntry);
      }

      return updatedCases;
    });
  };

  const updateCaseStatus = (status: CaseStatus) => {
    const selectedCase = cases.find((item) => item.id === selectedCaseId);
    if (!selectedCase) return;

    if (status === 'Resolved') {
      addNotification('Case', 'Case Resolved', `Case ${selectedCase.id} was resolved by ${auth.user.email}.`, selectedCase.id);
    }

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

    if (selectedCase.assignedAnalyst !== assignedAnalyst) {
      addNotification('Case', 'Case Assigned', `${assignedAnalyst} was assigned to case ${selectedCase.id}.`, selectedCase.id);
    }

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

  const addAssetNote = () => {
    if (!selectedAssetId) return;
    const content = assetNoteDraft.trim();
    if (!content) return;

    const timestamp = new Date().toISOString();
    setAssets((current) => current.map((asset) => asset.id === selectedAssetId
      ? {
          ...asset,
          notes: [...asset.notes, {
            id: `${asset.id}-note-${Date.now()}`,
            timestamp,
            analyst: auth.user.email,
            content
          }].sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime())
        }
      : asset));

    setAssetNoteDraft('');
  };

  const addUserNote = () => {
    if (!selectedUserId) return;
    const content = userNoteDraft.trim();
    if (!content) return;

    const timestamp = new Date().toISOString();
    setUsers((current) => current.map((user) => user.id === selectedUserId
      ? {
          ...user,
          notes: [...user.notes, {
            id: `${user.id}-note-${Date.now()}`,
            timestamp,
            analyst: auth.user.email,
            content
          }].sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime())
        }
      : user));

    setUserNoteDraft('');
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

      const createdLog = await res.json() as LogEntry;
      evaluateIncomingEvent(createdLog, logsRef.current);
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
    { label: 'Assets', icon: '▣' },
    { label: 'Users', icon: '◎' },
    { label: 'Notifications', icon: '◔' },
    { label: 'Events', icon: '◫' },
    { label: 'Rules', icon: '◇' },
    { label: 'Threat Intel', icon: '✦' },
    { label: 'Reports', icon: '▥' },
    { label: 'Analyst', icon: '◌' }
  ].filter((item): item is { label: PageName; icon: string } => rolePageAccess[currentUserRole].includes(item.label as PageName));

  const renderPageContent = () => {
    if (!canAccessPage(activePage)) {
      return (
        <section style={{ display: 'grid', placeItems: 'center', minHeight: '420px', padding: '2rem' }}>
          <div style={{ maxWidth: '540px', width: '100%', background: 'rgba(15, 23, 42, 0.42)', border: '1px solid rgba(148, 163, 184, 0.2)', borderRadius: '20px', padding: '2rem', textAlign: 'center' }}>
            <div style={{ fontSize: '0.72rem', letterSpacing: '0.12em', color: '#93c5fd', textTransform: 'uppercase' }}>Access Denied</div>
            <h2 style={{ margin: '0.75rem 0 0.5rem', fontSize: '2rem' }}>You do not have permission to view this page.</h2>
            <p style={{ margin: 0, color: '#cbd5e1', lineHeight: 1.7 }}>Your current role, {currentUserRoleLabel}, does not include access to {activePage}. Contact an administrator for access.</p>
            <button type="button" onClick={() => setActivePage(getDefaultPageForRole(currentUserRole))} style={{ marginTop: '1rem', background: 'linear-gradient(135deg, #2563eb, #0ea5e9)', border: 'none', color: '#eff6ff', borderRadius: '12px', padding: '0.75rem 1rem', cursor: 'pointer', fontWeight: 700 }}>Return to Dashboard</button>
          </div>
        </section>
      );
    }

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
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', flexWrap: 'wrap' }}>
                      <div style={{ color: '#bfdbfe', fontSize: '0.72rem', fontWeight: 800, letterSpacing: '0.08em' }}>{item.id}</div>
                      {item.source === 'Employee Portal' && (
                        <span style={{ display: 'inline-flex', alignItems: 'center', borderRadius: '999px', background: 'rgba(59, 130, 246, 0.18)', border: '1px solid rgba(96, 165, 250, 0.28)', color: '#bfdbfe', padding: '0.18rem 0.5rem', fontSize: '0.62rem', fontWeight: 700, letterSpacing: '0.08em', textTransform: 'uppercase' }}>
                          Employee Portal
                        </span>
                      )}
                    </div>
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

    if (activePage === 'Notifications') {
      const filteredNotifications = notifications
        .filter((notification) => notificationFilter === 'All' || notification.kind === notificationFilter)
        .sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime());

      return (
        <section style={{ display: 'flex', flexDirection: 'column', gap: '1.2rem' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '1rem', flexWrap: 'wrap' }}>
            <div>
              <div style={{ color: '#93c5fd', fontSize: '0.72rem', letterSpacing: '0.12em', textTransform: 'uppercase' }}>Notification Center</div>
              <h2 style={{ margin: '0.25rem 0 0', fontSize: '1.5rem' }}>Recent Activity</h2>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', flexWrap: 'wrap' }}>
              <select value={notificationFilter} onChange={(event) => setNotificationFilter(event.target.value as NotificationFilter)} style={fieldStyle}>
                <option value="All">All</option>
                <option value="Incident">Incident</option>
                <option value="Case">Case</option>
                <option value="IOC">IOC</option>
                <option value="Employee">Employee</option>
              </select>
              {unreadCount > 0 && (
                <button type="button" onClick={markAllNotificationsRead} style={{ border: '1px solid rgba(96, 165, 250, 0.35)', background: 'rgba(59, 130, 246, 0.14)', color: '#dbeafe', borderRadius: '10px', padding: '0.55rem 0.8rem', cursor: 'pointer', fontWeight: 700 }}>
                  Mark all read
                </button>
              )}
            </div>
          </div>

          <div style={{ display: 'grid', gap: '0.8rem' }}>
            {filteredNotifications.length === 0 ? (
              <div style={{ background: 'rgba(15, 23, 42, 0.38)', border: '1px solid rgba(148, 163, 184, 0.2)', borderRadius: '18px', padding: '2rem', color: '#cbd5e1' }}>
                No notifications match the current filter.
              </div>
            ) : filteredNotifications.map((notification) => (
              <div key={notification.id} onClick={() => markNotificationRead(notification.id)} style={{ background: notification.read ? 'rgba(15, 23, 42, 0.35)' : 'rgba(59, 130, 246, 0.08)', border: '1px solid rgba(148, 163, 184, 0.18)', borderRadius: '14px', padding: '0.9rem 1rem', display: 'grid', gap: '0.45rem', cursor: 'pointer' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '0.8rem', flexWrap: 'wrap' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem', flexWrap: 'wrap' }}>
                    <span style={{ display: 'inline-flex', padding: '0.2rem 0.5rem', borderRadius: '999px', background: notification.kind === 'IOC' ? 'rgba(244, 63, 94, 0.12)' : notification.kind === 'Case' ? 'rgba(59, 130, 246, 0.12)' : notification.kind === 'Employee' ? 'rgba(34, 197, 94, 0.12)' : 'rgba(245, 158, 11, 0.12)', color: notification.kind === 'IOC' ? '#fca5a5' : notification.kind === 'Case' ? '#bfdbfe' : notification.kind === 'Employee' ? '#86efac' : '#fbbf24', fontWeight: 800, fontSize: '0.62rem', letterSpacing: '0.08em', textTransform: 'uppercase' }}>{notification.kind}</span>
                    <strong style={{ color: '#f8fafc' }}>{notification.title}</strong>
                  </div>
                  {!notification.read && <span style={{ width: '8px', height: '8px', borderRadius: '50%', background: '#60a5fa', boxShadow: '0 0 12px rgba(96,165,250,0.65)' }} />} 
                </div>
                <div style={{ color: '#cbd5e1', lineHeight: 1.6 }}>{notification.message}</div>
                <div style={{ color: '#94a3b8', fontSize: '0.72rem' }}>{new Date(notification.createdAt).toLocaleString()}</div>
              </div>
            ))}
          </div>
        </section>
      );
    }

    if (activePage === 'Users') {
      if (!canManageUsers) {
        return (
          <section style={{ display: 'grid', placeItems: 'center', minHeight: '420px', padding: '2rem' }}>
            <div style={{ maxWidth: '540px', width: '100%', background: 'rgba(15, 23, 42, 0.42)', border: '1px solid rgba(148, 163, 184, 0.2)', borderRadius: '20px', padding: '2rem', textAlign: 'center' }}>
              <div style={{ fontSize: '0.72rem', letterSpacing: '0.12em', color: '#93c5fd', textTransform: 'uppercase' }}>Access Denied</div>
              <h2 style={{ margin: '0.75rem 0 0.5rem', fontSize: '2rem' }}>User management is restricted.</h2>
              <p style={{ margin: 0, color: '#cbd5e1', lineHeight: 1.7 }}>Only an administrator can manage users and account access.</p>
            </div>
          </section>
        );
      }
      const userDepartments = ['All', ...Array.from(new Set(users.map((user) => user.department)))];
      const userRoles = ['All', ...Array.from(new Set(users.map((user) => user.role)))];
      const filteredUsers = users.filter((user) => {
        const haystack = `${user.name} ${user.email} ${user.department} ${user.role}`.toLowerCase();
        const matchesSearch = !userSearch || haystack.includes(userSearch.toLowerCase());
        const matchesStatus = userStatusFilter === 'All' || user.status === userStatusFilter;
        const matchesDepartment = userDepartmentFilter === 'All' || user.department === userDepartmentFilter;
        const matchesRole = userRoleFilter === 'All' || user.role === userRoleFilter;
        return matchesSearch && matchesStatus && matchesDepartment && matchesRole;
      });
      const selectedUser = users.find((user) => user.id === selectedUserId) ?? null;
      const selectedUserAssets = selectedUser
        ? assets.filter((asset) => {
            const ownerMatch = asset.owner.toLowerCase().includes(selectedUser.name.split(' ')[0].toLowerCase()) || asset.owner.toLowerCase().includes(selectedUser.name.split(' ').slice(-1)[0].toLowerCase());
            const deviceMatch = selectedUser.devices.some((device) => {
              const deviceName = device.toLowerCase();
              return asset.hostname.toLowerCase().includes(deviceName) || deviceName.includes(asset.hostname.toLowerCase());
            });
            return ownerMatch || deviceMatch;
          })
        : [];
      const selectedUserIncidents = selectedUser
        ? logs.filter((log) => {
            const aliases = [selectedUser.name, selectedUser.email.split('@')[0], ...selectedUser.devices].map((value) => value.toLowerCase());
            const haystack = `${log.message} ${log.source} ${log.eventType}`.toLowerCase();
            return aliases.some((alias) => haystack.includes(alias));
          }).slice(0, 8)
        : [];
      const selectedUserTickets = selectedUser
        ? employeeTickets.filter((ticket) => {
            const ticketText = `${ticket.department} ${ticket.device} ${ticket.incidentType}`.toLowerCase();
            return ticketText.includes(selectedUser.department.toLowerCase()) || selectedUser.devices.some((device) => ticketText.includes(device.toLowerCase()));
          })
        : [];
      const selectedUserCases = selectedUser
        ? cases.filter((item) => {
            const haystack = `${item.incident.message} ${item.incident.eventType} ${item.incident.source}`.toLowerCase();
            const aliases = [selectedUser.name, selectedUser.email.split('@')[0], ...selectedUser.devices].map((value) => value.toLowerCase());
            return selectedUserAssets.some((asset) => haystack.includes(asset.hostname.toLowerCase()) || haystack.includes(asset.ip.toLowerCase())) || aliases.some((alias) => haystack.includes(alias));
          })
        : [];
      const selectedUserIocs = selectedUser
        ? iocs.filter((ioc) => {
            const haystack = `${ioc.value} ${ioc.threatFamily}`.toLowerCase();
            const aliases = [selectedUser.name, ...selectedUser.devices].map((value) => value.toLowerCase());
            return aliases.some((alias) => haystack.includes(alias));
          })
        : [];

      return (
        <section style={{ display: 'flex', flexDirection: 'column', gap: '1.2rem' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '1rem', flexWrap: 'wrap' }}>
            <div>
              <div style={{ color: '#93c5fd', fontSize: '0.72rem', letterSpacing: '0.12em', textTransform: 'uppercase' }}>User Directory</div>
              <h2 style={{ margin: '0.25rem 0 0', fontSize: '1.5rem' }}>Employees & Accounts</h2>
            </div>
            <div style={{ color: '#cbd5e1', fontSize: '0.85rem' }}>{filteredUsers.length} users</div>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '0.75rem' }}>
            <input value={userSearch} onChange={(event) => setUserSearch(event.target.value)} placeholder="Search user, email, role" style={{ ...fieldStyle, minHeight: '44px' }} />
            <select value={userDepartmentFilter} onChange={(event) => setUserDepartmentFilter(event.target.value)} style={fieldStyle}>
              {userDepartments.map((department) => <option key={department} value={department}>{department === 'All' ? 'All Departments' : department}</option>)}
            </select>
            <select value={userRoleFilter} onChange={(event) => setUserRoleFilter(event.target.value)} style={fieldStyle}>
              {userRoles.map((role) => <option key={role} value={role}>{role === 'All' ? 'All Roles' : role}</option>)}
            </select>
            <select value={userStatusFilter} onChange={(event) => setUserStatusFilter(event.target.value as 'All' | UserStatus)} style={fieldStyle}>
              <option value="All">All Status</option>
              <option value="Active">Active</option>
              <option value="Monitoring">Monitoring</option>
              <option value="Restricted">Restricted</option>
              <option value="Offboarded">Offboarded</option>
            </select>
          </div>

          {filteredUsers.length === 0 ? (
            <div style={{ background: 'rgba(15, 23, 42, 0.38)', border: '1px solid rgba(148, 163, 184, 0.2)', borderRadius: '18px', padding: '2rem', color: '#cbd5e1' }}>
              No users match the current filters.
            </div>
          ) : (
            <div style={{ background: 'rgba(15, 23, 42, 0.38)', border: '1px solid rgba(148, 163, 184, 0.2)', borderRadius: '18px', padding: '0.25rem' }}>
              <div style={{ overflowX: 'auto' }}>
                <table style={{ width: '100%', minWidth: '980px', borderCollapse: 'collapse' }}>
                  <thead>
                    <tr style={{ color: '#93c5fd', textAlign: 'left', fontSize: '0.68rem', letterSpacing: '0.08em', textTransform: 'uppercase' }}>
                      {['Name', 'Email', 'Department', 'Role', 'Devices', 'Status', 'Risk Score', 'Last Login'].map((header) => (
                        <th key={header} style={{ padding: '0.9rem 0.75rem', borderBottom: '1px solid rgba(148, 163, 184, 0.16)' }}>{header}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {filteredUsers.map((user) => (
                      <tr key={user.id} onClick={() => setSelectedUserId(user.id)} style={{ cursor: 'pointer', borderBottom: '1px solid rgba(148, 163, 184, 0.1)', background: selectedUserId === user.id ? 'rgba(59, 130, 246, 0.08)' : 'transparent' }}>
                        <td style={{ padding: '0.85rem 0.75rem', color: '#f8fafc', fontWeight: 700 }}>{user.name}</td>
                        <td style={{ padding: '0.85rem 0.75rem', color: '#cbd5e1' }}>{user.email}</td>
                        <td style={{ padding: '0.85rem 0.75rem', color: '#cbd5e1' }}>{user.department}</td>
                        <td style={{ padding: '0.85rem 0.75rem', color: '#cbd5e1' }}>{user.role}</td>
                        <td style={{ padding: '0.85rem 0.75rem', color: '#cbd5e1' }}>{user.devices.join(', ')}</td>
                        <td style={{ padding: '0.85rem 0.75rem' }}><span style={{ color: user.status === 'Offboarded' ? '#94a3b8' : user.status === 'Restricted' ? '#fca5a5' : user.status === 'Monitoring' ? '#fbbf24' : '#86efac', fontWeight: 700 }}>{user.status}</span></td>
                        <td style={{ padding: '0.85rem 0.75rem', color: user.riskScore >= 70 ? '#fca5a5' : user.riskScore >= 45 ? '#fbbf24' : '#86efac', fontWeight: 800 }}>{user.riskScore}</td>
                        <td style={{ padding: '0.85rem 0.75rem', color: '#cbd5e1', whiteSpace: 'nowrap' }}>{new Date(user.lastLogin).toLocaleString()}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {selectedUser && (
            <div style={{ background: 'rgba(15, 23, 42, 0.38)', border: '1px solid rgba(148, 163, 184, 0.2)', borderRadius: '18px', padding: '1.1rem', display: 'grid', gap: '1rem' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '1rem', flexWrap: 'wrap' }}>
                <div>
                  <div style={{ color: '#93c5fd', fontSize: '0.7rem', letterSpacing: '0.12em', textTransform: 'uppercase' }}>User Detail</div>
                  <h3 style={{ margin: '0.25rem 0 0', fontSize: '1.2rem' }}>{selectedUser.name}</h3>
                </div>
                <button type="button" onClick={() => setSelectedUserId(null)} style={{ width: '32px', height: '32px', borderRadius: '10px', border: '1px solid rgba(148, 163, 184, 0.2)', background: 'rgba(15, 23, 42, 0.7)', color: '#e2e8f0', cursor: 'pointer' }}>×</button>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(170px, 1fr))', gap: '0.75rem' }}>
                <div style={{ background: 'rgba(15, 23, 42, 0.52)', border: '1px solid rgba(148, 163, 184, 0.16)', borderRadius: '12px', padding: '0.75rem' }}>
                  <div style={{ color: '#93c5fd', fontSize: '0.68rem', letterSpacing: '0.08em', textTransform: 'uppercase', marginBottom: '0.3rem' }}>Email</div>
                  <div style={{ color: '#f8fafc', fontWeight: 700 }}>{selectedUser.email}</div>
                </div>
                <div style={{ background: 'rgba(15, 23, 42, 0.52)', border: '1px solid rgba(148, 163, 184, 0.16)', borderRadius: '12px', padding: '0.75rem' }}>
                  <div style={{ color: '#93c5fd', fontSize: '0.68rem', letterSpacing: '0.08em', textTransform: 'uppercase', marginBottom: '0.3rem' }}>Role</div>
                  <div style={{ color: '#f8fafc', fontWeight: 700 }}>{selectedUser.role}</div>
                </div>
                <div style={{ background: 'rgba(15, 23, 42, 0.52)', border: '1px solid rgba(148, 163, 184, 0.16)', borderRadius: '12px', padding: '0.75rem' }}>
                  <div style={{ color: '#93c5fd', fontSize: '0.68rem', letterSpacing: '0.08em', textTransform: 'uppercase', marginBottom: '0.3rem' }}>Department</div>
                  <div style={{ color: '#f8fafc', fontWeight: 700 }}>{selectedUser.department}</div>
                </div>
                <div style={{ background: 'rgba(15, 23, 42, 0.52)', border: '1px solid rgba(148, 163, 184, 0.16)', borderRadius: '12px', padding: '0.75rem' }}>
                  <div style={{ color: '#93c5fd', fontSize: '0.68rem', letterSpacing: '0.08em', textTransform: 'uppercase', marginBottom: '0.3rem' }}>Status</div>
                  <div style={{ color: selectedUser.status === 'Offboarded' ? '#94a3b8' : selectedUser.status === 'Restricted' ? '#fca5a5' : selectedUser.status === 'Monitoring' ? '#fbbf24' : '#86efac', fontWeight: 700 }}>{selectedUser.status}</div>
                </div>
              </div>

              <div style={{ background: 'rgba(15, 23, 42, 0.52)', border: '1px solid rgba(148, 163, 184, 0.16)', borderRadius: '12px', padding: '0.85rem' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.7rem' }}>
                  <div style={{ color: '#93c5fd', fontSize: '0.68rem', letterSpacing: '0.08em', textTransform: 'uppercase' }}>Risk Score</div>
                  <div style={{ fontWeight: 800, color: selectedUser.riskScore >= 70 ? '#fca5a5' : selectedUser.riskScore >= 45 ? '#fbbf24' : '#86efac' }}>{selectedUser.riskScore}/100</div>
                </div>
                <div style={{ width: '100%', height: '10px', borderRadius: '999px', background: 'rgba(148,163,184,0.14)', overflow: 'hidden' }}>
                  <div style={{ width: `${selectedUser.riskScore}%`, height: '100%', borderRadius: '999px', background: selectedUser.riskScore >= 70 ? 'linear-gradient(90deg, #f87171, #ef4444)' : selectedUser.riskScore >= 45 ? 'linear-gradient(90deg, #fbbf24, #f59e0b)' : 'linear-gradient(90deg, #22c55e, #4ade80)' }} />
                </div>
              </div>

              <div style={{ display: 'grid', gap: '0.75rem' }}>
                <div style={{ background: 'rgba(15, 23, 42, 0.52)', border: '1px solid rgba(148, 163, 184, 0.16)', borderRadius: '12px', padding: '0.85rem' }}>
                  <div style={{ color: '#93c5fd', fontSize: '0.68rem', letterSpacing: '0.08em', textTransform: 'uppercase', marginBottom: '0.45rem' }}>Assigned Assets</div>
                  {selectedUserAssets.length === 0 ? <div style={{ color: '#cbd5e1', fontSize: '0.8rem' }}>No linked assets.</div> : selectedUserAssets.map((asset) => (
                    <div key={asset.id} style={{ color: '#dbeafe', fontSize: '0.76rem', lineHeight: 1.7, borderTop: '1px solid rgba(148,163,184,0.12)', paddingTop: '0.4rem', marginTop: '0.4rem' }}>{asset.hostname} · {asset.ip} · {asset.type}</div>
                  ))}
                </div>

                <div style={{ background: 'rgba(15, 23, 42, 0.52)', border: '1px solid rgba(148, 163, 184, 0.16)', borderRadius: '12px', padding: '0.85rem' }}>
                  <div style={{ color: '#93c5fd', fontSize: '0.68rem', letterSpacing: '0.08em', textTransform: 'uppercase', marginBottom: '0.45rem' }}>Related Incidents</div>
                  {selectedUserIncidents.length === 0 ? <div style={{ color: '#cbd5e1', fontSize: '0.8rem' }}>No related incidents.</div> : selectedUserIncidents.map((log) => (
                    <div key={log.id} style={{ color: '#dbeafe', fontSize: '0.76rem', lineHeight: 1.7, borderTop: '1px solid rgba(148,163,184,0.12)', paddingTop: '0.4rem', marginTop: '0.4rem' }}>{log.eventType} · {new Date(log.timestamp).toLocaleString()}</div>
                  ))}
                </div>

                <div style={{ background: 'rgba(15, 23, 42, 0.52)', border: '1px solid rgba(148, 163, 184, 0.16)', borderRadius: '12px', padding: '0.85rem' }}>
                  <div style={{ color: '#93c5fd', fontSize: '0.68rem', letterSpacing: '0.08em', textTransform: 'uppercase', marginBottom: '0.45rem' }}>Submitted Tickets</div>
                  {selectedUserTickets.length === 0 ? <div style={{ color: '#cbd5e1', fontSize: '0.8rem' }}>No submitted tickets.</div> : selectedUserTickets.map((ticket) => (
                    <div key={ticket.id} style={{ color: '#dbeafe', fontSize: '0.76rem', lineHeight: 1.7, borderTop: '1px solid rgba(148,163,184,0.12)', paddingTop: '0.4rem', marginTop: '0.4rem' }}>{ticket.id} · {ticket.status} · {ticket.incidentType}</div>
                  ))}
                </div>

                <div style={{ background: 'rgba(15, 23, 42, 0.52)', border: '1px solid rgba(148, 163, 184, 0.16)', borderRadius: '12px', padding: '0.85rem' }}>
                  <div style={{ color: '#93c5fd', fontSize: '0.68rem', letterSpacing: '0.08em', textTransform: 'uppercase', marginBottom: '0.45rem' }}>Active Cases</div>
                  {selectedUserCases.length === 0 ? <div style={{ color: '#cbd5e1', fontSize: '0.8rem' }}>No active cases.</div> : selectedUserCases.map((item) => (
                    <div key={item.id} style={{ color: '#dbeafe', fontSize: '0.76rem', lineHeight: 1.7, borderTop: '1px solid rgba(148,163,184,0.12)', paddingTop: '0.4rem', marginTop: '0.4rem' }}>{item.id} · {item.status} · {item.priority}</div>
                  ))}
                </div>

                <div style={{ background: 'rgba(15, 23, 42, 0.52)', border: '1px solid rgba(148, 163, 184, 0.16)', borderRadius: '12px', padding: '0.85rem' }}>
                  <div style={{ color: '#93c5fd', fontSize: '0.68rem', letterSpacing: '0.08em', textTransform: 'uppercase', marginBottom: '0.45rem' }}>IOC Exposure</div>
                  {selectedUserIocs.length === 0 ? <div style={{ color: '#cbd5e1', fontSize: '0.8rem' }}>No observed IOC exposure.</div> : selectedUserIocs.map((ioc) => (
                    <div key={`${ioc.id}-${ioc.value}`} style={{ color: '#dbeafe', fontSize: '0.76rem', lineHeight: 1.7, borderTop: '1px solid rgba(148,163,184,0.12)', paddingTop: '0.4rem', marginTop: '0.4rem' }}>{ioc.value} · {ioc.threatFamily}</div>
                  ))}
                </div>
              </div>

              <div style={{ background: 'rgba(15, 23, 42, 0.52)', border: '1px solid rgba(148, 163, 184, 0.16)', borderRadius: '12px', padding: '0.85rem' }}>
                <div style={{ color: '#93c5fd', fontSize: '0.68rem', letterSpacing: '0.08em', textTransform: 'uppercase', marginBottom: '0.7rem' }}>Analyst Notes</div>
                <textarea
                  value={userNoteDraft}
                  onChange={(event) => setUserNoteDraft(event.target.value)}
                  placeholder="Add analyst note..."
                  style={{ width: '100%', minHeight: '90px', resize: 'vertical', borderRadius: '10px', border: '1px solid rgba(148, 163, 184, 0.2)', background: 'rgba(15, 23, 42, 0.75)', color: '#e2e8f0', padding: '0.7rem 0.8rem', boxSizing: 'border-box' }}
                />
                <button type="button" onClick={addUserNote} style={{ marginTop: '0.6rem', width: '100%', background: 'linear-gradient(135deg, #2563eb, #0ea5e9)', border: 'none', color: '#eff6ff', borderRadius: '12px', padding: '0.7rem 1rem', cursor: 'pointer', fontWeight: 700 }}>Add Note</button>
                {selectedUser.notes.length === 0 ? (
                  <div style={{ marginTop: '0.7rem', color: '#cbd5e1', fontSize: '0.8rem' }}>No notes recorded for this user.</div>
                ) : (
                  <div style={{ display: 'grid', gap: '0.65rem', marginTop: '0.75rem' }}>
                    {selectedUser.notes.slice().sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime()).map((note) => (
                      <div key={note.id} style={{ background: 'rgba(15, 23, 42, 0.7)', border: '1px solid rgba(148, 163, 184, 0.16)', borderRadius: '10px', padding: '0.7rem 0.8rem' }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', gap: '0.5rem', marginBottom: '0.35rem', color: '#cbd5e1', fontSize: '0.68rem' }}>
                          <span>{note.analyst}</span>
                          <span>{new Date(note.timestamp).toLocaleString()}</span>
                        </div>
                        <div style={{ color: '#e2e8f0', lineHeight: 1.6 }}>{note.content}</div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          )}
        </section>
      );
    }

    if (activePage === 'Assets') {
      const assetDepartments = ['All', ...Array.from(new Set(assets.map((asset) => asset.department)))];
      const filteredAssets = assets.filter((asset) => {
        const haystack = `${asset.hostname} ${asset.ip} ${asset.owner} ${asset.department}`.toLowerCase();
        const matchesSearch = !assetSearch || haystack.includes(assetSearch.toLowerCase());
        const matchesStatus = assetStatusFilter === 'All' || asset.status === assetStatusFilter;
        const matchesType = assetTypeFilter === 'All' || asset.type === assetTypeFilter;
        const matchesDepartment = assetDepartmentFilter === 'All' || asset.department === assetDepartmentFilter;
        const matchesCriticality = assetCriticalityFilter === 'All' || asset.criticality === assetCriticalityFilter;
        return matchesSearch && matchesStatus && matchesType && matchesDepartment && matchesCriticality;
      });

      const selectedAsset = assets.find((asset) => asset.id === selectedAssetId) ?? null;
      const relatedAssetIncidents = selectedAsset
        ? logs.filter((log) => {
            const haystack = `${log.message} ${log.source} ${log.eventType}`.toLowerCase();
            return haystack.includes(selectedAsset.hostname.toLowerCase()) || haystack.includes(selectedAsset.ip.toLowerCase());
          }).slice(0, 8)
        : [];
      const relatedAssetCases = selectedAsset
        ? cases.filter((item) => {
            const haystack = `${item.incident.message} ${item.incident.eventType} ${item.incident.source}`.toLowerCase();
            return haystack.includes(selectedAsset.hostname.toLowerCase()) || haystack.includes(selectedAsset.ip.toLowerCase());
          })
        : [];
      const relatedAssetEvents = selectedAsset
        ? logs.filter((log) => {
            const haystack = `${log.message} ${log.source} ${log.eventType}`.toLowerCase();
            return haystack.includes(selectedAsset.hostname.toLowerCase()) || haystack.includes(selectedAsset.ip.toLowerCase());
          }).slice(0, 5)
        : [];
      const relatedIocs = selectedAsset
        ? iocs.filter((ioc) => {
            const haystack = `${ioc.value} ${ioc.threatFamily}`.toLowerCase();
            return haystack.includes(selectedAsset.hostname.toLowerCase()) || haystack.includes(selectedAsset.ip.toLowerCase());
          })
        : [];

      return (
        <section style={{ display: 'flex', flexDirection: 'column', gap: '1.2rem' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '1rem', flexWrap: 'wrap' }}>
            <div>
              <div style={{ color: '#93c5fd', fontSize: '0.72rem', letterSpacing: '0.12em', textTransform: 'uppercase' }}>Asset Inventory</div>
              <h2 style={{ margin: '0.25rem 0 0', fontSize: '1.5rem' }}>Tracked Systems</h2>
            </div>
            <div style={{ color: '#cbd5e1', fontSize: '0.85rem' }}>{filteredAssets.length} assets</div>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(170px, 1fr))', gap: '0.75rem' }}>
            <input value={assetSearch} onChange={(event) => setAssetSearch(event.target.value)} placeholder="Search hostname or IP" style={{ ...fieldStyle, minHeight: '44px' }} />
            <select value={assetStatusFilter} onChange={(event) => setAssetStatusFilter(event.target.value as 'All' | AssetStatus)} style={fieldStyle}>
              <option value="All">All Status</option>
              {assetStatuses.map((status) => <option key={status} value={status}>{status}</option>)}
            </select>
            <select value={assetTypeFilter} onChange={(event) => setAssetTypeFilter(event.target.value as 'All' | AssetType)} style={fieldStyle}>
              <option value="All">All Types</option>
              {assetTypes.map((type) => <option key={type} value={type}>{type}</option>)}
            </select>
            <select value={assetDepartmentFilter} onChange={(event) => setAssetDepartmentFilter(event.target.value)} style={fieldStyle}>
              <option value="All">All Departments</option>
              {assetDepartments.slice(1).map((department) => <option key={department} value={department}>{department}</option>)}
            </select>
            <select value={assetCriticalityFilter} onChange={(event) => setAssetCriticalityFilter(event.target.value as 'All' | AssetCriticality)} style={fieldStyle}>
              <option value="All">All Criticality</option>
              {assetCriticalities.map((level) => <option key={level} value={level}>{level}</option>)}
            </select>
          </div>

          {filteredAssets.length === 0 ? (
            <div style={{ background: 'rgba(15, 23, 42, 0.38)', border: '1px solid rgba(148, 163, 184, 0.2)', borderRadius: '18px', padding: '2rem', color: '#cbd5e1' }}>
              No assets match the current filters.
            </div>
          ) : (
            <div style={{ background: 'rgba(15, 23, 42, 0.38)', border: '1px solid rgba(148, 163, 184, 0.2)', borderRadius: '18px', padding: '0.25rem' }}>
              <div style={{ overflowX: 'auto' }}>
                <table style={{ width: '100%', minWidth: '980px', borderCollapse: 'collapse' }}>
                  <thead>
                    <tr style={{ color: '#93c5fd', textAlign: 'left', fontSize: '0.68rem', letterSpacing: '0.08em', textTransform: 'uppercase' }}>
                      {['Hostname', 'IP', 'Type', 'Owner', 'Department', 'Status', 'Criticality', 'Risk Score', 'Last Seen'].map((header) => (
                        <th key={header} style={{ padding: '0.9rem 0.75rem', borderBottom: '1px solid rgba(148, 163, 184, 0.16)' }}>{header}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {filteredAssets.map((asset) => (
                      <tr key={asset.id} onClick={() => setSelectedAssetId(asset.id)} style={{ cursor: 'pointer', borderBottom: '1px solid rgba(148, 163, 184, 0.1)', background: selectedAssetId === asset.id ? 'rgba(59, 130, 246, 0.08)' : 'transparent' }}>
                        <td style={{ padding: '0.85rem 0.75rem', color: '#f8fafc', fontWeight: 700 }}>{asset.hostname}</td>
                        <td style={{ padding: '0.85rem 0.75rem', color: '#cbd5e1' }}>{asset.ip}</td>
                        <td style={{ padding: '0.85rem 0.75rem', color: '#cbd5e1' }}>{asset.type}</td>
                        <td style={{ padding: '0.85rem 0.75rem', color: '#cbd5e1' }}>{asset.owner}</td>
                        <td style={{ padding: '0.85rem 0.75rem', color: '#cbd5e1' }}>{asset.department}</td>
                        <td style={{ padding: '0.85rem 0.75rem' }}><span style={{ color: asset.status === 'Isolated' ? '#fca5a5' : asset.status === 'Offline' ? '#94a3b8' : asset.status === 'Monitoring' ? '#fbbf24' : '#86efac', fontWeight: 700 }}>{asset.status}</span></td>
                        <td style={{ padding: '0.85rem 0.75rem' }}><span style={{ color: asset.criticality === 'Critical' ? '#fca5a5' : asset.criticality === 'High' ? '#fbbf24' : asset.criticality === 'Medium' ? '#93c5fd' : '#86efac', fontWeight: 700 }}>{asset.criticality}</span></td>
                        <td style={{ padding: '0.85rem 0.75rem', color: asset.riskScore >= 80 ? '#fca5a5' : asset.riskScore >= 60 ? '#fbbf24' : '#86efac', fontWeight: 800 }}>{asset.riskScore}</td>
                        <td style={{ padding: '0.85rem 0.75rem', color: '#cbd5e1', whiteSpace: 'nowrap' }}>{new Date(asset.lastSeen).toLocaleString()}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {selectedAsset && (
            <div style={{ background: 'rgba(15, 23, 42, 0.38)', border: '1px solid rgba(148, 163, 184, 0.2)', borderRadius: '18px', padding: '1.1rem', display: 'grid', gap: '1rem' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '1rem', flexWrap: 'wrap' }}>
                <div>
                  <div style={{ color: '#93c5fd', fontSize: '0.7rem', letterSpacing: '0.12em', textTransform: 'uppercase' }}>Asset Detail</div>
                  <h3 style={{ margin: '0.25rem 0 0', fontSize: '1.2rem' }}>{selectedAsset.hostname}</h3>
                </div>
                <button type="button" onClick={() => setSelectedAssetId(null)} style={{ width: '32px', height: '32px', borderRadius: '10px', border: '1px solid rgba(148, 163, 184, 0.2)', background: 'rgba(15, 23, 42, 0.7)', color: '#e2e8f0', cursor: 'pointer' }}>×</button>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))', gap: '0.75rem' }}>
                <div style={{ background: 'rgba(15, 23, 42, 0.52)', border: '1px solid rgba(148, 163, 184, 0.16)', borderRadius: '12px', padding: '0.75rem' }}>
                  <div style={{ color: '#93c5fd', fontSize: '0.68rem', letterSpacing: '0.08em', textTransform: 'uppercase', marginBottom: '0.3rem' }}>IP</div>
                  <div style={{ color: '#f8fafc', fontWeight: 700 }}>{selectedAsset.ip}</div>
                </div>
                <div style={{ background: 'rgba(15, 23, 42, 0.52)', border: '1px solid rgba(148, 163, 184, 0.16)', borderRadius: '12px', padding: '0.75rem' }}>
                  <div style={{ color: '#93c5fd', fontSize: '0.68rem', letterSpacing: '0.08em', textTransform: 'uppercase', marginBottom: '0.3rem' }}>Type</div>
                  <div style={{ color: '#f8fafc', fontWeight: 700 }}>{selectedAsset.type}</div>
                </div>
                <div style={{ background: 'rgba(15, 23, 42, 0.52)', border: '1px solid rgba(148, 163, 184, 0.16)', borderRadius: '12px', padding: '0.75rem' }}>
                  <div style={{ color: '#93c5fd', fontSize: '0.68rem', letterSpacing: '0.08em', textTransform: 'uppercase', marginBottom: '0.3rem' }}>Owner</div>
                  <div style={{ color: '#f8fafc', fontWeight: 700 }}>{selectedAsset.owner}</div>
                </div>
                <div style={{ background: 'rgba(15, 23, 42, 0.52)', border: '1px solid rgba(148, 163, 184, 0.16)', borderRadius: '12px', padding: '0.75rem' }}>
                  <div style={{ color: '#93c5fd', fontSize: '0.68rem', letterSpacing: '0.08em', textTransform: 'uppercase', marginBottom: '0.3rem' }}>Department</div>
                  <div style={{ color: '#f8fafc', fontWeight: 700 }}>{selectedAsset.department}</div>
                </div>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem' }}>
                <div style={{ background: 'rgba(15, 23, 42, 0.52)', border: '1px solid rgba(148, 163, 184, 0.16)', borderRadius: '12px', padding: '0.75rem' }}>
                  <div style={{ color: '#93c5fd', fontSize: '0.68rem', letterSpacing: '0.08em', textTransform: 'uppercase', marginBottom: '0.3rem' }}>Status</div>
                  <div style={{ color: selectedAsset.status === 'Isolated' ? '#fca5a5' : selectedAsset.status === 'Offline' ? '#94a3b8' : selectedAsset.status === 'Monitoring' ? '#fbbf24' : '#86efac', fontWeight: 700 }}>{selectedAsset.status}</div>
                </div>
                <div style={{ background: 'rgba(15, 23, 42, 0.52)', border: '1px solid rgba(148, 163, 184, 0.16)', borderRadius: '12px', padding: '0.75rem' }}>
                  <div style={{ color: '#93c5fd', fontSize: '0.68rem', letterSpacing: '0.08em', textTransform: 'uppercase', marginBottom: '0.3rem' }}>Criticality</div>
                  <div style={{ color: selectedAsset.criticality === 'Critical' ? '#fca5a5' : selectedAsset.criticality === 'High' ? '#fbbf24' : selectedAsset.criticality === 'Medium' ? '#93c5fd' : '#86efac', fontWeight: 700 }}>{selectedAsset.criticality}</div>
                </div>
              </div>

              <div style={{ background: 'rgba(15, 23, 42, 0.52)', border: '1px solid rgba(148, 163, 184, 0.16)', borderRadius: '12px', padding: '0.85rem' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.5rem' }}>
                  <div style={{ color: '#93c5fd', fontSize: '0.68rem', letterSpacing: '0.08em', textTransform: 'uppercase' }}>Risk Score</div>
                  <div style={{ fontWeight: 800, color: selectedAsset.riskScore >= 80 ? '#fca5a5' : selectedAsset.riskScore >= 60 ? '#fbbf24' : '#86efac' }}>{selectedAsset.riskScore}/100</div>
                </div>
                <div style={{ width: '100%', height: '10px', borderRadius: '999px', background: 'rgba(148,163,184,0.14)', overflow: 'hidden' }}>
                  <div style={{ width: `${selectedAsset.riskScore}%`, height: '100%', borderRadius: '999px', background: selectedAsset.riskScore >= 80 ? 'linear-gradient(90deg, #f87171, #ef4444)' : selectedAsset.riskScore >= 60 ? 'linear-gradient(90deg, #fbbf24, #f59e0b)' : 'linear-gradient(90deg, #22c55e, #4ade80)' }} />
                </div>
              </div>

              <div style={{ display: 'grid', gap: '0.75rem' }}>
                <div style={{ background: 'rgba(15, 23, 42, 0.52)', border: '1px solid rgba(148, 163, 184, 0.16)', borderRadius: '12px', padding: '0.85rem' }}>
                  <div style={{ color: '#93c5fd', fontSize: '0.68rem', letterSpacing: '0.08em', textTransform: 'uppercase', marginBottom: '0.45rem' }}>Related Incidents</div>
                  {relatedAssetIncidents.length === 0 ? <div style={{ color: '#cbd5e1', fontSize: '0.8rem' }}>No matching incidents.</div> : relatedAssetIncidents.map((log) => (
                    <div key={log.id} style={{ color: '#dbeafe', fontSize: '0.76rem', lineHeight: 1.7, borderTop: '1px solid rgba(148,163,184,0.12)', paddingTop: '0.4rem', marginTop: '0.4rem' }}>{log.eventType} · {new Date(log.timestamp).toLocaleString()}</div>
                  ))}
                </div>

                <div style={{ background: 'rgba(15, 23, 42, 0.52)', border: '1px solid rgba(148, 163, 184, 0.16)', borderRadius: '12px', padding: '0.85rem' }}>
                  <div style={{ color: '#93c5fd', fontSize: '0.68rem', letterSpacing: '0.08em', textTransform: 'uppercase', marginBottom: '0.45rem' }}>Related Cases</div>
                  {relatedAssetCases.length === 0 ? <div style={{ color: '#cbd5e1', fontSize: '0.8rem' }}>No linked cases.</div> : relatedAssetCases.map((item) => (
                    <div key={item.id} style={{ color: '#dbeafe', fontSize: '0.76rem', lineHeight: 1.7, borderTop: '1px solid rgba(148,163,184,0.12)', paddingTop: '0.4rem', marginTop: '0.4rem' }}>{item.id} · {item.status}</div>
                  ))}
                </div>

                <div style={{ background: 'rgba(15, 23, 42, 0.52)', border: '1px solid rgba(148, 163, 184, 0.16)', borderRadius: '12px', padding: '0.85rem' }}>
                  <div style={{ color: '#93c5fd', fontSize: '0.68rem', letterSpacing: '0.08em', textTransform: 'uppercase', marginBottom: '0.45rem' }}>Recent Events</div>
                  {relatedAssetEvents.length === 0 ? <div style={{ color: '#cbd5e1', fontSize: '0.8rem' }}>No recent events.</div> : relatedAssetEvents.map((log) => (
                    <div key={log.id} style={{ color: '#dbeafe', fontSize: '0.76rem', lineHeight: 1.7, borderTop: '1px solid rgba(148,163,184,0.12)', paddingTop: '0.4rem', marginTop: '0.4rem' }}>{log.eventType} · {log.source}</div>
                  ))}
                </div>

                <div style={{ background: 'rgba(15, 23, 42, 0.52)', border: '1px solid rgba(148, 163, 184, 0.16)', borderRadius: '12px', padding: '0.85rem' }}>
                  <div style={{ color: '#93c5fd', fontSize: '0.68rem', letterSpacing: '0.08em', textTransform: 'uppercase', marginBottom: '0.45rem' }}>IOC Matches</div>
                  {relatedIocs.length === 0 ? <div style={{ color: '#cbd5e1', fontSize: '0.8rem' }}>No IOC matches for this asset.</div> : relatedIocs.map((ioc) => (
                    <div key={`${ioc.id}-${ioc.value}`} style={{ color: '#dbeafe', fontSize: '0.76rem', lineHeight: 1.7, borderTop: '1px solid rgba(148,163,184,0.12)', paddingTop: '0.4rem', marginTop: '0.4rem' }}>{ioc.value} · {ioc.threatFamily}</div>
                  ))}
                </div>
              </div>

              <div style={{ background: 'rgba(15, 23, 42, 0.52)', border: '1px solid rgba(148, 163, 184, 0.16)', borderRadius: '12px', padding: '0.85rem' }}>
                <div style={{ color: '#93c5fd', fontSize: '0.68rem', letterSpacing: '0.08em', textTransform: 'uppercase', marginBottom: '0.7rem' }}>Analyst Notes</div>
                <textarea
                  value={assetNoteDraft}
                  onChange={(event) => setAssetNoteDraft(event.target.value)}
                  placeholder="Add analyst note..."
                  style={{ width: '100%', minHeight: '90px', resize: 'vertical', borderRadius: '10px', border: '1px solid rgba(148, 163, 184, 0.2)', background: 'rgba(15, 23, 42, 0.75)', color: '#e2e8f0', padding: '0.7rem 0.8rem', boxSizing: 'border-box' }}
                />
                <button type="button" onClick={addAssetNote} style={{ marginTop: '0.6rem', width: '100%', background: 'linear-gradient(135deg, #2563eb, #0ea5e9)', border: 'none', color: '#eff6ff', borderRadius: '12px', padding: '0.7rem 1rem', cursor: 'pointer', fontWeight: 700 }}>Add Note</button>
                {selectedAsset.notes.length === 0 ? (
                  <div style={{ marginTop: '0.7rem', color: '#cbd5e1', fontSize: '0.8rem' }}>No analyst notes recorded.</div>
                ) : (
                  <div style={{ display: 'grid', gap: '0.65rem', marginTop: '0.75rem' }}>
                    {selectedAsset.notes.slice().sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime()).map((note) => (
                      <div key={note.id} style={{ background: 'rgba(15, 23, 42, 0.7)', border: '1px solid rgba(148, 163, 184, 0.16)', borderRadius: '10px', padding: '0.7rem 0.8rem' }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', gap: '0.5rem', marginBottom: '0.35rem', color: '#cbd5e1', fontSize: '0.68rem' }}>
                          <span>{note.analyst}</span>
                          <span>{new Date(note.timestamp).toLocaleString()}</span>
                        </div>
                        <div style={{ color: '#e2e8f0', lineHeight: 1.6 }}>{note.content}</div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
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

    if (activePage === 'Rules') {
      if (!canManageRules) {
        return (
          <section style={{ display: 'grid', placeItems: 'center', minHeight: '420px', padding: '2rem' }}>
            <div style={{ maxWidth: '540px', width: '100%', background: 'rgba(15, 23, 42, 0.42)', border: '1px solid rgba(148, 163, 184, 0.2)', borderRadius: '20px', padding: '2rem', textAlign: 'center' }}>
              <div style={{ fontSize: '0.72rem', letterSpacing: '0.12em', color: '#93c5fd', textTransform: 'uppercase' }}>Access Denied</div>
              <h2 style={{ margin: '0.75rem 0 0.5rem', fontSize: '2rem' }}>Rule editing is restricted.</h2>
              <p style={{ margin: 0, color: '#cbd5e1', lineHeight: 1.7 }}>Only administrators can create, edit, or delete detection rules.</p>
            </div>
          </section>
        );
      }
      return <RulesPage rules={rules} onRulesChange={setRules} />;
    }

    if (activePage === 'Threat Intel') {
      return <ThreatIntelPage iocs={iocs} onIOCsChange={setIOCs} />;
    }

    if (activePage === 'Reports') {
      return (
        <ReportsPage
          logs={logs}
          incidents={[...incidentLogs.map((log) => ({ log, triggerTimestamp: log.timestamp })), ...detectedIncidents]}
          cases={cases}
          rules={rules}
          ruleHitEvents={ruleHitEvents}
          analystName={auth.user.email}
        />
      );
    }

    if (false) {
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
                <div style={{ position: 'relative' }}>
                  <button type="button" onClick={() => setNotificationsOpen((value) => !value)} style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', width: '42px', height: '42px', borderRadius: '12px', border: '1px solid rgba(148, 163, 184, 0.2)', background: 'rgba(15, 23, 42, 0.72)', color: '#e2e8f0', cursor: 'pointer', position: 'relative' }}>
                    <span style={{ fontSize: '1.1rem' }}>🔔</span>
                    {unreadCount > 0 && (
                      <span style={{ position: 'absolute', top: '-5px', right: '-3px', minWidth: '18px', height: '18px', borderRadius: '999px', background: 'linear-gradient(135deg, #f97316, #ef4444)', color: '#fff', fontSize: '0.62rem', fontWeight: 800, display: 'inline-flex', alignItems: 'center', justifyContent: 'center', padding: '0 0.25rem' }}>{unreadCount}</span>
                    )}
                  </button>
                  {notificationsOpen && (
                    <div style={{ position: 'absolute', top: 'calc(100% + 12px)', right: 0, width: '340px', background: 'rgba(15, 23, 42, 0.96)', border: '1px solid rgba(148, 163, 184, 0.18)', borderRadius: '14px', boxShadow: '0 18px 32px rgba(2, 6, 23, 0.42)', padding: '0.7rem', zIndex: 60 }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.55rem', color: '#cbd5e1' }}>
                        <strong style={{ fontSize: '0.8rem' }}>Notifications</strong>
                        {unreadCount > 0 && <button type="button" onClick={markAllNotificationsRead} style={{ background: 'transparent', border: 'none', color: '#93c5fd', cursor: 'pointer', fontSize: '0.7rem', fontWeight: 700 }}>Mark all read</button>}
                      </div>
                      <div style={{ display: 'grid', gap: '0.5rem', maxHeight: '280px', overflowY: 'auto' }}>
                        {notifications.length === 0 ? (
                          <div style={{ color: '#cbd5e1', fontSize: '0.76rem', padding: '0.55rem 0' }}>No recent notifications.</div>
                        ) : notifications.slice(0, 6).map((notification) => (
                          <button key={notification.id} type="button" onClick={() => { markNotificationRead(notification.id); setNotificationsOpen(false); }} style={{ display: 'grid', gap: '0.15rem', width: '100%', textAlign: 'left', background: notification.read ? 'rgba(15, 23, 42, 0.7)' : 'rgba(59, 130, 246, 0.08)', border: '1px solid rgba(148, 163, 184, 0.12)', borderRadius: '10px', padding: '0.6rem 0.7rem', color: '#e2e8f0', cursor: 'pointer' }}>
                            <div style={{ display: 'flex', justifyContent: 'space-between', gap: '0.45rem' }}>
                              <strong style={{ fontSize: '0.74rem' }}>{notification.title}</strong>
                              {!notification.read && <span style={{ width: '8px', height: '8px', borderRadius: '50%', background: '#60a5fa', display: 'inline-block' }} />}
                            </div>
                            <span style={{ color: '#cbd5e1', fontSize: '0.7rem', lineHeight: 1.5 }}>{notification.message}</span>
                            <span style={{ color: '#94a3b8', fontSize: '0.65rem' }}>{new Date(notification.createdAt).toLocaleString()}</span>
                          </button>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
                <div style={{ display: 'flex', padding: '0.2rem', gap: '0.2rem', borderRadius: '10px', background: 'rgba(15, 23, 42, 0.7)', border: '1px solid rgba(148, 163, 184, 0.2)' }}>
                  <button type="button" style={{ border: '1px solid rgba(96, 165, 250, 0.35)', background: 'rgba(59, 130, 246, 0.18)', color: '#dbeafe', borderRadius: '8px', padding: '0.45rem 0.65rem', cursor: 'default', fontSize: '0.75rem', fontWeight: 700 }}>SOC Console</button>
                  <button type="button" onClick={() => setPortalMode('employee')} style={{ border: 'none', background: 'transparent', color: '#94a3b8', borderRadius: '8px', padding: '0.45rem 0.65rem', cursor: 'pointer', fontSize: '0.75rem' }}>Employee Portal</button>
                </div>
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
                  color: '#dbeafe',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '0.6rem',
                  flexWrap: 'wrap'
                }}>
                  <span>{auth.user.email}</span>
                  <span style={{
                    display: 'inline-flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    padding: '0.2rem 0.55rem',
                    borderRadius: '999px',
                    background: currentUserRole === 'admin' ? 'rgba(34, 197, 94, 0.14)' : currentUserRole === 'analyst' ? 'rgba(59, 130, 246, 0.14)' : 'rgba(168, 85, 247, 0.14)',
                    color: currentUserRole === 'admin' ? '#86efac' : currentUserRole === 'analyst' ? '#bfdbfe' : '#e9d5ff',
                    border: '1px solid rgba(148, 163, 184, 0.2)',
                    fontSize: '0.7rem',
                    fontWeight: 700,
                    letterSpacing: '0.08em',
                    textTransform: 'uppercase'
                  }}>{currentUserRoleLabel}</span>
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

        {toastNotifications.length > 0 && (
          <div style={{ position: 'fixed', right: '1.25rem', bottom: '1.25rem', display: 'grid', gap: '0.7rem', zIndex: 80 }}>
            <style>{`
              @keyframes toastIn {
                from { opacity: 0; transform: translateY(18px) scale(0.96); }
                to { opacity: 1; transform: translateY(0) scale(1); }
              }
            `}</style>
            {toastNotifications.map((toast) => (
              <div key={toast.id} style={{ minWidth: '320px', maxWidth: '360px', background: 'rgba(15, 23, 42, 0.92)', border: '1px solid rgba(96, 165, 250, 0.3)', borderRadius: '14px', boxShadow: '0 22px 40px rgba(15, 23, 42, 0.38)', padding: '0.8rem 0.9rem', color: '#e2e8f0', animation: 'toastIn 0.22s ease', backdropFilter: 'blur(14px)', WebkitBackdropFilter: 'blur(14px)' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '0.75rem', marginBottom: '0.25rem' }}>
                  <strong style={{ fontSize: '0.76rem', letterSpacing: '0.08em', textTransform: 'uppercase', color: '#93c5fd' }}>{toast.kind}</strong>
                  <button type="button" onClick={() => setToastNotifications((current) => current.filter((item) => item.id !== toast.id))} style={{ background: 'transparent', border: 'none', color: '#cbd5e1', cursor: 'pointer', fontSize: '0.75rem' }}>×</button>
                </div>
                <div style={{ fontWeight: 700, marginBottom: '0.2rem' }}>{toast.title}</div>
                <div style={{ color: '#cbd5e1', fontSize: '0.75rem', lineHeight: 1.5 }}>{toast.message}</div>
              </div>
            ))}
          </div>
        )}

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

            {drawerIncident.incident.triggeredByRule && (
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.55rem', flexWrap: 'wrap', marginBottom: '1rem', padding: '0.6rem 0.7rem', borderRadius: '10px', background: 'rgba(249, 115, 22, 0.12)', border: '1px solid rgba(249, 115, 22, 0.3)', color: '#fed7aa', fontSize: '0.75rem', fontWeight: 700 }}>
                <span>Triggered by: {drawerIncident.incident.triggeredByRule.name}</span>
                <span style={{ color: '#fdba74', fontWeight: 500 }}>{drawerIncident.incident.triggeredByRule.mitreTechnique} · {new Date(drawerIncident.incident.triggeredByRule.triggerTimestamp).toLocaleString()}</span>
              </div>
            )}
            {drawerIncident.incident.iocMatches?.map((match) => (
              <div key={`${match.value}-${match.threatFamily}`} style={{ display: 'flex', alignItems: 'center', gap: '0.55rem', flexWrap: 'wrap', marginBottom: '1rem', padding: '0.6rem 0.7rem', borderRadius: '10px', background: 'rgba(244, 63, 94, 0.12)', border: '1px solid rgba(244, 63, 94, 0.32)', color: '#fecdd3', fontSize: '0.75rem', fontWeight: 700 }}>
                <span>IOC Match</span>
                <span style={{ color: '#fda4af', fontWeight: 600 }}>{match.value} · {match.threatFamily}</span>
              </div>
            ))}

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
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.55rem', flexWrap: 'wrap', marginTop: '0.3rem' }}>
                  <h3 style={{ margin: 0, fontSize: '1.2rem' }}>{selectedCase.id}</h3>
                  {selectedCase.source === 'Employee Portal' && (
                    <span style={{ display: 'inline-flex', alignItems: 'center', borderRadius: '999px', background: 'rgba(59, 130, 246, 0.18)', border: '1px solid rgba(96, 165, 250, 0.28)', color: '#bfdbfe', padding: '0.18rem 0.56rem', fontSize: '0.62rem', fontWeight: 700, letterSpacing: '0.08em', textTransform: 'uppercase' }}>
                      Employee Portal
                    </span>
                  )}
                </div>
              </div>
              <button type="button" onClick={() => setSelectedCaseId(null)} style={{ width: '32px', height: '32px', borderRadius: '10px', border: '1px solid rgba(148, 163, 184, 0.2)', background: 'rgba(15, 23, 42, 0.7)', color: '#e2e8f0', cursor: 'pointer' }}>×</button>
            </div>

            <div style={{ display: 'grid', gap: '1rem' }}>
              <div style={{ background: 'rgba(15, 23, 42, 0.52)', border: '1px solid rgba(148, 163, 184, 0.16)', borderRadius: '12px', padding: '0.85rem' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '0.75rem', marginBottom: '0.55rem' }}>
                  <div style={{ color: '#93c5fd', fontSize: '0.68rem', letterSpacing: '0.08em', textTransform: 'uppercase' }}>SLA</div>
                  <span style={{ color: selectedCaseSla?.color ?? '#22c55e', fontWeight: 800, fontSize: '0.72rem', letterSpacing: '0.08em', textTransform: 'uppercase' }}>{selectedCaseSla?.label ?? 'Healthy'}</span>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '0.75rem', marginBottom: '0.45rem' }}>
                  <strong style={{ color: '#f8fafc' }}>{selectedCase.priority}</strong>
                  <span style={{ color: selectedCaseSla?.color ?? '#22c55e', fontWeight: 800 }}>{selectedCaseSla?.remainingText ?? 'Healthy'}</span>
                </div>
                <div style={{ width: '100%', height: '10px', borderRadius: '999px', background: 'rgba(148,163,184,0.14)', overflow: 'hidden' }}>
                  <div style={{ width: `${Math.max(0, Math.min(100, ((getSlaWindowMs(selectedCase.priority) - Math.max(0, selectedCaseSla?.remainingMs ?? 0)) / getSlaWindowMs(selectedCase.priority)) * 100))}%`, height: '100%', borderRadius: '999px', background: selectedCaseSla?.color ?? '#22c55e' }} />
                </div>
              </div>

              <div style={{ background: 'rgba(15, 23, 42, 0.52)', border: '1px solid rgba(148, 163, 184, 0.16)', borderRadius: '12px', padding: '0.85rem' }}>
                <div style={{ color: '#93c5fd', fontSize: '0.68rem', letterSpacing: '0.08em', textTransform: 'uppercase', marginBottom: '0.45rem' }}>Linked Incident</div>
                <div style={{ color: '#f8fafc', fontWeight: 700 }}>{selectedCase.incident.eventType} · {selectedCase.incident.id}</div>
                <div style={{ color: '#cbd5e1', fontSize: '0.8rem', lineHeight: 1.5, marginTop: '0.35rem' }}>{selectedCase.incident.message}</div>
              </div>

              <div style={{ background: 'rgba(15, 23, 42, 0.52)', border: '1px solid rgba(148, 163, 184, 0.16)', borderRadius: '12px', padding: '0.85rem' }}>
                <div style={{ color: '#93c5fd', fontSize: '0.68rem', letterSpacing: '0.08em', textTransform: 'uppercase', marginBottom: '0.7rem' }}>Evidence Panel</div>
                <div style={{ display: 'grid', gap: '0.6rem' }}>
                  {caseEvidenceLogs.length === 0 ? (
                    <div style={{ color: '#cbd5e1', fontSize: '0.78rem' }}>No related telemetry was matched for this case.</div>
                  ) : caseEvidenceLogs.map((log) => {
                    const expanded = expandedEvidenceId === log.id;
                    return (
                      <div key={log.id} style={{ background: 'rgba(15, 23, 42, 0.7)', border: '1px solid rgba(148, 163, 184, 0.16)', borderRadius: '10px', overflow: 'hidden' }}>
                        <button
                          type="button"
                          onClick={() => setExpandedEvidenceId(expanded ? null : log.id)}
                          style={{
                            width: '100%',
                            background: 'transparent',
                            border: 'none',
                            color: '#e2e8f0',
                            padding: '0.7rem 0.8rem',
                            textAlign: 'left',
                            cursor: 'pointer'
                          }}
                        >
                          <div style={{ display: 'flex', justifyContent: 'space-between', gap: '0.75rem', alignItems: 'center' }}>
                            <strong style={{ fontSize: '0.8rem' }}>{log.eventType}</strong>
                            <span style={{ color: log.severity === 'CRITICAL' ? '#fca5a5' : log.severity === 'HIGH' ? '#fbbf24' : '#93c5fd', fontSize: '0.68rem', fontWeight: 700 }}>{log.severity}</span>
                          </div>
                          <div style={{ color: '#cbd5e1', fontSize: '0.68rem', marginTop: '0.25rem' }}>{log.source} · {new Date(log.timestamp).toLocaleString()}</div>
                        </button>
                        {expanded && (
                          <div style={{ borderTop: '1px solid rgba(148, 163, 184, 0.12)', padding: '0.75rem 0.8rem', color: '#dbeafe', lineHeight: 1.6, fontSize: '0.76rem' }}>
                            {log.message}
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              </div>

              <div style={{ background: 'rgba(15, 23, 42, 0.52)', border: '1px solid rgba(148, 163, 184, 0.16)', borderRadius: '12px', padding: '0.85rem' }}>
                <div style={{ color: '#93c5fd', fontSize: '0.68rem', letterSpacing: '0.08em', textTransform: 'uppercase', marginBottom: '0.7rem' }}>Attack Timeline</div>
                <div style={{ display: 'grid', gap: '0.8rem', position: 'relative', paddingLeft: '0.85rem' }}>
                  <div style={{ position: 'absolute', left: '4px', top: '8px', bottom: '8px', width: '2px', background: 'rgba(96, 165, 250, 0.34)' }} />
                  {attackTimeline.map((entry) => (
                    <div key={entry.id} style={{ display: 'flex', gap: '0.75rem', position: 'relative' }}>
                      <div style={{ width: '10px', height: '10px', borderRadius: '50%', background: '#60a5fa', border: '2px solid rgba(15,23,42,0.9)', marginTop: '0.3rem', position: 'relative', zIndex: 1 }} />
                      <div style={{ flex: 1, background: 'rgba(15, 23, 42, 0.7)', border: '1px solid rgba(148, 163, 184, 0.18)', borderRadius: '10px', padding: '0.55rem 0.65rem' }}>
                        <div style={{ color: '#f8fafc', fontWeight: 700, fontSize: '0.82rem', marginBottom: '0.2rem' }}>{entry.label}</div>
                        <div style={{ color: '#cbd5e1', fontSize: '0.68rem' }}>{new Date(entry.timestamp).toLocaleString()} {entry.detail ? `· ${entry.detail}` : ''}</div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              <div style={{ background: 'rgba(15, 23, 42, 0.52)', border: '1px solid rgba(148, 163, 184, 0.16)', borderRadius: '12px', padding: '0.85rem' }}>
                <div style={{ color: '#93c5fd', fontSize: '0.68rem', letterSpacing: '0.08em', textTransform: 'uppercase', marginBottom: '0.7rem' }}>MITRE Intelligence</div>
                <div style={{ display: 'inline-flex', flexDirection: 'column', gap: '0.5rem', padding: '0.75rem', borderRadius: '10px', background: 'rgba(15, 23, 42, 0.8)', border: '1px solid rgba(148, 163, 184, 0.2)' }}>
                  <span style={{ display: 'inline-block', padding: '0.2rem 0.5rem', borderRadius: '9999px', background: mitreProfile.color, color: '#f8fafc', fontWeight: 700, fontSize: '0.72rem', letterSpacing: '0.04em', width: 'fit-content' }}>{mitreProfile.id}</span>
                  <div style={{ color: '#f8fafc', fontWeight: 700 }}>{mitreProfile.tactic}</div>
                  <div style={{ color: '#cbd5e1', fontSize: '0.74rem' }}>{mitreRecommendations[mitreProfile.id] ?? 'Review the mapped technique and validate whether additional telemetry is needed before escalating containment.'}</div>
                </div>
              </div>

              <div style={{ background: 'rgba(15, 23, 42, 0.52)', border: '1px solid rgba(148, 163, 184, 0.16)', borderRadius: '12px', padding: '0.85rem' }}>
                <div style={{ color: '#93c5fd', fontSize: '0.68rem', letterSpacing: '0.08em', textTransform: 'uppercase', marginBottom: '0.7rem' }}>Response Checklist</div>
                <div style={{ display: 'grid', gap: '0.6rem' }}>
                  {caseChecklistItems.map((task) => (
                    <label key={task} style={{ display: 'flex', alignItems: 'center', gap: '0.6rem', color: '#e2e8f0', fontSize: '0.8rem', cursor: 'pointer' }}>
                      <input
                        type="checkbox"
                        checked={Boolean(responseChecklist[task])}
                        onChange={() => setResponseChecklist((current) => ({ ...current, [task]: !Boolean(current[task]) }))}
                        style={{ accentColor: '#38bdf8' }}
                      />
                      <span>{task}</span>
                    </label>
                  ))}
                </div>
              </div>

              <div style={{ background: 'rgba(15, 23, 42, 0.52)', border: '1px solid rgba(148, 163, 184, 0.16)', borderRadius: '12px', padding: '0.85rem' }}>
                <div style={{ color: '#93c5fd', fontSize: '0.68rem', letterSpacing: '0.08em', textTransform: 'uppercase', marginBottom: '0.7rem' }}>Case Risk Score</div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
                  <div style={{ width: '92px', height: '92px', borderRadius: '50%', background: `conic-gradient(${riskColor} 0 ${caseRiskScore}%, rgba(148,163,184,0.18) ${caseRiskScore}% 100%)`, display: 'grid', placeItems: 'center' }}>
                    <div style={{ width: '66px', height: '66px', borderRadius: '50%', background: 'rgba(15, 23, 42, 0.9)', display: 'grid', placeItems: 'center', border: '1px solid rgba(148, 163, 184, 0.18)' }}>
                      <span style={{ fontSize: '1.15rem', fontWeight: 800, color: riskColor }}>{caseRiskScore}</span>
                    </div>
                  </div>
                  <div>
                    <div style={{ color: '#f8fafc', fontWeight: 800, fontSize: '1rem' }}>{riskBand}</div>
                    <div style={{ color: '#cbd5e1', fontSize: '0.76rem', marginTop: '0.2rem' }}>Severity + IOC + rule + related events</div>
                  </div>
                </div>
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
                    <select value={selectedCase.status} onChange={(event) => updateCaseStatus(event.target.value as CaseStatus)} disabled={!canEditCases} style={{ ...fieldStyle, marginTop: '0.35rem', opacity: canEditCases ? 1 : 0.6 }}>
                      {caseStatuses.map((status) => <option key={status} value={status}>{status}</option>)}
                    </select>
                  </label>
                  <label style={{ color: '#cbd5e1', fontSize: '0.78rem' }}>Assigned Analyst
                    <select value={selectedCase.assignedAnalyst} onChange={(event) => updateCaseAssignment(event.target.value as AnalystName)} disabled={!canEditCases} style={{ ...fieldStyle, marginTop: '0.35rem', opacity: canEditCases ? 1 : 0.6 }}>
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
