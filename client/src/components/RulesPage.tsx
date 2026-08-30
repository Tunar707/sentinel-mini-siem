import { useState, type CSSProperties, type FormEvent } from 'react';
import { getMitreMapping } from '../utils/mitre';
import type { Severity } from '../types/log';
import type { DetectionRule } from '../types/rule';

type RuleForm = Omit<DetectionRule, 'id' | 'createdAt' | 'hitCount' | 'lastTriggered'>;

const sourceOptions = ['Any Source', 'Auth Gateway', 'Firewall', 'Endpoint Agent', 'VPN', 'SIEM Correlation', 'Identity Provider', 'CloudTrail', 'Web Proxy', 'Kubernetes', 'Email Gateway'];
const eventTypeOptions = ['Failed Login', 'Malware Detection', 'Port Scan', 'Brute Force', 'Critical Alert', 'Privilege Escalation', 'Suspicious Process', 'Data Exfiltration', 'Lateral Movement', 'Shadow IT'];
const severityOptions: Severity[] = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
const techniqueOptions = ['T1110 - Brute Force', 'T1204 - User Execution', 'T1046 - Network Service Scanning', 'T1486 - Data Encrypted for Impact', 'T1068 - Exploitation for Privilege Escalation', 'T1059 - Command and Scripting Interpreter', 'N/A - Unmapped'];

export const defaultRules: DetectionRule[] = [
  { id: 'rule-brute-force', name: 'Brute Force Authentication', source: 'Auth Gateway', eventType: 'Failed Login', severity: 'CRITICAL', mitreTechnique: 'T1110 - Brute Force', thresholdCount: 5, timeWindowMinutes: 10, enabled: true, createdAt: '2026-08-30T00:00:00.000Z', hitCount: 0 },
  { id: 'rule-port-scan', name: 'Perimeter Port Sweep', source: 'Firewall', eventType: 'Port Scan', severity: 'HIGH', mitreTechnique: 'T1046 - Network Service Scanning', thresholdCount: 20, timeWindowMinutes: 5, enabled: true, createdAt: '2026-08-30T00:00:00.000Z', hitCount: 0 },
  { id: 'rule-malware', name: 'Endpoint Malware Signal', source: 'Endpoint Agent', eventType: 'Malware Detection', severity: 'CRITICAL', mitreTechnique: 'T1204 - User Execution', thresholdCount: 1, timeWindowMinutes: 15, enabled: true, createdAt: '2026-08-30T00:00:00.000Z', hitCount: 0 }
];

const emptyForm: RuleForm = {
  name: '',
  source: 'Any Source',
  eventType: 'Failed Login',
  severity: 'MEDIUM',
  mitreTechnique: 'T1110 - Brute Force',
  thresholdCount: 5,
  timeWindowMinutes: 10,
  enabled: true
};

type ToastKind = 'Incident' | 'Case' | 'IOC' | 'Employee' | 'System';

type RulesPageProps = {
  rules: DetectionRule[];
  onRulesChange: (rules: DetectionRule[]) => void;
  onToast?: (kind: ToastKind, title: string, message: string, onUndo: () => void) => void;
};

const panelStyle: CSSProperties = {
  background: 'rgba(15, 23, 42, 0.42)',
  border: '1px solid rgba(148, 163, 184, 0.2)',
  borderRadius: '18px',
  boxShadow: '0 24px 45px rgba(8, 15, 31, 0.2)',
  backdropFilter: 'blur(16px)',
  WebkitBackdropFilter: 'blur(16px)'
};

const inputStyle: CSSProperties = {
  width: '100%',
  boxSizing: 'border-box',
  borderRadius: '10px',
  border: '1px solid rgba(148, 163, 184, 0.2)',
  background: 'rgba(15, 23, 42, 0.78)',
  color: '#e2e8f0',
  padding: '0.65rem 0.7rem',
  outline: 'none'
};

function RulesPage({ rules, onRulesChange, onToast }: RulesPageProps) {
  const [form, setForm] = useState<RuleForm>(emptyForm);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [formError, setFormError] = useState('');

  const handleEventTypeChange = (eventType: string) => {
    const mapping = getMitreMapping(eventType);
    const matchingTechnique = techniqueOptions.find((option) => option.startsWith(mapping.id));
    setForm((current) => ({
      ...current,
      eventType,
      mitreTechnique: matchingTechnique ?? current.mitreTechnique
    }));
  };

  const handleSubmit = (event: FormEvent) => {
    event.preventDefault();
    if (!form.name.trim()) {
      setFormError('Rule name is required.');
      return;
    }
    if (form.thresholdCount < 1 || form.timeWindowMinutes < 1) {
      setFormError('Threshold and time window must be at least 1.');
      return;
    }

    if (editingId) {
      onRulesChange(rules.map((rule) => rule.id === editingId ? { ...rule, ...form, name: form.name.trim() } : rule));
    } else {
      onRulesChange([{
        ...form,
        name: form.name.trim(),
        id: `rule-${Date.now()}`,
        createdAt: new Date().toISOString(),
        hitCount: 0
      }, ...rules]);
    }

    setForm(emptyForm);
    setEditingId(null);
    setFormError('');
  };

  const editRule = (rule: DetectionRule) => {
    const { id, createdAt, ...ruleForm } = rule;
    setEditingId(id);
    setForm(ruleForm);
    setFormError('');
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  const deleteRule = (ruleId: string) => {
    const target = rules.find((rule) => rule.id === ruleId);
    if (!target) return;
    const previousRules = rules;
    if (onToast) {
      onRulesChange(rules.filter((rule) => rule.id !== ruleId));
      onToast('System', 'Rule deleted', `${target.name} was removed from the detection catalog.`, () => onRulesChange(previousRules));
    } else if (window.confirm('Delete this detection rule?')) {
      onRulesChange(rules.filter((rule) => rule.id !== ruleId));
    }
    if (editingId === ruleId) {
      setEditingId(null);
      setForm(emptyForm);
    }
  };

  const cancelEdit = () => {
    setEditingId(null);
    setForm(emptyForm);
    setFormError('');
  };

  return (
    <section style={{ display: 'flex', flexDirection: 'column', gap: '1.2rem' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'end', gap: '1rem', flexWrap: 'wrap' }}>
        <div>
          <div style={{ color: '#93c5fd', fontSize: '0.72rem', letterSpacing: '0.12em', textTransform: 'uppercase' }}>Detection Operations</div>
          <h2 style={{ margin: '0.25rem 0 0', fontSize: '1.5rem' }}>Detection Rules</h2>
        </div>
        <div style={{ color: '#cbd5e1', fontSize: '0.85rem' }}>{rules.filter((rule) => rule.enabled).length} enabled · {rules.length} total</div>
      </div>

      <form onSubmit={handleSubmit} style={{ ...panelStyle, padding: '1.1rem' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '1rem', flexWrap: 'wrap', marginBottom: '1rem' }}>
          <div>
            <div style={{ color: '#93c5fd', fontSize: '0.68rem', letterSpacing: '0.1em', textTransform: 'uppercase' }}>{editingId ? 'Edit Rule' : 'New Rule'}</div>
            <h3 style={{ margin: '0.25rem 0 0', fontSize: '1.05rem' }}>{editingId ? 'Update detection logic' : 'Create detection logic'}</h3>
          </div>
          {editingId && <button type="button" onClick={cancelEdit} style={{ border: '1px solid rgba(148, 163, 184, 0.22)', background: 'rgba(15, 23, 42, 0.72)', color: '#cbd5e1', borderRadius: '9px', padding: '0.55rem 0.75rem', cursor: 'pointer' }}>Cancel</button>}
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '0.8rem' }}>
          <label style={{ color: '#cbd5e1', fontSize: '0.78rem' }}>Name<input value={form.name} onChange={(event) => setForm({ ...form, name: event.target.value })} placeholder="e.g. Suspicious Login Burst" style={{ ...inputStyle, marginTop: '0.35rem' }} /></label>
          <label style={{ color: '#cbd5e1', fontSize: '0.78rem' }}>Source<select value={form.source} onChange={(event) => setForm({ ...form, source: event.target.value })} style={{ ...inputStyle, marginTop: '0.35rem' }}>{sourceOptions.map((option) => <option key={option}>{option}</option>)}</select></label>
          <label style={{ color: '#cbd5e1', fontSize: '0.78rem' }}>Event Type<select value={form.eventType} onChange={(event) => handleEventTypeChange(event.target.value)} style={{ ...inputStyle, marginTop: '0.35rem' }}>{eventTypeOptions.map((option) => <option key={option}>{option}</option>)}</select></label>
          <label style={{ color: '#cbd5e1', fontSize: '0.78rem' }}>Severity<select value={form.severity} onChange={(event) => setForm({ ...form, severity: event.target.value as Severity })} style={{ ...inputStyle, marginTop: '0.35rem' }}>{severityOptions.map((option) => <option key={option}>{option}</option>)}</select></label>
          <label style={{ color: '#cbd5e1', fontSize: '0.78rem' }}>MITRE Technique<select value={form.mitreTechnique} onChange={(event) => setForm({ ...form, mitreTechnique: event.target.value })} style={{ ...inputStyle, marginTop: '0.35rem' }}>{techniqueOptions.map((option) => <option key={option}>{option}</option>)}</select></label>
          <label style={{ color: '#cbd5e1', fontSize: '0.78rem' }}>Threshold Count<input type="number" min="1" value={form.thresholdCount} onChange={(event) => setForm({ ...form, thresholdCount: Number(event.target.value) })} style={{ ...inputStyle, marginTop: '0.35rem' }} /></label>
          <label style={{ color: '#cbd5e1', fontSize: '0.78rem' }}>Time Window (minutes)<input type="number" min="1" value={form.timeWindowMinutes} onChange={(event) => setForm({ ...form, timeWindowMinutes: Number(event.target.value) })} style={{ ...inputStyle, marginTop: '0.35rem' }} /></label>
          <label style={{ display: 'flex', alignItems: 'center', gap: '0.6rem', color: '#e2e8f0', fontSize: '0.82rem', paddingTop: '1.35rem' }}><input type="checkbox" checked={form.enabled} onChange={(event) => setForm({ ...form, enabled: event.target.checked })} /> Enabled</label>
        </div>
        {formError && <div style={{ color: '#fda4af', fontSize: '0.82rem', marginTop: '0.8rem' }}>{formError}</div>}
        <button type="submit" style={{ marginTop: '1rem', border: '1px solid rgba(96, 165, 250, 0.55)', borderRadius: '10px', background: 'linear-gradient(135deg, #2563eb, #0ea5e9)', color: '#eff6ff', padding: '0.7rem 1rem', cursor: 'pointer', fontWeight: 700 }}>{editingId ? 'Save Rule' : 'Create Rule'}</button>
      </form>

      <div style={{ ...panelStyle, overflow: 'hidden' }}>
        <div style={{ padding: '1rem 1.1rem', borderBottom: '1px solid rgba(148, 163, 184, 0.16)', display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '1rem' }}>
          <div><h3 style={{ margin: 0, fontSize: '1rem' }}>Rule Catalog</h3><div style={{ color: '#94a3b8', fontSize: '0.78rem', marginTop: '0.25rem' }}>Threshold-based rules for monitored event streams</div></div>
        </div>
        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', minWidth: '1050px', borderCollapse: 'collapse', fontSize: '0.8rem' }}>
            <thead><tr style={{ color: '#93c5fd', textAlign: 'left', fontSize: '0.68rem', letterSpacing: '0.08em', textTransform: 'uppercase' }}>
              {['Rule', 'Source', 'Event Type', 'Severity', 'MITRE', 'Threshold', 'Window', 'Hits', 'Last Triggered', 'State', 'Actions'].map((heading) => <th key={heading} style={{ padding: '0.85rem 0.75rem', borderBottom: '1px solid rgba(148, 163, 184, 0.16)', whiteSpace: 'nowrap' }}>{heading}</th>)}
            </tr></thead>
            <tbody>
              {rules.map((rule) => <tr key={rule.id} style={{ borderBottom: '1px solid rgba(148, 163, 184, 0.1)', color: '#e2e8f0' }}>
                <td style={{ padding: '0.9rem 0.75rem', fontWeight: 700 }}>{rule.name}<div style={{ color: '#64748b', fontSize: '0.68rem', marginTop: '0.2rem' }}>{rule.id}</div></td>
                <td style={{ padding: '0.9rem 0.75rem', color: '#cbd5e1' }}>{rule.source}</td>
                <td style={{ padding: '0.9rem 0.75rem', color: '#cbd5e1' }}>{rule.eventType}</td>
                <td style={{ padding: '0.9rem 0.75rem' }}><span style={{ color: rule.severity === 'CRITICAL' ? '#fca5a5' : rule.severity === 'HIGH' ? '#fcd34d' : '#bfdbfe', fontWeight: 800 }}>{rule.severity}</span></td>
                <td style={{ padding: '0.9rem 0.75rem', color: '#cbd5e1' }}>{rule.mitreTechnique}</td>
                <td style={{ padding: '0.9rem 0.75rem', color: '#cbd5e1' }}>{rule.thresholdCount} events</td>
                <td style={{ padding: '0.9rem 0.75rem', color: '#cbd5e1' }}>{rule.timeWindowMinutes} min</td>
                <td style={{ padding: '0.9rem 0.75rem', color: '#f8fafc', fontWeight: 700 }}>{rule.hitCount ?? 0}</td>
                <td style={{ padding: '0.9rem 0.75rem', color: '#cbd5e1', whiteSpace: 'nowrap' }}>{rule.lastTriggered ? new Date(rule.lastTriggered).toLocaleString() : 'Never'}</td>
                <td style={{ padding: '0.9rem 0.75rem' }}><span style={{ display: 'inline-flex', alignItems: 'center', gap: '0.35rem', color: rule.enabled ? '#86efac' : '#94a3b8', fontWeight: 700 }}><span style={{ width: '7px', height: '7px', borderRadius: '50%', background: rule.enabled ? '#4ade80' : '#64748b' }} />{rule.enabled ? 'Enabled' : 'Disabled'}</span></td>
                <td style={{ padding: '0.9rem 0.75rem' }}><div style={{ display: 'flex', gap: '0.4rem' }}><button type="button" onClick={() => editRule(rule)} style={{ border: '1px solid rgba(96, 165, 250, 0.35)', background: 'rgba(59, 130, 246, 0.12)', color: '#bfdbfe', borderRadius: '8px', padding: '0.4rem 0.55rem', cursor: 'pointer' }}>Edit</button><button type="button" onClick={() => deleteRule(rule.id)} style={{ border: '1px solid rgba(248, 113, 113, 0.35)', background: 'rgba(239, 68, 68, 0.1)', color: '#fca5a5', borderRadius: '8px', padding: '0.4rem 0.55rem', cursor: 'pointer' }}>Delete</button></div></td>
              </tr>)}
              {rules.length === 0 && <tr><td colSpan={11} style={{ padding: '2rem', textAlign: 'center', color: '#94a3b8' }}>No detection rules configured.</td></tr>}
            </tbody>
          </table>
        </div>
      </div>
    </section>
  );
}

export default RulesPage;
