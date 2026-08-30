import { useState, type CSSProperties, type FormEvent } from 'react';
import type { IOC, IOCType } from '../types/ioc';

type IOCForm = Omit<IOC, 'id' | 'createdAt'>;

type ToastKind = 'Incident' | 'Case' | 'IOC' | 'Employee' | 'System';

type ThreatIntelPageProps = {
  iocs: IOC[];
  onIOCsChange: (iocs: IOC[]) => void;
  onToast?: (kind: ToastKind, title: string, message: string, onUndo: () => void) => void;
};

const iocTypes: IOCType[] = ['IP', 'Domain', 'Hash', 'Email'];
const intelSources = ['OpenCTI', 'MISP', 'Abuse.ch', 'VirusTotal', 'Internal Hunt', 'Analyst Report'];
const defaultIocs: IOC[] = [
  { id: 'ioc-ip-001', value: '203.0.113.42', type: 'IP', threatFamily: 'Credential Phishing', confidence: 96, source: 'MISP', enabled: true, createdAt: '2026-08-20T10:00:00.000Z' },
  { id: 'ioc-ip-002', value: '198.51.100.77', type: 'IP', threatFamily: 'Brute Force', confidence: 91, source: 'Abuse.ch', enabled: true, createdAt: '2026-08-21T10:00:00.000Z' },
  { id: 'ioc-ip-003', value: '45.76.102.18', type: 'IP', threatFamily: 'Network Scanning', confidence: 88, source: 'Internal Hunt', enabled: true, createdAt: '2026-08-22T10:00:00.000Z' },
  { id: 'ioc-domain-001', value: 'login-secure-check.com', type: 'Domain', threatFamily: 'Credential Phishing', confidence: 94, source: 'OpenCTI', enabled: true, createdAt: '2026-08-22T11:00:00.000Z' },
  { id: 'ioc-domain-002', value: 'cdn-update-service.net', type: 'Domain', threatFamily: 'Command and Control', confidence: 89, source: 'VirusTotal', enabled: true, createdAt: '2026-08-23T10:00:00.000Z' },
  { id: 'ioc-domain-003', value: 'exfil-storage.io', type: 'Domain', threatFamily: 'Data Exfiltration', confidence: 93, source: 'MISP', enabled: true, createdAt: '2026-08-24T10:00:00.000Z' },
  { id: 'ioc-hash-001', value: '44d88612fea8a8f36de82e1278abb02f', type: 'Hash', threatFamily: 'Ransomware', confidence: 98, source: 'VirusTotal', enabled: true, createdAt: '2026-08-24T11:00:00.000Z' },
  { id: 'ioc-hash-002', value: '098f6bcd4621d373cade4e832627b4f6', type: 'Hash', threatFamily: 'Malware Loader', confidence: 87, source: 'Abuse.ch', enabled: true, createdAt: '2026-08-25T10:00:00.000Z' },
  { id: 'ioc-email-001', value: 'invoice-review@malicious-mail.com', type: 'Email', threatFamily: 'Business Email Compromise', confidence: 90, source: 'Analyst Report', enabled: true, createdAt: '2026-08-26T10:00:00.000Z' },
  { id: 'ioc-email-002', value: 'security-alert@account-verify.net', type: 'Email', threatFamily: 'Credential Phishing', confidence: 95, source: 'OpenCTI', enabled: true, createdAt: '2026-08-27T10:00:00.000Z' }
];

export { defaultIocs };

const emptyForm: IOCForm = {
  value: '',
  type: 'IP',
  threatFamily: '',
  confidence: 80,
  source: 'Internal Hunt',
  enabled: true
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

function ThreatIntelPage({ iocs, onIOCsChange, onToast }: ThreatIntelPageProps) {
  const [form, setForm] = useState<IOCForm>(emptyForm);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [formError, setFormError] = useState('');

  const handleSubmit = (event: FormEvent) => {
    event.preventDefault();
    if (!form.value.trim() || !form.threatFamily.trim()) {
      setFormError('IOC value and threat family are required.');
      return;
    }
    if (form.confidence < 0 || form.confidence > 100) {
      setFormError('Confidence must be between 0 and 100.');
      return;
    }

    if (editingId) {
      onIOCsChange(iocs.map((ioc) => ioc.id === editingId ? { ...ioc, ...form, value: form.value.trim(), threatFamily: form.threatFamily.trim() } : ioc));
    } else {
      onIOCsChange([{
        ...form,
        value: form.value.trim(),
        threatFamily: form.threatFamily.trim(),
        id: `ioc-${Date.now()}`,
        createdAt: new Date().toISOString()
      }, ...iocs]);
    }

    setForm(emptyForm);
    setEditingId(null);
    setFormError('');
  };

  const editIOC = (ioc: IOC) => {
    const { id, createdAt, ...iocForm } = ioc;
    setEditingId(id);
    setForm(iocForm);
    setFormError('');
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  const deleteIOC = (iocId: string) => {
    const target = iocs.find((ioc) => ioc.id === iocId);
    if (!target) return;
    const previousIOCs = iocs;
    if (onToast) {
      onIOCsChange(iocs.filter((ioc) => ioc.id !== iocId));
      onToast('System', 'IOC deleted', `${target.value} was removed from threat intelligence.`, () => onIOCsChange(previousIOCs));
    } else if (window.confirm('Delete this IOC?')) {
      onIOCsChange(iocs.filter((ioc) => ioc.id !== iocId));
    }
    if (editingId === iocId) {
      setEditingId(null);
      setForm(emptyForm);
    }
  };

  return (
    <section style={{ display: 'flex', flexDirection: 'column', gap: '1.2rem' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'end', gap: '1rem', flexWrap: 'wrap' }}>
        <div>
          <div style={{ color: '#93c5fd', fontSize: '0.72rem', letterSpacing: '0.12em', textTransform: 'uppercase' }}>Threat Intelligence</div>
          <h2 style={{ margin: '0.25rem 0 0', fontSize: '1.5rem' }}>IOC Repository</h2>
        </div>
        <div style={{ color: '#cbd5e1', fontSize: '0.85rem' }}>{iocs.filter((ioc) => ioc.enabled).length} enabled · {iocs.length} total</div>
      </div>

      <form onSubmit={handleSubmit} style={{ ...panelStyle, padding: '1.1rem' }}>
        <div style={{ marginBottom: '1rem' }}>
          <div style={{ color: '#93c5fd', fontSize: '0.68rem', letterSpacing: '0.1em', textTransform: 'uppercase' }}>{editingId ? 'Edit IOC' : 'New IOC'}</div>
          <h3 style={{ margin: '0.25rem 0 0', fontSize: '1.05rem' }}>{editingId ? 'Update intelligence record' : 'Add intelligence record'}</h3>
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: 'minmax(200px, 1.3fr) repeat(4, minmax(130px, 0.8fr))', gap: '0.8rem', alignItems: 'end' }}>
          <label style={{ color: '#cbd5e1', fontSize: '0.78rem' }}>Value<input value={form.value} onChange={(event) => setForm({ ...form, value: event.target.value })} placeholder="203.0.113.42" style={{ ...inputStyle, marginTop: '0.35rem' }} /></label>
          <label style={{ color: '#cbd5e1', fontSize: '0.78rem' }}>Type<select value={form.type} onChange={(event) => setForm({ ...form, type: event.target.value as IOCType })} style={{ ...inputStyle, marginTop: '0.35rem' }}>{iocTypes.map((type) => <option key={type}>{type}</option>)}</select></label>
          <label style={{ color: '#cbd5e1', fontSize: '0.78rem' }}>Threat Family<input value={form.threatFamily} onChange={(event) => setForm({ ...form, threatFamily: event.target.value })} placeholder="Command and Control" style={{ ...inputStyle, marginTop: '0.35rem' }} /></label>
          <label style={{ color: '#cbd5e1', fontSize: '0.78rem' }}>Confidence (%)<input type="number" min="0" max="100" value={form.confidence} onChange={(event) => setForm({ ...form, confidence: Number(event.target.value) })} style={{ ...inputStyle, marginTop: '0.35rem' }} /></label>
          <label style={{ color: '#cbd5e1', fontSize: '0.78rem' }}>Source<select value={form.source} onChange={(event) => setForm({ ...form, source: event.target.value })} style={{ ...inputStyle, marginTop: '0.35rem' }}>{intelSources.map((source) => <option key={source}>{source}</option>)}</select></label>
          <label style={{ display: 'flex', alignItems: 'center', gap: '0.55rem', color: '#e2e8f0', fontSize: '0.82rem', paddingBottom: '0.7rem' }}><input type="checkbox" checked={form.enabled} onChange={(event) => setForm({ ...form, enabled: event.target.checked })} /> Enabled</label>
        </div>
        {formError && <div style={{ color: '#fda4af', fontSize: '0.82rem', marginTop: '0.8rem' }}>{formError}</div>}
        <div style={{ display: 'flex', gap: '0.55rem', marginTop: '1rem' }}>
          <button type="submit" style={{ border: '1px solid rgba(96, 165, 250, 0.55)', borderRadius: '10px', background: 'linear-gradient(135deg, #2563eb, #0ea5e9)', color: '#eff6ff', padding: '0.7rem 1rem', cursor: 'pointer', fontWeight: 700 }}>{editingId ? 'Save IOC' : 'Add IOC'}</button>
          {editingId && <button type="button" onClick={() => { setEditingId(null); setForm(emptyForm); }} style={{ border: '1px solid rgba(148, 163, 184, 0.22)', background: 'rgba(15, 23, 42, 0.72)', color: '#cbd5e1', borderRadius: '10px', padding: '0.7rem 1rem', cursor: 'pointer' }}>Cancel</button>}
        </div>
      </form>

      <div style={{ ...panelStyle, overflow: 'hidden' }}>
        <div style={{ padding: '1rem 1.1rem', borderBottom: '1px solid rgba(148, 163, 184, 0.16)' }}>
          <h3 style={{ margin: 0, fontSize: '1rem' }}>IOC Feed</h3>
          <div style={{ color: '#94a3b8', fontSize: '0.78rem', marginTop: '0.25rem' }}>Enabled indicators are checked against incoming event source and message content</div>
        </div>
        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', minWidth: '900px', borderCollapse: 'collapse', fontSize: '0.8rem' }}>
            <thead><tr style={{ color: '#93c5fd', textAlign: 'left', fontSize: '0.68rem', letterSpacing: '0.08em', textTransform: 'uppercase' }}>
              {['Value', 'Type', 'Threat Family', 'Confidence', 'Source', 'State', 'Actions'].map((heading) => <th key={heading} style={{ padding: '0.85rem 0.75rem', borderBottom: '1px solid rgba(148, 163, 184, 0.16)', whiteSpace: 'nowrap' }}>{heading}</th>)}
            </tr></thead>
            <tbody>{iocs.map((ioc) => <tr key={ioc.id} style={{ borderBottom: '1px solid rgba(148, 163, 184, 0.1)', color: '#e2e8f0' }}>
              <td style={{ padding: '0.9rem 0.75rem', fontWeight: 700, whiteSpace: 'nowrap' }}>{ioc.value}</td>
              <td style={{ padding: '0.9rem 0.75rem', color: '#bfdbfe' }}>{ioc.type}</td>
              <td style={{ padding: '0.9rem 0.75rem', color: '#cbd5e1' }}>{ioc.threatFamily}</td>
              <td style={{ padding: '0.9rem 0.75rem' }}><span style={{ color: ioc.confidence >= 90 ? '#86efac' : '#fcd34d', fontWeight: 800 }}>{ioc.confidence}%</span></td>
              <td style={{ padding: '0.9rem 0.75rem', color: '#cbd5e1' }}>{ioc.source}</td>
              <td style={{ padding: '0.9rem 0.75rem' }}><span style={{ color: ioc.enabled ? '#86efac' : '#94a3b8', fontWeight: 700 }}>{ioc.enabled ? 'Enabled' : 'Disabled'}</span></td>
              <td style={{ padding: '0.9rem 0.75rem' }}><div style={{ display: 'flex', gap: '0.4rem' }}><button type="button" onClick={() => editIOC(ioc)} style={{ border: '1px solid rgba(96, 165, 250, 0.35)', background: 'rgba(59, 130, 246, 0.12)', color: '#bfdbfe', borderRadius: '8px', padding: '0.4rem 0.55rem', cursor: 'pointer' }}>Edit</button><button type="button" onClick={() => deleteIOC(ioc.id)} style={{ border: '1px solid rgba(248, 113, 113, 0.35)', background: 'rgba(239, 68, 68, 0.1)', color: '#fca5a5', borderRadius: '8px', padding: '0.4rem 0.55rem', cursor: 'pointer' }}>Delete</button></div></td>
            </tr>)}
            {iocs.length === 0 && <tr><td colSpan={7} style={{ padding: '2rem', textAlign: 'center', color: '#94a3b8' }}>No indicators configured.</td></tr>}
            </tbody>
          </table>
        </div>
      </div>
    </section>
  );
}

export default ThreatIntelPage;
