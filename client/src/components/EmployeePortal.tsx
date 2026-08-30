import { useMemo, useState, type CSSProperties, type FormEvent } from 'react';

type EmployeePage = 'Dashboard' | 'My Tickets';
export type TicketStatus = 'Open' | 'Investigating' | 'Resolved';
export type TicketPriority = 'P1' | 'P2' | 'P3' | 'P4';

type TicketTimelineEntry = {
  id: string;
  timestamp: string;
  message: string;
};

export type EmployeeTicket = {
  id: string;
  caseId?: string;
  incidentType: string;
  priority: TicketPriority;
  department: string;
  device: string;
  description: string;
  attachmentName?: string;
  status: TicketStatus;
  createdAt: string;
  assignedAnalyst: string;
  timeline: TicketTimelineEntry[];
};

type EmployeePortalProps = {
  employeeName: string;
  tickets: EmployeeTicket[];
  onTicketSubmit: (ticket: EmployeeTicket) => void;
  onSwitchToSOC: () => void;
  onLogout: () => void;
};

type TicketForm = Omit<EmployeeTicket, 'id' | 'status' | 'createdAt' | 'assignedAnalyst' | 'timeline'>;

const priorities: TicketPriority[] = ['P1', 'P2', 'P3', 'P4'];
const incidentTypes = ['Phishing Email', 'Suspicious Login', 'Malware Alert', 'Lost or Stolen Device', 'Unauthorized Access', 'Other'];
const departments = ['Finance', 'Human Resources', 'Legal', 'Engineering', 'Sales', 'Operations', 'Other'];
const emptyForm: TicketForm = { incidentType: 'Phishing Email', priority: 'P3', department: 'Operations', device: '', description: '', attachmentName: '' };

const panelStyle: CSSProperties = {
  background: 'rgba(15, 23, 42, 0.48)',
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
  padding: '0.7rem 0.75rem',
  outline: 'none'
};

function EmployeePortal({ employeeName, tickets, onTicketSubmit, onSwitchToSOC, onLogout }: EmployeePortalProps) {
  const [page, setPage] = useState<EmployeePage>('Dashboard');
  const [form, setForm] = useState<TicketForm>(emptyForm);
  const [formError, setFormError] = useState('');
  const [submitted, setSubmitted] = useState('');

  const counts = useMemo(() => ({
    open: tickets.filter((ticket) => ticket.status === 'Open').length,
    investigating: tickets.filter((ticket) => ticket.status === 'Investigating').length,
    resolved: tickets.filter((ticket) => ticket.status === 'Resolved').length
  }), [tickets]);

  const handleSubmit = (event: FormEvent) => {
    event.preventDefault();
    if (!form.device.trim() || !form.description.trim()) {
      setFormError('Device and description are required.');
      return;
    }

    const createdAt = new Date().toISOString();
    const ticketId = `TKT-${createdAt.slice(0, 10).replace(/-/g, '')}-${Math.random().toString(36).slice(2, 7).toUpperCase()}`;
    const ticket: EmployeeTicket = {
      ...form,
      device: form.device.trim(),
      description: form.description.trim(),
      id: ticketId,
      status: 'Open',
      createdAt,
      assignedAnalyst: 'Pending triage',
      timeline: [{ id: `${ticketId}-created`, timestamp: createdAt, message: 'Ticket submitted by employee' }]
    };

    onTicketSubmit(ticket);
    setForm(emptyForm);
    setFormError('');
    setSubmitted(`${ticketId} submitted successfully.`);
    setPage('My Tickets');
  };

  return (
    <div style={{ minHeight: '100vh', background: 'linear-gradient(135deg, #0f172a 0%, #0b1f3a 45%, #123a72 100%)', color: '#e2e8f0', fontFamily: 'Inter, system-ui, sans-serif', padding: '1.25rem' }}>
      <header style={{ ...panelStyle, padding: '1rem 1.25rem', marginBottom: '1.2rem' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '1rem', flexWrap: 'wrap' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
            <div style={{ width: '38px', height: '38px', borderRadius: '12px', background: 'linear-gradient(135deg, #38bdf8, #2563eb)', display: 'grid', placeItems: 'center', fontWeight: 900, color: '#eff6ff' }}>S</div>
            <div><div style={{ color: '#93c5fd', fontSize: '0.7rem', letterSpacing: '0.14em', textTransform: 'uppercase' }}>Sentinel</div><div style={{ fontWeight: 800 }}>Employee Portal</div></div>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.55rem', flexWrap: 'wrap' }}>
            <div style={{ display: 'flex', padding: '0.2rem', gap: '0.2rem', borderRadius: '10px', background: 'rgba(15, 23, 42, 0.7)', border: '1px solid rgba(148, 163, 184, 0.2)' }}>
              <button type="button" onClick={onSwitchToSOC} style={{ border: 'none', background: 'transparent', color: '#94a3b8', borderRadius: '8px', padding: '0.45rem 0.65rem', cursor: 'pointer', fontSize: '0.75rem' }}>SOC Console</button>
              <button type="button" style={{ border: '1px solid rgba(96, 165, 250, 0.35)', background: 'rgba(59, 130, 246, 0.18)', color: '#dbeafe', borderRadius: '8px', padding: '0.45rem 0.65rem', cursor: 'default', fontSize: '0.75rem', fontWeight: 700 }}>Employee Portal</button>
            </div>
            <span style={{ color: '#cbd5e1', fontSize: '0.8rem' }}>{employeeName}</span>
            <button type="button" onClick={onLogout} style={{ border: '1px solid rgba(148, 163, 184, 0.2)', background: 'rgba(15, 23, 42, 0.65)', color: '#e2e8f0', borderRadius: '9px', padding: '0.5rem 0.7rem', cursor: 'pointer', fontWeight: 600 }}>Logout</button>
          </div>
        </div>
      </header>

      <main style={{ maxWidth: '1220px', margin: '0 auto' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'end', gap: '1rem', flexWrap: 'wrap', marginBottom: '1rem' }}>
          <div><div style={{ color: '#93c5fd', fontSize: '0.72rem', letterSpacing: '0.12em', textTransform: 'uppercase' }}>Workplace Security</div><h1 style={{ margin: '0.25rem 0 0', fontSize: '1.65rem' }}>{page === 'Dashboard' ? 'How can we help?' : 'My Tickets'}</h1></div>
          <nav style={{ display: 'flex', gap: '0.45rem' }}><button type="button" onClick={() => setPage('Dashboard')} style={{ border: '1px solid rgba(148, 163, 184, 0.2)', background: page === 'Dashboard' ? 'rgba(59, 130, 246, 0.18)' : 'rgba(15, 23, 42, 0.52)', color: '#e2e8f0', borderRadius: '9px', padding: '0.55rem 0.7rem', cursor: 'pointer' }}>Dashboard</button><button type="button" onClick={() => setPage('My Tickets')} style={{ border: '1px solid rgba(148, 163, 184, 0.2)', background: page === 'My Tickets' ? 'rgba(59, 130, 246, 0.18)' : 'rgba(15, 23, 42, 0.52)', color: '#e2e8f0', borderRadius: '9px', padding: '0.55rem 0.7rem', cursor: 'pointer' }}>My Tickets</button></nav>
        </div>

        {page === 'Dashboard' ? <>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '0.9rem', marginBottom: '1rem' }}>
            {[['Open Tickets', counts.open, '#38bdf8'], ['Investigating', counts.investigating, '#f59e0b'], ['Resolved', counts.resolved, '#4ade80']].map(([label, value, color]) => <div key={label as string} style={{ ...panelStyle, padding: '1rem' }}><div style={{ color: '#94a3b8', fontSize: '0.7rem', letterSpacing: '0.08em', textTransform: 'uppercase' }}>{label}</div><div style={{ color: color as string, fontSize: '2rem', fontWeight: 900, marginTop: '0.5rem' }}>{value}</div></div>)}
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: 'minmax(0, 1.25fr) minmax(280px, 0.75fr)', gap: '1rem' }}>
            <form onSubmit={handleSubmit} style={{ ...panelStyle, padding: '1.1rem' }}>
              <div style={{ marginBottom: '1rem' }}><div style={{ color: '#93c5fd', fontSize: '0.68rem', letterSpacing: '0.1em', textTransform: 'uppercase' }}>Employee Request</div><h2 style={{ margin: '0.25rem 0 0', fontSize: '1.15rem' }}>Report Incident</h2></div>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, minmax(0, 1fr))', gap: '0.8rem' }}>
                <label style={{ color: '#cbd5e1', fontSize: '0.78rem' }}>Incident Type<select value={form.incidentType} onChange={(event) => setForm({ ...form, incidentType: event.target.value })} style={{ ...inputStyle, marginTop: '0.35rem' }}>{incidentTypes.map((type) => <option key={type}>{type}</option>)}</select></label>
                <label style={{ color: '#cbd5e1', fontSize: '0.78rem' }}>Priority<select value={form.priority} onChange={(event) => setForm({ ...form, priority: event.target.value as TicketPriority })} style={{ ...inputStyle, marginTop: '0.35rem' }}>{priorities.map((priority) => <option key={priority}>{priority}</option>)}</select></label>
                <label style={{ color: '#cbd5e1', fontSize: '0.78rem' }}>Department<select value={form.department} onChange={(event) => setForm({ ...form, department: event.target.value })} style={{ ...inputStyle, marginTop: '0.35rem' }}>{departments.map((department) => <option key={department}>{department}</option>)}</select></label>
                <label style={{ color: '#cbd5e1', fontSize: '0.78rem' }}>Device<input value={form.device} onChange={(event) => setForm({ ...form, device: event.target.value })} placeholder="Laptop, phone, or asset ID" style={{ ...inputStyle, marginTop: '0.35rem' }} /></label>
              </div>
              <label style={{ display: 'block', color: '#cbd5e1', fontSize: '0.78rem', marginTop: '0.8rem' }}>Markdown Description<textarea value={form.description} onChange={(event) => setForm({ ...form, description: event.target.value })} placeholder="Describe what happened, when, and what you observed..." rows={6} style={{ ...inputStyle, marginTop: '0.35rem', resize: 'vertical' }} /></label>
              <label style={{ display: 'block', color: '#cbd5e1', fontSize: '0.78rem', marginTop: '0.8rem' }}>Attachment<input type="file" disabled style={{ ...inputStyle, marginTop: '0.35rem', opacity: 0.55 }} /></label>
              {formError && <div style={{ color: '#fda4af', fontSize: '0.82rem', marginTop: '0.7rem' }}>{formError}</div>}
              {submitted && <div style={{ color: '#86efac', fontSize: '0.82rem', marginTop: '0.7rem' }}>{submitted}</div>}
              <button type="submit" style={{ marginTop: '1rem', border: '1px solid rgba(96, 165, 250, 0.55)', borderRadius: '10px', background: 'linear-gradient(135deg, #2563eb, #0ea5e9)', color: '#eff6ff', padding: '0.7rem 1rem', cursor: 'pointer', fontWeight: 700 }}>Submit Incident</button>
            </form>
            <section style={{ ...panelStyle, padding: '1.1rem' }}><div style={{ color: '#93c5fd', fontSize: '0.68rem', letterSpacing: '0.1em', textTransform: 'uppercase', marginBottom: '0.8rem' }}>Recent Activity</div>{tickets.length === 0 ? <p style={{ margin: 0, color: '#94a3b8', lineHeight: 1.6 }}>Your submitted incidents and analyst updates will appear here.</p> : <div style={{ display: 'grid', gap: '0.8rem' }}>{tickets.slice(0, 5).map((ticket) => <div key={ticket.id} style={{ borderLeft: '2px solid #38bdf8', paddingLeft: '0.7rem' }}><div style={{ color: '#f8fafc', fontWeight: 700, fontSize: '0.82rem' }}>{ticket.incidentType} submitted</div><div style={{ color: '#94a3b8', fontSize: '0.72rem', marginTop: '0.25rem' }}>{ticket.id} · {new Date(ticket.createdAt).toLocaleString()}</div></div>)}</div>}</section>
          </div>
        </> : <section style={{ ...panelStyle, overflow: 'hidden' }}>
          {tickets.length === 0 ? <div style={{ padding: '2rem', color: '#94a3b8' }}>No tickets submitted yet.</div> : <div style={{ overflowX: 'auto' }}><table style={{ width: '100%', minWidth: '820px', borderCollapse: 'collapse', fontSize: '0.8rem' }}><thead><tr style={{ color: '#93c5fd', textAlign: 'left', fontSize: '0.68rem', letterSpacing: '0.08em', textTransform: 'uppercase' }}>{['Ticket ID', 'Status', 'Created', 'Priority', 'Assigned Analyst', 'Timeline'].map((heading) => <th key={heading} style={{ padding: '0.9rem 0.75rem', borderBottom: '1px solid rgba(148, 163, 184, 0.16)' }}>{heading}</th>)}</tr></thead><tbody>{tickets.map((ticket) => <tr key={ticket.id} style={{ borderBottom: '1px solid rgba(148, 163, 184, 0.1)' }}><td style={{ padding: '0.9rem 0.75rem', color: '#bfdbfe', fontWeight: 800 }}>{ticket.id}<div style={{ color: '#cbd5e1', fontWeight: 500, marginTop: '0.25rem' }}>{ticket.incidentType}</div></td><td style={{ padding: '0.9rem 0.75rem', color: ticket.status === 'Resolved' ? '#86efac' : '#fcd34d', fontWeight: 700 }}>{ticket.status}</td><td style={{ padding: '0.9rem 0.75rem', color: '#cbd5e1', whiteSpace: 'nowrap' }}>{new Date(ticket.createdAt).toLocaleDateString()}</td><td style={{ padding: '0.9rem 0.75rem', color: ticket.priority === 'P1' ? '#fca5a5' : '#fcd34d', fontWeight: 800 }}>{ticket.priority}</td><td style={{ padding: '0.9rem 0.75rem', color: '#cbd5e1' }}>{ticket.assignedAnalyst}</td><td style={{ padding: '0.9rem 0.75rem', color: '#cbd5e1' }}><div style={{ display: 'grid', gap: '0.35rem' }}>{ticket.timeline.map((entry) => <div key={entry.id}><strong style={{ color: '#e2e8f0' }}>{entry.message}</strong><div style={{ color: '#64748b', fontSize: '0.68rem' }}>{new Date(entry.timestamp).toLocaleString()}</div></div>)}</div></td></tr>)}</tbody></table></div>}
        </section>}
      </main>
    </div>
  );
}

export default EmployeePortal;
