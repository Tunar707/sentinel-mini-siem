import { useMemo, useState, type CSSProperties } from 'react';
import type { LogEntry } from '../types/log';
import type { DetectionRule } from '../types/rule';

type ReportIncident = {
  log: LogEntry;
  triggerTimestamp: string;
  ruleName?: string;
  iocMatches?: { value: string; threatFamily: string }[];
};

type ReportCase = {
  createdAt: string;
  incident: LogEntry;
};

type RuleHitEvent = {
  ruleId: string;
  timestamp: string;
};

type ReportsPageProps = {
  logs: LogEntry[];
  incidents: ReportIncident[];
  cases: ReportCase[];
  rules: DetectionRule[];
  ruleHitEvents: RuleHitEvent[];
  analystName: string;
};

type ReportRange = 'today' | '7d' | '30d' | 'custom';

const panelStyle: CSSProperties = {
  background: 'rgba(15, 23, 42, 0.42)',
  border: '1px solid rgba(148, 163, 184, 0.2)',
  borderRadius: '18px',
  boxShadow: '0 24px 45px rgba(8, 15, 31, 0.2)',
  backdropFilter: 'blur(16px)',
  WebkitBackdropFilter: 'blur(16px)'
};

const chartColors = ['#38bdf8', '#818cf8', '#f59e0b', '#fb7185', '#4ade80'];

const toDateInput = (date: Date) => date.toISOString().slice(0, 10);

function ReportsPage({ logs, incidents, cases, rules, ruleHitEvents, analystName }: ReportsPageProps) {
  const [range, setRange] = useState<ReportRange>('7d');
  const [customStart, setCustomStart] = useState(() => toDateInput(new Date(Date.now() - 6 * 24 * 60 * 60 * 1000)));
  const [customEnd, setCustomEnd] = useState(() => toDateInput(new Date()));

  const dateBounds = useMemo(() => {
    const now = new Date();
    const end = new Date(now);
    end.setHours(23, 59, 59, 999);
    const start = new Date(now);
    if (range === 'today') start.setHours(0, 0, 0, 0);
    if (range === '7d') start.setDate(start.getDate() - 6);
    if (range === '30d') start.setDate(start.getDate() - 29);
    if (range === 'custom') {
      const customStartDate = new Date(`${customStart}T00:00:00`);
      const customEndDate = new Date(`${customEnd}T23:59:59.999`);
      return { start: customStartDate, end: customEndDate };
    }
    return { start, end };
  }, [range, customStart, customEnd]);

  const inRange = (timestamp: string) => {
    const time = new Date(timestamp).getTime();
    return time >= dateBounds.start.getTime() && time <= dateBounds.end.getTime();
  };

  const filteredLogs = logs.filter((log) => inRange(log.timestamp));
  const filteredIncidents = incidents.filter((incident) => inRange(incident.triggerTimestamp));
  const filteredCases = cases.filter((item) => inRange(item.createdAt));
  const filteredRuleHits = ruleHitEvents.filter((hit) => inRange(hit.timestamp));
  const iocMatchCount = filteredIncidents.reduce((total, incident) => total + (incident.iocMatches?.length ?? 0), 0);
  const criticalIncidents = filteredIncidents.filter((incident) => incident.log.severity === 'CRITICAL');

  const severityCounts = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'].map((severity) => ({
    label: severity,
    value: filteredLogs.filter((log) => log.severity === severity).length
  }));
  const severityTotal = severityCounts.reduce((total, item) => total + item.value, 0) || 1;
  const sourceCounts = Object.entries(filteredLogs.reduce<Record<string, number>>((counts, log) => {
    counts[log.source] = (counts[log.source] ?? 0) + 1;
    return counts;
  }, {})).sort((a, b) => b[1] - a[1]).slice(0, 5);
  const ruleRanking = rules.map((rule) => ({
    name: rule.name,
    hits: filteredRuleHits.filter((hit) => hit.ruleId === rule.id).length
  })).sort((a, b) => b.hits - a.hits).slice(0, 5);

  const timelinePoints = useMemo(() => {
    const dayCount = Math.max(1, Math.ceil((dateBounds.end.getTime() - dateBounds.start.getTime()) / (24 * 60 * 60 * 1000)) + 1);
    const points = Array.from({ length: Math.min(dayCount, 31) }, (_, index) => {
      const day = new Date(dateBounds.start);
      day.setDate(day.getDate() + index);
      return { day, count: 0 };
    });
    filteredLogs.forEach((log) => {
      const logDate = new Date(log.timestamp);
      const index = Math.floor((new Date(logDate.getFullYear(), logDate.getMonth(), logDate.getDate()).getTime() - new Date(dateBounds.start.getFullYear(), dateBounds.start.getMonth(), dateBounds.start.getDate()).getTime()) / (24 * 60 * 60 * 1000));
      if (points[index]) points[index].count += 1;
    });
    const max = Math.max(...points.map((point) => point.count), 1);
    return points.map((point, index) => ({ ...point, index, x: points.length === 1 ? 50 : (index / (points.length - 1)) * 100, y: 94 - (point.count / max) * 78 }));
  }, [filteredLogs, dateBounds]);

  const linePath = timelinePoints.map((point, index) => `${index === 0 ? 'M' : 'L'} ${point.x} ${point.y}`).join(' ');
  const dateLabel = `${dateBounds.start.toLocaleDateString()} - ${dateBounds.end.toLocaleDateString()}`;
  const topIncidents = [...filteredIncidents].sort((a, b) => new Date(b.triggerTimestamp).getTime() - new Date(a.triggerTimestamp).getTime()).slice(0, 8);

  return (
    <section className="executive-report" style={{ display: 'flex', flexDirection: 'column', gap: '1.2rem' }}>
      <style>{`@media print { body { background: white !important; color: #111827 !important; } body * { visibility: hidden; } .executive-report, .executive-report * { visibility: visible; } .executive-report { position: absolute; left: 0; top: 0; width: 100%; } .report-no-print { display: none !important; } .report-panel { box-shadow: none !important; background: white !important; border: 1px solid #cbd5e1 !important; color: #111827 !important; } .report-panel * { color: #111827 !important; } }`}</style>
      <div className="report-no-print" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'end', gap: '1rem', flexWrap: 'wrap' }}>
        <div>
          <div style={{ color: '#93c5fd', fontSize: '0.72rem', letterSpacing: '0.12em', textTransform: 'uppercase' }}>Executive Reporting</div>
          <h2 style={{ margin: '0.25rem 0 0', fontSize: '1.5rem' }}>Security Operations Report</h2>
        </div>
        <button type="button" onClick={() => window.print()} style={{ border: '1px solid rgba(96, 165, 250, 0.55)', borderRadius: '10px', background: 'linear-gradient(135deg, #2563eb, #0ea5e9)', color: '#eff6ff', padding: '0.7rem 1rem', cursor: 'pointer', fontWeight: 700 }}>Export PDF</button>
      </div>

      <div className="report-no-print" style={{ ...panelStyle, padding: '1rem', display: 'flex', alignItems: 'end', gap: '0.8rem', flexWrap: 'wrap' }}>
        <label style={{ color: '#cbd5e1', fontSize: '0.78rem' }}>Reporting period<select value={range} onChange={(event) => setRange(event.target.value as ReportRange)} style={{ display: 'block', marginTop: '0.35rem', background: '#0f172a', color: '#e2e8f0', border: '1px solid rgba(148, 163, 184, 0.2)', borderRadius: '9px', padding: '0.6rem 0.7rem' }}><option value="today">Today</option><option value="7d">Last 7 Days</option><option value="30d">Last 30 Days</option><option value="custom">Custom date range</option></select></label>
        {range === 'custom' && <><label style={{ color: '#cbd5e1', fontSize: '0.78rem' }}>From<input type="date" value={customStart} onChange={(event) => setCustomStart(event.target.value)} style={{ display: 'block', marginTop: '0.35rem', padding: '0.58rem', background: '#0f172a', color: '#e2e8f0', border: '1px solid rgba(148, 163, 184, 0.2)', borderRadius: '9px' }} /></label><label style={{ color: '#cbd5e1', fontSize: '0.78rem' }}>To<input type="date" value={customEnd} onChange={(event) => setCustomEnd(event.target.value)} style={{ display: 'block', marginTop: '0.35rem', padding: '0.58rem', background: '#0f172a', color: '#e2e8f0', border: '1px solid rgba(148, 163, 184, 0.2)', borderRadius: '9px' }} /></label></>}
        <div style={{ color: '#93c5fd', fontSize: '0.8rem', paddingBottom: '0.65rem' }}>{dateLabel}</div>
      </div>

      <div className="report-panel" style={{ ...panelStyle, padding: '1.15rem' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', gap: '1rem', flexWrap: 'wrap', alignItems: 'center', marginBottom: '1rem' }}><div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}><div style={{ width: '36px', height: '36px', borderRadius: '11px', background: 'linear-gradient(135deg, #38bdf8, #2563eb)', display: 'grid', placeItems: 'center', fontWeight: 900, color: '#eff6ff' }}>S</div><div><div style={{ fontWeight: 900, letterSpacing: '0.12em', fontSize: '0.8rem' }}>SENTINEL</div><div style={{ color: '#94a3b8', fontSize: '0.7rem' }}>Executive Security Summary</div></div></div><div style={{ color: '#94a3b8', fontSize: '0.75rem' }}>Generated {new Date().toLocaleString()}</div></div>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(145px, 1fr))', gap: '0.7rem' }}>
          {[['Total Events', filteredLogs.length, '#38bdf8'], ['Total Incidents', filteredIncidents.length, '#fb7185'], ['Total Cases', filteredCases.length, '#a78bfa'], ['IOC Matches', iocMatchCount, '#f97316'], ['Rule Hits', filteredRuleHits.length, '#f59e0b'], ['Critical Incidents', criticalIncidents.length, '#ef4444']].map(([label, value, color]) => <div key={label as string} style={{ background: 'rgba(15, 23, 42, 0.55)', border: '1px solid rgba(148, 163, 184, 0.15)', borderRadius: '12px', padding: '0.8rem' }}><div style={{ color: '#94a3b8', fontSize: '0.66rem', letterSpacing: '0.06em', textTransform: 'uppercase' }}>{label}</div><div style={{ color: color as string, fontSize: '1.55rem', fontWeight: 900, marginTop: '0.35rem' }}>{value}</div></div>)}
        </div>
      </div>

      <div className="report-panel" style={{ display: 'grid', gridTemplateColumns: 'minmax(0, 1.5fr) minmax(240px, 0.8fr)', gap: '1rem' }}>
        <div style={{ ...panelStyle, padding: '1rem' }}><h3 style={{ margin: '0 0 0.8rem', fontSize: '1rem' }}>Events Over Time</h3><div style={{ height: '190px' }}><svg viewBox="0 0 100 100" width="100%" height="100%" preserveAspectRatio="none"><line x1="0" y1="94" x2="100" y2="94" stroke="rgba(148,163,184,0.35)" /><line x1="0" y1="55" x2="100" y2="55" stroke="rgba(148,163,184,0.15)" /><line x1="0" y1="16" x2="100" y2="16" stroke="rgba(148,163,184,0.15)" /><path d={`${linePath} L 100 94 L 0 94 Z`} fill="rgba(56,189,248,0.12)" /><path d={linePath} fill="none" stroke="#38bdf8" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" />{timelinePoints.map((point) => <circle key={point.index} cx={point.x} cy={point.y} r="1.7" fill="#e0f2fe" stroke="#38bdf8" strokeWidth="0.7" />)}</svg></div><div style={{ display: 'flex', justifyContent: 'space-between', color: '#94a3b8', fontSize: '0.68rem' }}><span>{timelinePoints[0]?.day.toLocaleDateString()}</span><span>{timelinePoints[timelinePoints.length - 1]?.day.toLocaleDateString()}</span></div></div>
        <div style={{ ...panelStyle, padding: '1rem' }}><h3 style={{ margin: '0 0 0.8rem', fontSize: '1rem' }}>Severity Distribution</h3><div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}><div style={{ width: '125px', height: '125px', borderRadius: '50%', background: `conic-gradient(#64748b 0% ${(severityCounts[0].value / severityTotal) * 100}%, #3b82f6 ${(severityCounts[0].value / severityTotal) * 100}% ${((severityCounts[0].value + severityCounts[1].value) / severityTotal) * 100}%, #f59e0b ${((severityCounts[0].value + severityCounts[1].value) / severityTotal) * 100}% ${((severityCounts[0].value + severityCounts[1].value + severityCounts[2].value) / severityTotal) * 100}%, #ef4444 ${((severityCounts[0].value + severityCounts[1].value + severityCounts[2].value) / severityTotal) * 100}% 100%)`, position: 'relative', flexShrink: 0 }}><div style={{ position: 'absolute', inset: '22px', borderRadius: '50%', background: '#0f172a', display: 'grid', placeItems: 'center', color: '#f8fafc', fontWeight: 800 }}>{filteredLogs.length}</div></div><div style={{ display: 'grid', gap: '0.42rem', fontSize: '0.74rem' }}>{severityCounts.map((item, index) => <div key={item.label} style={{ display: 'flex', gap: '0.45rem', alignItems: 'center' }}><span style={{ width: '8px', height: '8px', borderRadius: '50%', background: chartColors[index] }} /><span style={{ color: '#cbd5e1', minWidth: '60px' }}>{item.label}</span><strong>{item.value}</strong></div>)}</div></div></div>
      </div>

      <div className="report-panel" style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: '1rem' }}>
        <div style={{ ...panelStyle, padding: '1rem' }}><h3 style={{ margin: '0 0 0.9rem', fontSize: '1rem' }}>Top 5 Sources</h3>{sourceCounts.length === 0 ? <div style={{ color: '#94a3b8' }}>No events in this period.</div> : <div style={{ display: 'grid', gap: '0.75rem' }}>{sourceCounts.map(([source, count]) => <div key={source}><div style={{ display: 'flex', justifyContent: 'space-between', color: '#cbd5e1', fontSize: '0.76rem', marginBottom: '0.3rem' }}><span>{source}</span><strong>{count}</strong></div><div style={{ height: '8px', borderRadius: '999px', background: 'rgba(148,163,184,0.14)' }}><div style={{ height: '100%', width: `${(count / Math.max(sourceCounts[0][1], 1)) * 100}%`, borderRadius: '999px', background: 'linear-gradient(90deg, #38bdf8, #818cf8)' }} /></div></div>)}</div>}</div>
        <div style={{ ...panelStyle, padding: '1rem' }}><h3 style={{ margin: '0 0 0.9rem', fontSize: '1rem' }}>Rule Hit Ranking</h3>{ruleRanking.length === 0 ? <div style={{ color: '#94a3b8' }}>No rules configured.</div> : <div style={{ display: 'grid', gap: '0.7rem' }}>{ruleRanking.map((item, index) => <div key={item.name} style={{ display: 'grid', gridTemplateColumns: '24px 1fr auto', gap: '0.55rem', alignItems: 'center' }}><strong style={{ color: '#93c5fd' }}>0{index + 1}</strong><span style={{ color: '#cbd5e1', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{item.name}</span><strong>{item.hits}</strong></div>)}</div>}</div>
      </div>

      <div className="report-panel" style={{ ...panelStyle, overflow: 'hidden' }}><div style={{ padding: '1rem 1.1rem', borderBottom: '1px solid rgba(148, 163, 184, 0.16)', display: 'flex', justifyContent: 'space-between', gap: '1rem', flexWrap: 'wrap' }}><div><h3 style={{ margin: 0, fontSize: '1rem' }}>Top Incidents</h3><div style={{ color: '#94a3b8', fontSize: '0.75rem', marginTop: '0.25rem' }}>Analyst: {analystName} · {dateLabel}</div></div></div><div style={{ overflowX: 'auto' }}><table style={{ width: '100%', minWidth: '760px', borderCollapse: 'collapse', fontSize: '0.78rem' }}><thead><tr style={{ color: '#93c5fd', textAlign: 'left', textTransform: 'uppercase', fontSize: '0.66rem', letterSpacing: '0.07em' }}>{['Time', 'Event', 'Source', 'Severity', 'Signal'].map((heading) => <th key={heading} style={{ padding: '0.8rem 0.75rem', borderBottom: '1px solid rgba(148, 163, 184, 0.16)' }}>{heading}</th>)}</tr></thead><tbody>{topIncidents.map((incident) => <tr key={incident.log.id} style={{ borderBottom: '1px solid rgba(148, 163, 184, 0.1)' }}><td style={{ padding: '0.8rem 0.75rem', whiteSpace: 'nowrap', color: '#cbd5e1' }}>{new Date(incident.triggerTimestamp).toLocaleString()}</td><td style={{ padding: '0.8rem 0.75rem', color: '#f8fafc', fontWeight: 700 }}>{incident.log.eventType}</td><td style={{ padding: '0.8rem 0.75rem', color: '#cbd5e1' }}>{incident.log.source}</td><td style={{ padding: '0.8rem 0.75rem', color: '#fca5a5', fontWeight: 800 }}>{incident.log.severity}</td><td style={{ padding: '0.8rem 0.75rem', color: '#fdba74' }}>{incident.ruleName ? `Rule: ${incident.ruleName}` : incident.iocMatches?.map((match) => `IOC: ${match.value}`).join(', ') ?? 'Critical signal'}</td></tr>)}</tbody></table>{topIncidents.length === 0 && <div style={{ padding: '1.5rem', color: '#94a3b8' }}>No incidents in this period.</div>}</div></div>
    </section>
  );
}

export default ReportsPage;
