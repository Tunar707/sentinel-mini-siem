import { Severity } from '../types/log';

export const severityColors: Record<Severity, { background: string; color: string }> = {
  LOW: { background: '#374151', color: '#f3f4f6' },
  MEDIUM: { background: '#1d4ed8', color: '#eff6ff' },
  HIGH: { background: '#f59e0b', color: '#111827' },
  CRITICAL: { background: '#dc2626', color: '#fef2f2' }
};

function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span
      style={{
        display: 'inline-block',
        padding: '0.3rem 0.6rem',
        borderRadius: '9999px',
        fontWeight: 700,
        fontSize: '0.75rem',
        background: severityColors[severity].background,
        color: severityColors[severity].color
      }}
    >
      {severity}
    </span>
  );
}

export default SeverityBadge;
