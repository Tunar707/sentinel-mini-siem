import type { CSSProperties } from 'react';

type EmptyStateProps = {
  icon: string;
  title: string;
  description: string;
  actionLabel?: string;
  onAction?: () => void;
};

const style: CSSProperties = {
  display: 'grid',
  placeItems: 'center',
  textAlign: 'center',
  padding: '2rem',
  borderRadius: '18px',
  border: '1px solid rgba(148, 163, 184, 0.18)',
  background: 'rgba(15, 23, 42, 0.28)',
  color: '#cbd5e1',
  minHeight: '220px'
};

export default function EmptyState({ icon, title, description, actionLabel, onAction }: EmptyStateProps) {
  return (
    <div style={style}>
      <div style={{ display: 'grid', gap: '0.8rem', maxWidth: '420px' }}>
        <div style={{ fontSize: '2rem' }}>{icon}</div>
        <div>
          <h3 style={{ margin: 0, color: '#f8fafc', fontSize: '1.2rem' }}>{title}</h3>
          <p style={{ margin: '0.55rem 0 0', lineHeight: 1.6 }}>{description}</p>
        </div>
        {actionLabel && onAction && (
          <button type="button" onClick={onAction} style={{ justifySelf: 'center', border: '1px solid rgba(96, 165, 250, 0.55)', borderRadius: '10px', background: 'linear-gradient(135deg, #2563eb, #0ea5e9)', color: '#eff6ff', padding: '0.7rem 1rem', cursor: 'pointer', fontWeight: 700 }}>
            {actionLabel}
          </button>
        )}
      </div>
    </div>
  );
}
