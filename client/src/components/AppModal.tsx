import type { CSSProperties, ReactNode } from 'react';

type AppModalProps = {
  open: boolean;
  title: string;
  description?: string;
  submitLabel?: string;
  cancelLabel?: string;
  children: ReactNode;
  onClose: () => void;
  onSubmit?: () => void;
  disabled?: boolean;
  error?: string;
};

const panelStyle: CSSProperties = {
  background: 'rgba(15, 23, 42, 0.9)',
  border: '1px solid rgba(148, 163, 184, 0.2)',
  borderRadius: '18px',
  boxShadow: '0 24px 45px rgba(8, 15, 31, 0.35)',
  backdropFilter: 'blur(16px)',
  WebkitBackdropFilter: 'blur(16px)',
  width: 'min(680px, calc(100vw - 2rem))',
  maxHeight: 'calc(100vh - 2rem)',
  overflow: 'auto',
  color: '#e2e8f0'
};

export default function AppModal({
  open,
  title,
  description,
  submitLabel = 'Save',
  cancelLabel = 'Cancel',
  children,
  onClose,
  onSubmit,
  disabled = false,
  error
}: AppModalProps) {
  if (!open) return null;

  return (
    <div style={{ position: 'fixed', inset: 0, background: 'rgba(2, 6, 23, 0.7)', display: 'grid', placeItems: 'center', padding: '1rem', zIndex: 2000 }} onClick={onClose}>
      <div onClick={(event) => event.stopPropagation()} style={panelStyle}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: '1rem', padding: '1.1rem 1.1rem 0.7rem' }}>
          <div>
            <div style={{ color: '#93c5fd', fontSize: '0.7rem', letterSpacing: '0.12em', textTransform: 'uppercase' }}>Record</div>
            <h3 style={{ margin: '0.3rem 0 0', fontSize: '1.2rem' }}>{title}</h3>
            {description && <div style={{ color: '#cbd5e1', fontSize: '0.8rem', marginTop: '0.2rem' }}>{description}</div>}
          </div>
          <button type="button" onClick={onClose} style={{ width: '32px', height: '32px', borderRadius: '10px', border: '1px solid rgba(148, 163, 184, 0.2)', background: 'rgba(15, 23, 42, 0.7)', color: '#e2e8f0', cursor: 'pointer' }}>×</button>
        </div>

        <div style={{ padding: '0 1.1rem 1.1rem' }}>
          {children}
          {error && (
            <div style={{ marginTop: '0.8rem', color: '#fca5a5', fontSize: '0.82rem' }}>{error}</div>
          )}

          {onSubmit && (
            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.7rem', marginTop: '1rem' }}>
              <button type="button" onClick={onClose} style={{ border: '1px solid rgba(148, 163, 184, 0.22)', background: 'rgba(15, 23, 42, 0.72)', color: '#cbd5e1', borderRadius: '10px', padding: '0.7rem 1rem', cursor: 'pointer' }}>{cancelLabel}</button>
              <button type="button" onClick={onSubmit} disabled={disabled} style={{ border: '1px solid rgba(96, 165, 250, 0.55)', borderRadius: '10px', background: disabled ? 'rgba(59,130,246,0.35)' : 'linear-gradient(135deg, #2563eb, #0ea5e9)', color: '#eff6ff', padding: '0.7rem 1rem', cursor: disabled ? 'not-allowed' : 'pointer', fontWeight: 700 }}>{submitLabel}</button>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
