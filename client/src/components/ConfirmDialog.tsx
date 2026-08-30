import type { CSSProperties } from 'react';

type ConfirmDialogProps = {
  open: boolean;
  title: string;
  message: string;
  confirmLabel?: string;
  cancelLabel?: string;
  onConfirm: () => void;
  onCancel: () => void;
};

const panelStyle: CSSProperties = {
  background: 'rgba(15, 23, 42, 0.92)',
  border: '1px solid rgba(248, 113, 113, 0.28)',
  borderRadius: '18px',
  boxShadow: '0 24px 45px rgba(8, 15, 31, 0.35)',
  backdropFilter: 'blur(16px)',
  WebkitBackdropFilter: 'blur(16px)',
  width: 'min(420px, calc(100vw - 2rem))',
  color: '#e2e8f0'
};

export default function ConfirmDialog({
  open,
  title,
  message,
  confirmLabel = 'Delete',
  cancelLabel = 'Cancel',
  onConfirm,
  onCancel
}: ConfirmDialogProps) {
  if (!open) return null;

  return (
    <div style={{ position: 'fixed', inset: 0, background: 'rgba(2, 6, 23, 0.72)', display: 'grid', placeItems: 'center', padding: '1rem', zIndex: 2100 }} onClick={onCancel}>
      <div onClick={(event) => event.stopPropagation()} style={panelStyle}>
        <div style={{ padding: '1.1rem 1.1rem 0.8rem' }}>
          <div style={{ color: '#fca5a5', fontSize: '0.7rem', letterSpacing: '0.12em', textTransform: 'uppercase' }}>Confirm</div>
          <h3 style={{ margin: '0.35rem 0 0.5rem', fontSize: '1.2rem' }}>{title}</h3>
          <p style={{ margin: 0, color: '#cbd5e1', lineHeight: 1.6 }}>{message}</p>
        </div>

        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.7rem', padding: '0 1.1rem 1.1rem' }}>
          <button type="button" onClick={onCancel} style={{ border: '1px solid rgba(148, 163, 184, 0.22)', background: 'rgba(15, 23, 42, 0.72)', color: '#cbd5e1', borderRadius: '10px', padding: '0.7rem 1rem', cursor: 'pointer' }}>{cancelLabel}</button>
          <button type="button" onClick={onConfirm} style={{ border: '1px solid rgba(248, 113, 113, 0.35)', background: 'linear-gradient(135deg, rgba(239,68,68,0.8), rgba(220,38,38,0.9))', color: '#fff5f5', borderRadius: '10px', padding: '0.7rem 1rem', cursor: 'pointer', fontWeight: 700 }}>{confirmLabel}</button>
        </div>
      </div>
    </div>
  );
}
