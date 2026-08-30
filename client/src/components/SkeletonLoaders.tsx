import type { CSSProperties } from 'react';

const baseStyle: CSSProperties = {
  background: 'linear-gradient(90deg, rgba(148,163,184,0.12), rgba(148,163,184,0.2), rgba(148,163,184,0.12))',
  backgroundSize: '200% 100%',
  animation: 'pulse 1.4s ease-in-out infinite',
  borderRadius: '12px'
};

const shimmerKey = `@keyframes skeletonPulse { 0% { background-position: 200% 0; } 100% { background-position: -200% 0; } }`;

export function AssetSkeleton() {
  return (
    <div style={{ display: 'grid', gap: '0.8rem', padding: '1rem' }}>
      <style>{shimmerKey}</style>
      {Array.from({ length: 4 }).map((_, index) => (
        <div key={index} style={{ display: 'grid', gridTemplateColumns: '1.6fr 1fr 1fr 1fr 1fr 1fr', gap: '0.75rem' }}>
          <div style={{ ...baseStyle, height: '40px' }} />
          <div style={{ ...baseStyle, height: '40px' }} />
          <div style={{ ...baseStyle, height: '40px' }} />
          <div style={{ ...baseStyle, height: '40px' }} />
          <div style={{ ...baseStyle, height: '40px' }} />
          <div style={{ ...baseStyle, height: '40px' }} />
        </div>
      ))}
    </div>
  );
}

export function UserSkeleton() {
  return (
    <div style={{ display: 'grid', gap: '0.8rem', padding: '1rem' }}>
      <style>{shimmerKey}</style>
      {Array.from({ length: 4 }).map((_, index) => (
        <div key={index} style={{ display: 'grid', gridTemplateColumns: '1.4fr 1.6fr 1.2fr 1fr 1.5fr 0.8fr 0.8fr 0.8fr', gap: '0.75rem' }}>
          <div style={{ ...baseStyle, height: '38px' }} />
          <div style={{ ...baseStyle, height: '38px' }} />
          <div style={{ ...baseStyle, height: '38px' }} />
          <div style={{ ...baseStyle, height: '38px' }} />
          <div style={{ ...baseStyle, height: '38px' }} />
          <div style={{ ...baseStyle, height: '38px' }} />
          <div style={{ ...baseStyle, height: '38px' }} />
          <div style={{ ...baseStyle, height: '38px' }} />
        </div>
      ))}
    </div>
  );
}

export function CaseSkeleton() {
  return (
    <div style={{ display: 'grid', gap: '0.8rem', padding: '1rem' }}>
      <style>{shimmerKey}</style>
      {Array.from({ length: 3 }).map((_, index) => (
        <div key={index} style={{ display: 'grid', gridTemplateColumns: '1.2fr 1.2fr 1fr 1fr 1.2fr', gap: '0.75rem' }}>
          <div style={{ ...baseStyle, height: '48px' }} />
          <div style={{ ...baseStyle, height: '48px' }} />
          <div style={{ ...baseStyle, height: '48px' }} />
          <div style={{ ...baseStyle, height: '48px' }} />
          <div style={{ ...baseStyle, height: '48px' }} />
        </div>
      ))}
    </div>
  );
}

export function ReportSkeleton() {
  return (
    <div style={{ display: 'grid', gap: '0.8rem', padding: '1rem' }}>
      <style>{shimmerKey}</style>
      <div style={{ ...baseStyle, height: '150px' }} />
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, minmax(0, 1fr))', gap: '0.75rem' }}>
        <div style={{ ...baseStyle, height: '120px' }} />
        <div style={{ ...baseStyle, height: '120px' }} />
        <div style={{ ...baseStyle, height: '120px' }} />
      </div>
    </div>
  );
}
