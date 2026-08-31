import { useEffect, useState } from 'react';

const AnimatedNumber = ({ value }: { value: number }) => {
  const [displayValue, setDisplayValue] = useState(0);

  useEffect(() => {
    let frame = 0;
    const start = displayValue;
    const diff = value - start;
    const duration = 400;
    const startTime = performance.now();

    const tick = (time: number) => {
      const progress = Math.min((time - startTime) / duration, 1);
      const eased = 1 - Math.pow(1 - progress, 3);
      setDisplayValue(start + diff * eased);
      if (progress < 1) {
        frame = window.requestAnimationFrame(tick);
      }
    };

    frame = window.requestAnimationFrame(tick);
    return () => window.cancelAnimationFrame(frame);
  }, [value]);

  return <span>{Math.round(displayValue)}</span>;
};

type KPIGridProps = {
  totalEvents?: number;
  criticalCount?: number;
  highCount?: number;
  todayCount?: number;
  cards?: Array<{ label: string; value: number; accent: string }>;
};

function KPIGrid({ totalEvents, criticalCount, highCount, todayCount, cards }: KPIGridProps) {
  const normalizedCards = cards ?? [
    { label: 'Total Events', value: totalEvents ?? 0, accent: '#38bdf8' },
    { label: 'Critical', value: criticalCount ?? 0, accent: '#ef4444' },
    { label: 'High', value: highCount ?? 0, accent: '#f59e0b' },
    { label: 'Events Today', value: todayCount ?? 0, accent: '#22c55e' }
  ];

  return (
    <section style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '1rem', marginBottom: '0.5rem' }}>
      {normalizedCards.map((card) => (
        <div key={card.label} style={{
          background: 'rgba(15, 23, 42, 0.9)',
          border: '1px solid rgba(148, 163, 184, 0.2)',
          borderRadius: '16px',
          padding: '1rem 1.25rem',
          boxShadow: '0 8px 20px rgba(15, 23, 42, 0.35)'
        }}>
          <div style={{ color: '#94a3b8', fontSize: '0.8rem', textTransform: 'uppercase', letterSpacing: '0.08em' }}>{card.label}</div>
          <div style={{ marginTop: '0.5rem', fontSize: '2rem', fontWeight: 700, color: card.accent }}><AnimatedNumber value={card.value} /></div>
        </div>
      ))}
    </section>
  );
}

export default KPIGrid;
