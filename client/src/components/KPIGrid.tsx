type KPIGridProps = {
  totalEvents: number;
  criticalCount: number;
  highCount: number;
  todayCount: number;
};

function KPIGrid({ totalEvents, criticalCount, highCount, todayCount }: KPIGridProps) {
  const cards = [
    { label: 'Total Events', value: totalEvents, accent: '#38bdf8' },
    { label: 'Critical', value: criticalCount, accent: '#ef4444' },
    { label: 'High', value: highCount, accent: '#f59e0b' },
    { label: 'Events Today', value: todayCount, accent: '#22c55e' }
  ];

  return (
    <section style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '1rem', marginBottom: '2rem' }}>
      {cards.map((card) => (
        <div key={card.label} style={{
          background: 'rgba(15, 23, 42, 0.9)',
          border: '1px solid rgba(148, 163, 184, 0.2)',
          borderRadius: '16px',
          padding: '1rem 1.25rem',
          boxShadow: '0 8px 20px rgba(15, 23, 42, 0.35)'
        }}>
          <div style={{ color: '#94a3b8', fontSize: '0.8rem', textTransform: 'uppercase', letterSpacing: '0.08em' }}>{card.label}</div>
          <div style={{ marginTop: '0.5rem', fontSize: '2rem', fontWeight: 700, color: card.accent }}>{card.value}</div>
        </div>
      ))}
    </section>
  );
}

export default KPIGrid;
