import { LogTemplate } from '../types/log';

type LogGeneratorProps = {
  templates: Record<string, LogTemplate>;
  onGenerate: (name: string) => void;
};

function LogGenerator({ templates, onGenerate }: LogGeneratorProps) {
  return (
    <section style={{ marginTop: '2rem' }}>
      <h2 style={{ marginBottom: '1rem' }}>Log Generator</h2>
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.75rem', marginBottom: '1.5rem' }}>
        {Object.keys(templates).map((name) => (
          <button
            key={name}
            type="button"
            onClick={() => onGenerate(name as keyof typeof templates)}
            style={{
              padding: '0.7rem 1rem',
              borderRadius: '10px',
              border: '1px solid #334155',
              background: 'linear-gradient(135deg, #1e293b, #0f172a)',
              color: '#f8fafc',
              cursor: 'pointer',
              fontWeight: 600
            }}
          >
            {name}
          </button>
        ))}
      </div>
    </section>
  );
}

export default LogGenerator;
