type SearchBarProps = {
  value: string;
  onChange: (value: string) => void;
};

function SearchBar({ value, onChange }: SearchBarProps) {
  return (
    <input
      type="text"
      value={value}
      onChange={(e) => onChange(e.target.value)}
      placeholder="Search source, event type, or message"
      style={{
        minWidth: '260px',
        padding: '0.7rem 0.9rem',
        borderRadius: '10px',
        border: '1px solid #334155',
        background: '#0f172a',
        color: '#e2e8f0'
      }}
    />
  );
}

export default SearchBar;
