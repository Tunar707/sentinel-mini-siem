import { useState } from 'react';
import { AuthResponse, type UserRole } from '@sentinel/shared';

const roleOptions: UserRole[] = ['admin', 'analyst', 'employee'];

export default function Login({ onLogin }: { onLogin: (data: AuthResponse) => void }) {
  const [email, setEmail] = useState('admin@sentinel.local');
  const [password, setPassword] = useState('admin123');
  const [selectedRole, setSelectedRole] = useState<UserRole>('admin');
  const [error, setError] = useState('');

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');

    try {
      const res = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password })
      });

      if (!res.ok) {
        const body = await res.json();
        throw new Error(body.error || 'Login failed');
      }

      const data: AuthResponse = await res.json();
      const roleOverride = selectedRole === 'admin' || selectedRole === 'analyst' || selectedRole === 'employee' ? selectedRole : data.user.role;
      const effectiveUser = { ...data.user, role: roleOverride };
      const nextAuth: AuthResponse = { ...data, user: effectiveUser };
      localStorage.setItem('token', nextAuth.token);
      onLogin(nextAuth);
    } catch (err: any) {
      setError(err.message);
    }
  };

  return (
    <div style={{ padding: '2rem', maxWidth: '420px', margin: 'auto' }}>
      <h2>Sentinel Login</h2>
      {error && <p style={{ color: 'red' }}>{error}</p>}
      <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
        <input 
          type="email" 
          placeholder="Email" 
          value={email} 
          onChange={e => setEmail(e.target.value)} 
          required 
        />
        <input 
          type="password" 
          placeholder="Password" 
          value={password} 
          onChange={e => setPassword(e.target.value)} 
          required 
        />
        <label style={{ display: 'flex', flexDirection: 'column', gap: '0.45rem', color: '#334155', fontWeight: 600 }}>
          Role
          <select value={selectedRole} onChange={(event) => setSelectedRole(event.target.value as UserRole)} style={{ padding: '0.7rem 0.8rem', borderRadius: '10px', border: '1px solid #cbd5e1' }}>
            {roleOptions.map((role) => (<option key={role} value={role}>{role.charAt(0).toUpperCase() + role.slice(1)}</option>))}
          </select>
        </label>
        <button type="submit">Login</button>
      </form>
    </div>
  );
}
