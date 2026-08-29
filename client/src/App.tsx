import { useEffect, useState } from 'react';
import { APP_NAME, HealthStatus, AuthResponse } from '@sentinel/shared';
import Login from './Login';

function App() {
  const [auth, setAuth] = useState<AuthResponse | null>(null);
  const [backendHealth, setBackendHealth] = useState<HealthStatus | null>(null);
  const [error, setError] = useState('');

  const fetchHealth = async (token: string) => {
    try {
      const res = await fetch('/api/health', {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (!res.ok) throw new Error('Unauthorized or fetch failed');
      const data = await res.json();
      setBackendHealth(data);
    } catch (err: any) {
      setError(err.message);
    }
  };

  useEffect(() => {
    const token = localStorage.getItem('token');
    if (token) {
      // In a real app we'd fetch the user profile, but here we just retry health check
      fetchHealth(token);
      // Faking the user for simple state since we didn't store it
      setAuth({ token, user: { id: '...', email: 'cached', role: 'admin' } });
    }
  }, []);

  if (!auth) {
    return <Login onLogin={(data) => {
      setAuth(data);
      fetchHealth(data.token);
    }} />;
  }

  return (
    <div style={{ padding: '2rem' }}>
      <h1>{APP_NAME}</h1>
      <p>Logged in as: {auth.user.email} (Role: {auth.user.role})</p>
      <button onClick={() => {
        localStorage.removeItem('token');
        setAuth(null);
        setBackendHealth(null);
      }}>Logout</button>

      <h2>System Status</h2>
      {error && <p style={{ color: 'red' }}>Error: {error}</p>}
      <p>Frontend: OK</p>
      <p>Backend: {backendHealth ? backendHealth.status : 'Loading...'}</p>
      {backendHealth?.user && (
        <pre>{JSON.stringify(backendHealth.user, null, 2)}</pre>
      )}
    </div>
  );
}

export default App;
