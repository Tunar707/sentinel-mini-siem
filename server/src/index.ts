import express from 'express';
import { APP_NAME, HealthStatus } from '@sentinel/shared';
import authRoutes from './routes/auth';
import logsRoutes from './routes/logs';
import incidentsRoutes from './routes/incidents';
import { requireAuth } from './middleware/auth';

const app = express();
const port = process.env.PORT || 3000;

app.use(express.json());

app.use('/api/auth', authRoutes);
app.use('/api/logs', logsRoutes);
app.use('/api/incidents', incidentsRoutes);

app.get('/health', (req, res) => {
  res.json({ status: 'ok', service: 'server' });
});

// Protect /api/health
app.get('/api/health', requireAuth, (req, res) => {
  const status: HealthStatus = { 
    status: 'ok', 
    service: 'api',
    user: (req as any).user 
  };
  res.json(status);
});

app.listen(port, () => {
  console.log(`${APP_NAME} backend listening on port ${port}`);
});
