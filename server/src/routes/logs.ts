import { Router } from 'express';
import { PrismaClient } from '@prisma/client';
import { z } from 'zod';
import jwt from 'jsonwebtoken';
import { UserContext } from '@sentinel/shared';
import { requireAuth, SECRET_KEY } from '../middleware/auth';

const router = Router();
const prisma = new PrismaClient();
const streamClients = new Set<{ id: string; res: any; userId: string }>();

const logSchema = z.object({
  source: z.string().min(1, 'Source is required'),
  eventType: z.string().min(1, 'Event type is required'),
  severity: z.enum(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']),
  message: z.string().min(1, 'Message is required')
});

const broadcastLog = (log: any) => {
  const payload = `event: log\ndata: ${JSON.stringify(log)}\n\n`;

  for (const client of streamClients) {
    if (client.res.writableEnded) {
      streamClients.delete(client);
      continue;
    }

    client.res.write(payload);
  }
};

const detectBruteforce = async (source: string) => {
  const twoMinutesAgo = new Date(Date.now() - 2 * 60 * 1000);

  const recentFailedLogins = await prisma.log.count({
    where: {
      source,
      eventType: 'Failed Login',
      severity: 'HIGH',
      timestamp: {
        gte: twoMinutesAgo
      }
    }
  });

  if (recentFailedLogins < 5) {
    return;
  }

  const recentAlertCount = await prisma.log.count({
    where: {
      source,
      eventType: 'BRUTE_FORCE_DETECTED',
      severity: 'CRITICAL',
      timestamp: {
        gte: twoMinutesAgo
      }
    }
  });

  if (recentAlertCount > 0) {
    return;
  }

  const alert = await prisma.log.create({
    data: {
      source,
      eventType: 'BRUTE_FORCE_DETECTED',
      severity: 'CRITICAL',
      message: `Brute force attack detected against ${source}`
    }
  });

  broadcastLog(alert);
};

router.post('/', requireAuth, async (req, res) => {
  try {
    const payload = logSchema.parse(req.body);

    const log = await prisma.log.create({
      data: {
        source: payload.source,
        eventType: payload.eventType,
        severity: payload.severity,
        message: payload.message
      }
    });

    broadcastLog(log);
    await detectBruteforce(payload.source);

    res.status(201).json(log);
  } catch (error: any) {
    if (error instanceof z.ZodError) {
      return res.status(400).json({ error: 'Invalid log payload', details: error.errors });
    }

    return res.status(500).json({ error: 'Failed to create log' });
  }
});

router.get('/stream', (req, res) => {
  const token = typeof req.query.token === 'string' ? req.query.token : null;

  if (!token) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  try {
    const decoded = jwt.verify(token, SECRET_KEY) as UserContext;
    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache, no-transform');
    res.setHeader('Connection', 'keep-alive');
    res.setHeader('X-Accel-Buffering', 'no');
    res.flushHeaders?.();

    const client = {
      id: `${decoded.id}-${Date.now()}`,
      userId: decoded.id,
      res
    };

    streamClients.add(client);
    res.write(`event: connected\ndata: ${JSON.stringify({ status: 'connected', user: decoded })}\n\n`);

    const heartbeat = setInterval(() => {
      if (res.writableEnded) {
        clearInterval(heartbeat);
        streamClients.delete(client);
        return;
      }

      res.write(': heartbeat\n\n');
    }, 25000);

    req.on('close', () => {
      clearInterval(heartbeat);
      streamClients.delete(client);
    });
  } catch {
    return res.status(401).json({ error: 'Invalid token' });
  }
});

router.get('/', requireAuth, async (_req, res) => {
  try {
    const logs = await prisma.log.findMany({
      orderBy: { timestamp: 'desc' },
      take: 100
    });

    res.json(logs);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch logs' });
  }
});

export default router;
