import { Router } from 'express';
import { PrismaClient } from '@prisma/client';
import { z } from 'zod';
import { requireAuth } from '../middleware/auth';

const router = Router();
const prisma = new PrismaClient();

const logSchema = z.object({
  source: z.string().min(1, 'Source is required'),
  eventType: z.string().min(1, 'Event type is required'),
  severity: z.enum(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']),
  message: z.string().min(1, 'Message is required')
});

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

  await prisma.log.create({
    data: {
      source,
      eventType: 'BRUTE_FORCE_DETECTED',
      severity: 'CRITICAL',
      message: `Brute force attack detected against ${source}`
    }
  });
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

    await detectBruteforce(payload.source);

    res.status(201).json(log);
  } catch (error: any) {
    if (error instanceof z.ZodError) {
      return res.status(400).json({ error: 'Invalid log payload', details: error.errors });
    }

    return res.status(500).json({ error: 'Failed to create log' });
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
