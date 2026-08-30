import { Router } from 'express';
import { PrismaClient } from '@prisma/client';
import { z } from 'zod';
import { requireAuth } from '../middleware/auth';

const router = Router();
const prisma = new PrismaClient();

const updateIncidentSchema = z.object({
  status: z.enum(['New', 'Investigating', 'Contained', 'Resolved']).optional(),
  assignedAnalyst: z.enum(['Tunar', 'Sarah', 'Michael', 'Emma']).optional()
});

const noteSchema = z.object({
  analyst: z.enum(['Tunar', 'Sarah', 'Michael', 'Emma']),
  content: z.string().min(1, 'Note content is required')
});

const formatIncident = (incident: any) => {
  const createdAt = incident.createdAt ?? incident.log?.timestamp ?? new Date().toISOString();
  const notes = (incident.notes ?? []).map((note: any) => ({
    id: note.id,
    analyst: note.analyst,
    timestamp: note.createdAt,
    content: note.content
  })).sort((a: any, b: any) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());

  const timeline = [
    {
      id: `${incident.id}-created`,
      type: 'created',
      timestamp: createdAt,
      message: 'Incident created',
      analyst: 'System'
    },
    {
      id: `${incident.id}-status`,
      type: 'status',
      timestamp: createdAt,
      message: `Status changed to ${incident.status}`,
      analyst: incident.assignedAnalyst
    },
    {
      id: `${incident.id}-assignment`,
      type: 'assignment',
      timestamp: createdAt,
      message: `Assigned to ${incident.assignedAnalyst}`,
      analyst: incident.assignedAnalyst
    },
    ...notes.map((note: any) => ({
      id: note.id,
      type: 'note',
      timestamp: note.timestamp,
      message: `Note added by ${note.analyst}`,
      analyst: note.analyst
    }))
  ].sort((a: any, b: any) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());

  return {
    id: incident.id,
    logId: incident.logId,
    status: incident.status,
    assignedAnalyst: incident.assignedAnalyst,
    createdAt,
    updatedAt: incident.updatedAt,
    source: incident.log?.source,
    eventType: incident.log?.eventType,
    severity: incident.log?.severity,
    timestamp: incident.log?.timestamp,
    message: incident.log?.message,
    notes,
    timeline
  };
};

router.get('/', requireAuth, async (_req, res) => {
  try {
    const incidents = await prisma.incident.findMany({
      include: {
        log: true,
        notes: { orderBy: { createdAt: 'asc' } }
      },
      orderBy: { createdAt: 'desc' }
    });

    res.json(incidents.map(formatIncident));
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch incidents' });
  }
});

router.get('/:id', requireAuth, async (req, res) => {
  try {
    const incident = await prisma.incident.findUnique({
      where: { id: req.params.id },
      include: { log: true, notes: { orderBy: { createdAt: 'asc' } } }
    });

    if (!incident) {
      return res.status(404).json({ error: 'Incident not found' });
    }

    res.json(formatIncident(incident));
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch incident' });
  }
});

router.patch('/:id', requireAuth, async (req, res) => {
  try {
    const payload = updateIncidentSchema.parse(req.body);

    const existing = await prisma.incident.findUnique({
      where: { id: req.params.id },
      include: { log: true, notes: { orderBy: { createdAt: 'asc' } } }
    });

    if (!existing) {
      return res.status(404).json({ error: 'Incident not found' });
    }

    const incident = await prisma.incident.update({
      where: { id: req.params.id },
      data: {
        status: payload.status ?? existing.status,
        assignedAnalyst: payload.assignedAnalyst ?? existing.assignedAnalyst
      },
      include: { log: true, notes: { orderBy: { createdAt: 'asc' } } }
    });

    res.json(formatIncident(incident));
  } catch (error: any) {
    if (error instanceof z.ZodError) {
      return res.status(400).json({ error: 'Invalid incident payload', details: error.errors });
    }

    return res.status(500).json({ error: 'Failed to update incident' });
  }
});

router.post('/:id/notes', requireAuth, async (req, res) => {
  try {
    const payload = noteSchema.parse(req.body);
    const incident = await prisma.incident.findUnique({
      where: { id: req.params.id }
    });

    if (!incident) {
      return res.status(404).json({ error: 'Incident not found' });
    }

    const note = await prisma.incidentNote.create({
      data: {
        incidentId: incident.id,
        analyst: payload.analyst,
        content: payload.content
      }
    });

    const fullIncident = await prisma.incident.findUnique({
      where: { id: req.params.id },
      include: { log: true, notes: { orderBy: { createdAt: 'asc' } } }
    });

    res.status(201).json(formatIncident(fullIncident!));
  } catch (error: any) {
    if (error instanceof z.ZodError) {
      return res.status(400).json({ error: 'Invalid note payload', details: error.errors });
    }

    return res.status(500).json({ error: 'Failed to add note' });
  }
});

export default router;
