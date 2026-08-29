"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = require("express");
const client_1 = require("@prisma/client");
const zod_1 = require("zod");
const auth_1 = require("../middleware/auth");
const router = (0, express_1.Router)();
const prisma = new client_1.PrismaClient();
const logSchema = zod_1.z.object({
    source: zod_1.z.string().min(1, 'Source is required'),
    eventType: zod_1.z.string().min(1, 'Event type is required'),
    severity: zod_1.z.enum(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']),
    message: zod_1.z.string().min(1, 'Message is required')
});
router.post('/', auth_1.requireAuth, async (req, res) => {
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
        res.status(201).json(log);
    }
    catch (error) {
        if (error instanceof zod_1.z.ZodError) {
            return res.status(400).json({ error: 'Invalid log payload', details: error.errors });
        }
        return res.status(500).json({ error: 'Failed to create log' });
    }
});
router.get('/', auth_1.requireAuth, async (_req, res) => {
    try {
        const logs = await prisma.log.findMany({
            orderBy: { timestamp: 'desc' },
            take: 100
        });
        res.json(logs);
    }
    catch (error) {
        res.status(500).json({ error: 'Failed to fetch logs' });
    }
});
exports.default = router;
