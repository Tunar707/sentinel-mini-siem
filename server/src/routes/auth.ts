import { Router } from 'express';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import { PrismaClient } from '@prisma/client';
import { ZodError } from 'zod';
import { UserContext, AuthResponse, loginSchema } from '@sentinel/shared';
import { SECRET_KEY } from '../middleware/auth';

const router = Router();
const prisma = new PrismaClient();

router.post('/login', async (req, res) => {
  try {
    const { email, password } = loginSchema.parse(req.body);

    const user = await prisma.user.findUnique({ where: { email } });
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });

    const isValid = await bcrypt.compare(password, user.passwordHash);
    if (!isValid) return res.status(401).json({ error: 'Invalid credentials' });

    const userContext: UserContext = { id: user.id, email: user.email, role: user.role as UserContext['role'] };
    const token = jwt.sign(userContext, SECRET_KEY);

    const response: AuthResponse = { token, user: userContext };
    res.json(response);
  } catch (err: any) {
    if (err instanceof ZodError) {
      return res.status(400).json({ error: 'Email and password required' });
    }

    return res.status(500).json({ error: 'Database error' });
  }
});

router.post('/seed', async (req, res) => {
  try {
    const existing = await prisma.user.findUnique({ where: { email: 'admin@sentinel.local' } });
    if (existing) return res.json({ message: 'Already seeded' });

    const hash = await bcrypt.hash('admin123', 10);
    await prisma.user.create({
      data: {
        id: 'admin-uuid',
        email: 'admin@sentinel.local',
        passwordHash: hash,
        role: 'admin'
      }
    });

    res.json({ message: 'Seeded admin@sentinel.local / admin123' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to seed', details: String(err) });
  }
});

export default router;
