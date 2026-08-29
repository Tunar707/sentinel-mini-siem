import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import { UserContext } from '@sentinel/shared';

export const SECRET_KEY = process.env.JWT_SECRET || 'supersecret_fallback';

export const requireAuth = (req: Request, res: Response, next: NextFunction) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, SECRET_KEY) as UserContext;
    (req as any).user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid token' });
  }
};
