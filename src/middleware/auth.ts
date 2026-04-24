import type { Request, Response, NextFunction } from 'express';
import { verifyToken } from '../lib/jwt.js';
import { db } from '../db/index.js';
import { users, userSessions } from '../db/schema.js';
import { eq, and, gt } from 'drizzle-orm';

export interface AuthRequest extends Request {
  userId?: string;
  sessionId?: string;
  isAdmin?: boolean;
}

export async function requireAuth(req: AuthRequest, res: Response, next: NextFunction) {
  const header = req.headers.authorization;
  if (!header?.startsWith('Bearer ')) {
    res.status(401).json({ success: false, error: 'Unauthorized' });
    return;
  }

  try {
    const token = header.slice(7);
    const payload = verifyToken(token);

    const [session] = await db
      .select()
      .from(userSessions)
      .where(and(eq(userSessions.id, payload.sessionId), gt(userSessions.expiresAt, new Date())))
      .limit(1);

    if (!session) {
      res.status(401).json({ success: false, error: 'Session expired' });
      return;
    }

    const [user] = await db.select().from(users).where(eq(users.id, payload.userId)).limit(1);
    if (!user || user.status === 'banned') {
      res.status(401).json({ success: false, error: 'Account not accessible' });
      return;
    }

    req.userId = user.id;
    req.sessionId = session.id;
    req.isAdmin = user.isAdmin;

    // Update last active
    await db
      .update(userSessions)
      .set({ lastActiveAt: new Date() })
      .where(eq(userSessions.id, session.id));

    next();
  } catch {
    res.status(401).json({ success: false, error: 'Invalid token' });
  }
}

export function requireAdmin(req: AuthRequest, res: Response, next: NextFunction) {
  if (!req.isAdmin) {
    res.status(403).json({ success: false, error: 'Forbidden' });
    return;
  }
  next();
}
