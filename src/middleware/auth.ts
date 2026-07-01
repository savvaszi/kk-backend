import type { Request, Response, NextFunction } from 'express';
import { verifyToken } from '../lib/jwt.js';
import { db } from '../db/index.js';
import { users, userSessions } from '../db/schema.js';
import { eq, and, gt } from 'drizzle-orm';

export interface AuthRequest extends Request {
  userId?: string;
  sessionId?: string;
  isAdmin?: boolean;
  adminRole?: string | null;
  mustChangePassword?: boolean;
  twoFaEnabled?: boolean;
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
    req.adminRole = user.adminRole;
    req.mustChangePassword = user.mustChangePassword;
    req.twoFaEnabled = user.twoFaEnabled;

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

// Admin routes require: isAdmin, a fresh (non-temporary) password, and 2FA
// enabled on the account (PCI DSS 8.3.5 / 8.3.9). setup-2fa / change-password
// live under /me/*, which only goes through requireAuth, so a locked-out admin
// can still reach them to unblock themselves.
export function requireAdmin(req: AuthRequest, res: Response, next: NextFunction) {
  if (!req.isAdmin) {
    res.status(403).json({ success: false, error: 'Forbidden' });
    return;
  }
  if (req.mustChangePassword) {
    res.status(403).json({ success: false, error: 'Password change required before continuing', code: 'MUST_CHANGE_PASSWORD' });
    return;
  }
  if (!req.twoFaEnabled) {
    res.status(403).json({ success: false, error: 'Two-factor authentication must be enabled for admin access', code: 'MFA_REQUIRED' });
    return;
  }
  next();
}

// Full admins only — KYC reviewers are blocked from user/settings/API-key
// management, sessions, audit log, and platform settings.
export function requireFullAdmin(req: AuthRequest, res: Response, next: NextFunction) {
  if (req.adminRole !== 'full') {
    res.status(403).json({ success: false, error: 'Requires Full Admin role' });
    return;
  }
  next();
}
