import { Router } from 'express';
import type { Request, Response } from 'express';
import { db } from '../db/index.js';
import { users, userSessions } from '../db/schema.js';
import { eq } from 'drizzle-orm';
import { hashPassword, verifyPassword } from '../lib/password.js';
import { signToken, tokenExpiresAt } from '../lib/jwt.js';
import { logAudit } from '../lib/audit.js';
import { requireAuth, type AuthRequest } from '../middleware/auth.js';

const router = Router();

router.post('/register', async (req: Request, res: Response) => {
  const { email, username, password, firstName, lastName } = req.body;
  if (!email || !username || !password) {
    res.status(400).json({ success: false, error: 'email, username and password are required' });
    return;
  }

  const existing = await db
    .select({ id: users.id })
    .from(users)
    .where(eq(users.email, email.toLowerCase()))
    .limit(1);

  if (existing.length > 0) {
    res.status(409).json({ success: false, error: 'Email already registered' });
    return;
  }

  const passwordHash = await hashPassword(password);
  const [user] = await db
    .insert(users)
    .values({
      email: email.toLowerCase(),
      username: username.toLowerCase(),
      passwordHash,
      firstName: firstName ?? null,
      lastName: lastName ?? null,
      status: 'active',
    })
    .returning();

  const [session] = await db
    .insert(userSessions)
    .values({
      userId: user.id,
      tokenHash: 'pending',
      device: req.headers['user-agent']?.slice(0, 255) ?? null,
      ipAddress: req.ip?.slice(0, 50) ?? null,
      isCurrent: true,
      expiresAt: tokenExpiresAt(),
    })
    .returning();

  const token = signToken({ userId: user.id, sessionId: session.id });

  await logAudit({
    userId: user.id,
    userName: user.email,
    action: 'Account Registered',
    detail: 'New user sign-up',
    type: 'user',
    severity: 'info',
    ipAddress: req.ip ?? undefined,
    notify: true,
  });

  res.status(201).json({ success: true, data: { token, user: safeUser(user) } });
});

router.post('/login', async (req: Request, res: Response) => {
  const { email, password } = req.body;
  if (!email || !password) {
    res.status(400).json({ success: false, error: 'email and password are required' });
    return;
  }

  const [user] = await db
    .select()
    .from(users)
    .where(eq(users.email, email.toLowerCase()))
    .limit(1);

  if (!user || !(await verifyPassword(password, user.passwordHash))) {
    res.status(401).json({ success: false, error: 'Invalid credentials' });
    return;
  }

  if (user.status === 'banned') {
    res.status(403).json({ success: false, error: 'Account banned' });
    return;
  }

  const [session] = await db
    .insert(userSessions)
    .values({
      userId: user.id,
      tokenHash: 'pending',
      device: req.headers['user-agent']?.slice(0, 255) ?? null,
      ipAddress: req.ip?.slice(0, 50) ?? null,
      isCurrent: true,
      expiresAt: tokenExpiresAt(),
    })
    .returning();

  const token = signToken({ userId: user.id, sessionId: session.id });

  await db.update(users).set({ lastSeenAt: new Date() }).where(eq(users.id, user.id));

  await logAudit({
    userId: user.id,
    userName: user.email,
    action: 'Login',
    detail: `Login from ${req.headers['user-agent']?.slice(0, 100) ?? 'unknown'}`,
    type: 'auth',
    severity: 'info',
    ipAddress: req.ip ?? undefined,
  });

  res.json({ success: true, data: { token, user: safeUser(user) } });
});

router.post('/logout', requireAuth, async (req: AuthRequest, res: Response) => {
  await db.delete(userSessions).where(eq(userSessions.id, req.sessionId!));
  res.json({ success: true });
});

function safeUser(u: typeof users.$inferSelect) {
  const { passwordHash, twoFaSecret, ...safe } = u;
  void passwordHash;
  void twoFaSecret;
  return safe;
}

export default router;
