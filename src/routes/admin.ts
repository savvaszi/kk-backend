import { Router } from 'express';
import type { Response } from 'express';
import { db } from '../db/index.js';
import { users, userSessions, apiKeys, wallets, auditLogs, adminNotifications, platformSettings, fireblocksEvents } from '../db/schema.js';
import { eq, desc, ilike, or, count, and, lt } from 'drizzle-orm';
import { requireAuth, requireAdmin, type AuthRequest } from '../middleware/auth.js';
import { logAudit } from '../lib/audit.js';
import { generateKeyId, generateRawKey, hashKey } from '../lib/apiKey.js';
import { hashPassword } from '../lib/password.js';

const router = Router();
router.use(requireAuth, requireAdmin);

// GET /admin/stats
router.get('/stats', async (_req: AuthRequest, res: Response) => {
  const [totalUsers] = await db.select({ c: count() }).from(users);
  const [activeApiKeys] = await db.select({ c: count() }).from(apiKeys).where(eq(apiKeys.status, 'active'));
  const [connectedWallets] = await db.select({ c: count() }).from(wallets);
  const [flaggedAccounts] = await db.select({ c: count() }).from(users).where(lt(users.securityScore, 40));
  const [bannedAccounts] = await db.select({ c: count() }).from(users).where(eq(users.status, 'banned'));
  const [twoFaUsers] = await db.select({ c: count() }).from(users).where(eq(users.twoFaEnabled, true));
  const [activeSessions] = await db.select({ c: count() }).from(userSessions).where(and(eq(userSessions.isCurrent, true)));
  const allScores = await db.select({ score: users.securityScore }).from(users);
  const avgScore = allScores.length ? Math.round(allScores.reduce((a, u) => a + u.score, 0) / allScores.length) : 0;
  const twoFaAdoption = totalUsers.c > 0 ? Math.round((twoFaUsers.c / totalUsers.c) * 100) : 0;

  res.json({
    success: true,
    data: {
      totalUsers: totalUsers.c,
      activeApiKeys: activeApiKeys.c,
      connectedWallets: connectedWallets.c,
      flaggedAccounts: flaggedAccounts.c,
      bannedAccounts: bannedAccounts.c,
      activeSessions: activeSessions.c,
      avgSecurityScore: avgScore,
      twoFaAdoption,
    },
  });
});

// GET /admin/users
router.get('/users', async (req: AuthRequest, res: Response) => {
  const { q, status } = req.query as Record<string, string>;
  let query = db.select().from(users).$dynamic();
  if (q) {
    query = query.where(or(ilike(users.email, `%${q}%`), ilike(users.username, `%${q}%`)));
  }
  if (status && status !== 'all') {
    query = query.where(eq(users.status, status));
  }
  const rows = await query.orderBy(desc(users.createdAt));
  res.json({ success: true, data: rows.map(safeUser) });
});

// GET /admin/users/:id
router.get('/users/:id', async (req: AuthRequest, res: Response) => {
  const [user] = await db.select().from(users).where(eq(users.id, req.params.id)).limit(1);
  if (!user) { res.status(404).json({ success: false, error: 'User not found' }); return; }
  const userWallets = await db.select().from(wallets).where(eq(wallets.userId, user.id));
  const userKeys = await db.select({ id: apiKeys.id, keyId: apiKeys.keyId, name: apiKeys.name, permissions: apiKeys.permissions, status: apiKeys.status, createdAt: apiKeys.createdAt }).from(apiKeys).where(eq(apiKeys.userId, user.id));
  const recentAudit = await db.select().from(auditLogs).where(eq(auditLogs.userId, user.id)).orderBy(desc(auditLogs.createdAt)).limit(20);
  res.json({ success: true, data: { ...safeUser(user), wallets: userWallets, apiKeys: userKeys, recentAudit } });
});

// PATCH /admin/users/:id
router.patch('/users/:id', async (req: AuthRequest, res: Response) => {
  const allowed = ['firstName', 'lastName', 'email', 'username', 'level', 'status', 'isAdmin'] as const;
  const updates: Record<string, unknown> = {};
  for (const field of allowed) {
    if (field in req.body) updates[field] = req.body[field];
  }
  const [user] = await db.update(users).set({ ...updates, updatedAt: new Date() }).where(eq(users.id, req.params.id)).returning();
  res.json({ success: true, data: safeUser(user) });
});

// POST /admin/users/:id/reset-password
router.post('/users/:id/reset-password', async (req: AuthRequest, res: Response) => {
  const { password } = req.body;
  if (!password || typeof password !== 'string' || password.length < 6) {
    res.status(400).json({ success: false, error: 'Password must be at least 6 characters' });
    return;
  }
  const passwordHash = await hashPassword(password);
  const [user] = await db.update(users).set({ passwordHash, updatedAt: new Date() }).where(eq(users.id, req.params.id)).returning();
  if (!user) { res.status(404).json({ success: false, error: 'User not found' }); return; }
  await logAudit({ userId: user.id, userName: user.email, action: 'Password Reset', detail: 'Password reset by admin', type: 'security', severity: 'warning' });
  res.json({ success: true });
});

// POST /admin/users/:id/ban
router.post('/users/:id/ban', async (req: AuthRequest, res: Response) => {
  const [user] = await db
    .update(users)
    .set({ status: 'banned', updatedAt: new Date() })
    .where(eq(users.id, req.params.id))
    .returning();
  if (!user) { res.status(404).json({ success: false, error: 'User not found' }); return; }
  await db.delete(userSessions).where(eq(userSessions.userId, user.id));
  await logAudit({ userId: user.id, userName: user.email, action: 'Account Banned', detail: req.body.reason ?? 'Banned by admin', type: 'security', severity: 'danger', notify: true });
  res.json({ success: true });
});

// POST /admin/users/:id/unban
router.post('/users/:id/unban', async (req: AuthRequest, res: Response) => {
  const [user] = await db
    .update(users)
    .set({ status: 'active', updatedAt: new Date() })
    .where(eq(users.id, req.params.id))
    .returning();
  if (!user) { res.status(404).json({ success: false, error: 'User not found' }); return; }
  await logAudit({ userId: user.id, userName: user.email, action: 'Account Unbanned', detail: 'Account restored by admin', type: 'security', severity: 'info' });
  res.json({ success: true });
});

// POST /admin/users (create manually)
router.post('/users', async (req: AuthRequest, res: Response) => {
  const { email, username, password, firstName, lastName, level = 0, status = 'active' } = req.body;
  if (!email || !username || !password) {
    res.status(400).json({ success: false, error: 'email, username and password are required' }); return;
  }
  if (typeof password !== 'string' || password.length < 6) {
    res.status(400).json({ success: false, error: 'Password must be at least 6 characters' }); return;
  }
  const passwordHash = await hashPassword(password);
  try {
    const [user] = await db.insert(users)
      .values({ email, username, passwordHash, firstName, lastName, level, status, emailVerified: true })
      .returning();
    await logAudit({ userId: user.id, userName: user.email, action: 'User Created', detail: 'Account created by admin', type: 'admin', severity: 'info' });
    res.status(201).json({ success: true, data: safeUser(user) });
  } catch (err: any) {
    if (err.code === '23505') {
      res.status(409).json({ success: false, error: 'Email or username already in use' });
    } else {
      res.status(500).json({ success: false, error: 'Failed to create user' });
    }
  }
});

// PATCH /admin/users/:id/kyc
router.patch('/users/:id/kyc', async (req: AuthRequest, res: Response) => {
  const { kycStatus } = req.body;
  if (!['none','pending','approved','rejected'].includes(kycStatus)) {
    res.status(400).json({ success: false, error: 'Invalid kycStatus' }); return;
  }
  const severity = kycStatus === 'approved' ? 'success' : kycStatus === 'rejected' ? 'warning' : 'info';
  const [user] = await db.update(users)
    .set({ kycStatus, kycReviewedAt: new Date(), updatedAt: new Date() })
    .where(eq(users.id, req.params.id))
    .returning();
  if (!user) { res.status(404).json({ success: false, error: 'User not found' }); return; }
  await logAudit({ userId: user.id, userName: user.email, action: `KYC ${kycStatus}`, detail: `KYC status set to ${kycStatus} by admin`, type: 'kyc', severity });
  res.json({ success: true, data: safeUser(user) });
});

// POST /admin/users/:id/notify
router.post('/users/:id/notify', async (req: AuthRequest, res: Response) => {
  const { title, body, type = 'info' } = req.body;
  if (!title || !body) {
    res.status(400).json({ success: false, error: 'title and body are required' }); return;
  }
  const [user] = await db.select().from(users).where(eq(users.id, req.params.id)).limit(1);
  if (!user) { res.status(404).json({ success: false, error: 'User not found' }); return; }
  await db.insert(adminNotifications).values({ title: `[${user.email}] ${title}`, body, type });
  await logAudit({ userId: user.id, userName: user.email, action: 'Notification Sent', detail: title, type: 'admin', severity: 'info' });
  res.json({ success: true });
});

// GET /admin/api-keys
router.get('/api-keys', async (_req: AuthRequest, res: Response) => {
  const keys = await db
    .select({
      id: apiKeys.id,
      keyId: apiKeys.keyId,
      name: apiKeys.name,
      permissions: apiKeys.permissions,
      status: apiKeys.status,
      createdAt: apiKeys.createdAt,
      lastUsedAt: apiKeys.lastUsedAt,
      userId: apiKeys.userId,
      userEmail: users.email,
      userName: users.username,
    })
    .from(apiKeys)
    .leftJoin(users, eq(apiKeys.userId, users.id))
    .orderBy(desc(apiKeys.createdAt));
  res.json({ success: true, data: keys });
});

// POST /admin/api-keys (create for a user)
router.post('/api-keys', async (req: AuthRequest, res: Response) => {
  const { userId, name, permissions = [] } = req.body;
  if (!userId || !name) { res.status(400).json({ success: false, error: 'userId and name required' }); return; }
  const validPerms = ['read', 'trade', 'withdraw', 'deposit'];
  const perms = (permissions as string[]).filter(p => validPerms.includes(p));
  const keyId = generateKeyId();
  const raw = generateRawKey();
  const keyHash = await hashKey(raw);
  const [key] = await db.insert(apiKeys).values({ userId, keyId, keyHash, name, permissions: perms }).returning({ id: apiKeys.id, keyId: apiKeys.keyId, name: apiKeys.name, permissions: apiKeys.permissions, createdAt: apiKeys.createdAt });
  res.status(201).json({ success: true, data: { ...key, fullKey: `${keyId}.${raw}` } });
});

// PATCH /admin/api-keys/:id/revoke
router.patch('/api-keys/:id/revoke', async (req: AuthRequest, res: Response) => {
  await db.update(apiKeys).set({ status: 'revoked' }).where(eq(apiKeys.id, req.params.id));
  res.json({ success: true });
});

// PATCH /admin/api-keys/:id/restore
router.patch('/api-keys/:id/restore', async (req: AuthRequest, res: Response) => {
  await db.update(apiKeys).set({ status: 'active' }).where(eq(apiKeys.id, req.params.id));
  res.json({ success: true });
});

// DELETE /admin/api-keys/:id
router.delete('/api-keys/:id', async (req: AuthRequest, res: Response) => {
  await db.delete(apiKeys).where(eq(apiKeys.id, req.params.id));
  res.json({ success: true });
});

// GET /admin/audit
router.get('/audit', async (req: AuthRequest, res: Response) => {
  const { severity, type, limit = '50' } = req.query as Record<string, string>;
  let query = db.select().from(auditLogs).$dynamic();
  if (severity && severity !== 'all') query = query.where(eq(auditLogs.severity, severity));
  if (type && type !== 'all') query = query.where(eq(auditLogs.type, type));
  const rows = await query.orderBy(desc(auditLogs.createdAt)).limit(Math.min(parseInt(limit), 500));
  res.json({ success: true, data: rows });
});

// GET /admin/sessions
router.get('/sessions', async (_req: AuthRequest, res: Response) => {
  const rows = await db
    .select({
      id: userSessions.id,
      device: userSessions.device,
      ipAddress: userSessions.ipAddress,
      location: userSessions.location,
      lastActiveAt: userSessions.lastActiveAt,
      createdAt: userSessions.createdAt,
      expiresAt: userSessions.expiresAt,
      userId: userSessions.userId,
      userEmail: users.email,
      userName: users.username,
    })
    .from(userSessions)
    .leftJoin(users, eq(userSessions.userId, users.id))
    .orderBy(desc(userSessions.lastActiveAt));
  res.json({ success: true, data: rows });
});

// DELETE /admin/sessions/:id
router.delete('/sessions/:id', async (req: AuthRequest, res: Response) => {
  await db.delete(userSessions).where(eq(userSessions.id, req.params.id));
  res.json({ success: true });
});

// DELETE /admin/sessions (revoke all except current)
router.delete('/sessions', async (req: AuthRequest, res: Response) => {
  const all = await db.select({ id: userSessions.id }).from(userSessions);
  for (const s of all) {
    if (s.id !== req.sessionId) {
      await db.delete(userSessions).where(eq(userSessions.id, s.id));
    }
  }
  res.json({ success: true });
});

// GET /admin/notifications
router.get('/notifications', async (_req: AuthRequest, res: Response) => {
  const rows = await db.select().from(adminNotifications).orderBy(desc(adminNotifications.createdAt)).limit(100);
  res.json({ success: true, data: rows });
});

// PATCH /admin/notifications/:id/read
router.patch('/notifications/:id/read', async (req: AuthRequest, res: Response) => {
  await db.update(adminNotifications).set({ isRead: true }).where(eq(adminNotifications.id, req.params.id));
  res.json({ success: true });
});

// PATCH /admin/notifications/read-all
router.patch('/notifications/read-all', async (_req: AuthRequest, res: Response) => {
  await db.update(adminNotifications).set({ isRead: true }).where(eq(adminNotifications.isRead, false));
  res.json({ success: true });
});

// GET /admin/settings
router.get('/settings', async (_req: AuthRequest, res: Response) => {
  const rows = await db.select().from(platformSettings);
  const settings = Object.fromEntries(rows.map(r => [r.key, r.value]));
  res.json({ success: true, data: settings });
});

// PATCH /admin/settings
router.patch('/settings', async (req: AuthRequest, res: Response) => {
  const updates = req.body as Record<string, string>;
  for (const [key, value] of Object.entries(updates)) {
    await db
      .insert(platformSettings)
      .values({ key, value, updatedAt: new Date() })
      .onConflictDoUpdate({ target: platformSettings.key, set: { value, updatedAt: new Date() } });
  }
  res.json({ success: true });
});

// GET /admin/fireblocks-events — paginated webhook event log
router.get('/fireblocks-events', async (req: AuthRequest, res: Response) => {
  const { direction, eventType, limit = '100' } = req.query as Record<string, string>;
  let query = db.select().from(fireblocksEvents).$dynamic();
  if (direction && direction !== 'all') query = query.where(eq(fireblocksEvents.direction, direction));
  if (eventType && eventType !== 'all') query = query.where(eq(fireblocksEvents.eventType, eventType));
  const rows = await query.orderBy(desc(fireblocksEvents.createdAt)).limit(Math.min(parseInt(limit), 1000));
  res.json({ success: true, data: rows });
});

function safeUser(u: typeof users.$inferSelect) {
  const { passwordHash, twoFaSecret, ...safe } = u;
  void passwordHash;
  void twoFaSecret;
  return safe;
}

export default router;
