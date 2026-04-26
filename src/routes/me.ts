import { Router } from 'express';
import type { Response } from 'express';
import { db } from '../db/index.js';
import { users, userSessions, apiKeys, wallets, auditLogs } from '../db/schema.js';
import { eq, and, gt, desc } from 'drizzle-orm';
import { requireAuth, type AuthRequest } from '../middleware/auth.js';
import { logAudit } from '../lib/audit.js';
import { calcSecurityScore } from '../lib/security.js';
import { generateKeyId, generateRawKey, hashKey } from '../lib/apiKey.js';

const router = Router();
router.use(requireAuth);

// GET /me - own profile
router.get('/', async (req: AuthRequest, res: Response) => {
  const [user] = await db.select().from(users).where(eq(users.id, req.userId!)).limit(1);
  res.json({ success: true, data: safeUser(user) });
});

// PATCH /me - update profile
router.patch('/', async (req: AuthRequest, res: Response) => {
  const allowed = [
    'firstName', 'lastName', 'phone', 'bio',
    'country', 'state', 'city', 'zip', 'streetAddress',
    'twitter', 'github', 'instagram', 'telegram',
  ] as const;
  const updates: Record<string, string | null> = {};
  for (const field of allowed) {
    if (field in req.body) updates[snakeCase(field)] = req.body[field] ?? null;
  }
  if (Object.keys(updates).length === 0) {
    res.status(400).json({ success: false, error: 'No valid fields to update' });
    return;
  }
  const [user] = await db
    .update(users)
    .set({ ...mapKeys(updates), updatedAt: new Date() })
    .where(eq(users.id, req.userId!))
    .returning();

  await logAudit({ userId: req.userId, userName: user.email, action: 'Profile Updated', detail: 'User updated profile', type: 'user', severity: 'info' });
  res.json({ success: true, data: safeUser(user) });
});

// GET /me/security
router.get('/security', async (req: AuthRequest, res: Response) => {
  const [user] = await db.select().from(users).where(eq(users.id, req.userId!)).limit(1);
  const walletRows = await db.select({ id: wallets.id }).from(wallets).where(eq(wallets.userId, req.userId!));
  const score = calcSecurityScore({
    emailVerified: user.emailVerified,
    phoneVerified: user.phoneVerified,
    twoFaEnabled: user.twoFaEnabled,
    walletCount: walletRows.length,
  });
  await db.update(users).set({ securityScore: score }).where(eq(users.id, req.userId!));
  res.json({
    success: true,
    data: {
      score,
      emailVerified: user.emailVerified,
      phoneVerified: user.phoneVerified,
      twoFaEnabled: user.twoFaEnabled,
      walletCount: walletRows.length,
    },
  });
});

// POST /me/security/verify-email
router.post('/security/verify-email', async (req: AuthRequest, res: Response) => {
  const [user] = await db
    .update(users)
    .set({ emailVerified: true, updatedAt: new Date() })
    .where(eq(users.id, req.userId!))
    .returning();
  await refreshScore(req.userId!);
  await logAudit({ userId: req.userId, userName: user.email, action: 'Email Verified', detail: 'Email address verified', type: 'security', severity: 'success' });
  res.json({ success: true });
});

// POST /me/security/enable-2fa
router.post('/security/enable-2fa', async (req: AuthRequest, res: Response) => {
  const [user] = await db
    .update(users)
    .set({ twoFaEnabled: true, updatedAt: new Date() })
    .where(eq(users.id, req.userId!))
    .returning();
  await refreshScore(req.userId!);
  await logAudit({ userId: req.userId, userName: user.email, action: '2FA Enabled', detail: 'Authenticator app connected', type: 'security', severity: 'success' });
  res.json({ success: true });
});

// GET /me/sessions
router.get('/sessions', async (req: AuthRequest, res: Response) => {
  const sessions = await db
    .select()
    .from(userSessions)
    .where(and(eq(userSessions.userId, req.userId!), gt(userSessions.expiresAt, new Date())))
    .orderBy(desc(userSessions.lastActiveAt));
  res.json({
    success: true,
    data: sessions.map(s => ({ ...s, isCurrent: s.id === req.sessionId })),
  });
});

// DELETE /me/sessions/:id
router.delete('/sessions/:id', async (req: AuthRequest, res: Response) => {
  if (req.params.id === req.sessionId) {
    res.status(400).json({ success: false, error: 'Cannot revoke current session; use /auth/logout' });
    return;
  }
  await db
    .delete(userSessions)
    .where(and(eq(userSessions.id, req.params.id), eq(userSessions.userId, req.userId!)));
  res.json({ success: true });
});

// DELETE /me/sessions (revoke all others)
router.delete('/sessions', async (req: AuthRequest, res: Response) => {
  const all = await db
    .select({ id: userSessions.id })
    .from(userSessions)
    .where(eq(userSessions.userId, req.userId!));
  for (const s of all) {
    if (s.id !== req.sessionId) {
      await db.delete(userSessions).where(eq(userSessions.id, s.id));
    }
  }
  res.json({ success: true });
});

// GET /me/api-keys
router.get('/api-keys', async (req: AuthRequest, res: Response) => {
  const keys = await db
    .select({ id: apiKeys.id, keyId: apiKeys.keyId, name: apiKeys.name, permissions: apiKeys.permissions, status: apiKeys.status, createdAt: apiKeys.createdAt, lastUsedAt: apiKeys.lastUsedAt })
    .from(apiKeys)
    .where(eq(apiKeys.userId, req.userId!))
    .orderBy(desc(apiKeys.createdAt));
  res.json({ success: true, data: keys });
});

// POST /me/api-keys
router.post('/api-keys', async (req: AuthRequest, res: Response) => {
  const { name, permissions = [] } = req.body;
  if (!name) {
    res.status(400).json({ success: false, error: 'name is required' });
    return;
  }
  const validPerms = ['read', 'trade', 'withdraw', 'deposit'];
  const perms = (permissions as string[]).filter(p => validPerms.includes(p));
  const keyId = generateKeyId();
  const raw = generateRawKey();
  const keyHash = await hashKey(raw);
  const fullKey = `${keyId}.${raw}`;

  const [key] = await db
    .insert(apiKeys)
    .values({ userId: req.userId!, keyId, keyHash, name, permissions: perms })
    .returning({ id: apiKeys.id, keyId: apiKeys.keyId, name: apiKeys.name, permissions: apiKeys.permissions, createdAt: apiKeys.createdAt });

  const [user] = await db.select({ email: users.email }).from(users).where(eq(users.id, req.userId!)).limit(1);
  await logAudit({ userId: req.userId, userName: user.email, action: 'API Key Created', detail: `${name} key created`, type: 'api', severity: 'info' });

  res.status(201).json({ success: true, data: { ...key, fullKey } });
});

// PATCH /me/api-keys/:id/revoke
router.patch('/api-keys/:id/revoke', async (req: AuthRequest, res: Response) => {
  await db
    .update(apiKeys)
    .set({ status: 'revoked' })
    .where(and(eq(apiKeys.id, req.params.id), eq(apiKeys.userId, req.userId!)));
  res.json({ success: true });
});

// DELETE /me/api-keys/:id
router.delete('/api-keys/:id', async (req: AuthRequest, res: Response) => {
  await db
    .delete(apiKeys)
    .where(and(eq(apiKeys.id, req.params.id), eq(apiKeys.userId, req.userId!)));
  res.json({ success: true });
});

// GET /me/wallets
router.get('/wallets', async (req: AuthRequest, res: Response) => {
  const rows = await db.select().from(wallets).where(eq(wallets.userId, req.userId!));
  res.json({ success: true, data: rows });
});

// POST /me/wallets
router.post('/wallets', async (req: AuthRequest, res: Response) => {
  const { address, walletType, chainId } = req.body;
  if (!address) {
    res.status(400).json({ success: false, error: 'address is required' });
    return;
  }
  const existingWallets = await db.select({ id: wallets.id }).from(wallets).where(eq(wallets.userId, req.userId!));
  const [wallet] = await db
    .insert(wallets)
    .values({ userId: req.userId!, address, walletType: walletType ?? null, chainId: chainId ?? null, isPrimary: existingWallets.length === 0 })
    .returning();
  await refreshScore(req.userId!);
  const [user] = await db.select({ email: users.email }).from(users).where(eq(users.id, req.userId!)).limit(1);
  await logAudit({ userId: req.userId, userName: user.email, action: 'Wallet Connected', detail: `${walletType ?? 'Wallet'} — ${address.slice(0, 10)}...`, type: 'wallet', severity: 'info' });
  res.status(201).json({ success: true, data: wallet });
});

// DELETE /me/wallets/:id
router.delete('/wallets/:id', async (req: AuthRequest, res: Response) => {
  await db.delete(wallets).where(and(eq(wallets.id, req.params.id), eq(wallets.userId, req.userId!)));
  await refreshScore(req.userId!);
  res.json({ success: true });
});

// GET /me/notifications
router.get('/notifications', async (req: AuthRequest, res: Response) => {
  const [user] = await db
    .select({ emailNotifications: users.emailNotifications, smsNotifications: users.smsNotifications, pushNotifications: users.pushNotifications })
    .from(users).where(eq(users.id, req.userId!)).limit(1);
  res.json({ success: true, data: user });
});

// GET /me/audit
router.get('/audit', async (req: AuthRequest, res: Response) => {
  const limit = Math.min(parseInt(req.query.limit as string ?? '25', 10), 100);
  const logs = await db
    .select()
    .from(auditLogs)
    .where(eq(auditLogs.userId, req.userId!))
    .orderBy(desc(auditLogs.createdAt))
    .limit(limit);
  res.json({ success: true, data: logs });
});

// POST /me/security/change-password
router.post('/security/change-password', async (req: AuthRequest, res: Response) => {
  const { currentPassword, newPassword } = req.body;
  if (!currentPassword || !newPassword) {
    res.status(400).json({ success: false, error: 'currentPassword and newPassword are required' });
    return;
  }
  if (newPassword.length < 8) {
    res.status(400).json({ success: false, error: 'New password must be at least 8 characters' });
    return;
  }
  const { verifyPassword, hashPassword } = await import('../lib/password.js');
  const [user] = await db.select().from(users).where(eq(users.id, req.userId!)).limit(1);
  if (!user) { res.status(404).json({ success: false, error: 'User not found' }); return; }
  const valid = await verifyPassword(currentPassword, user.passwordHash);
  if (!valid) { res.status(401).json({ success: false, error: 'Current password is incorrect' }); return; }
  const newHash = await hashPassword(newPassword);
  await db.update(users).set({ passwordHash: newHash, updatedAt: new Date() }).where(eq(users.id, user.id));
  // Revoke all other sessions for security
  const allSessions = await db.select({ id: userSessions.id }).from(userSessions).where(eq(userSessions.userId, user.id));
  for (const s of allSessions) {
    if (s.id !== req.sessionId) {
      await db.delete(userSessions).where(eq(userSessions.id, s.id));
    }
  }
  await logAudit({ userId: req.userId, userName: user.email, action: 'Password Changed', detail: 'Password updated successfully', type: 'security', severity: 'success' });
  res.json({ success: true });
});

// PATCH /me/notifications
router.patch('/notifications', async (req: AuthRequest, res: Response) => {
  const { emailNotifications, smsNotifications, pushNotifications } = req.body;
  await db.update(users).set({
    ...(emailNotifications !== undefined && { emailNotifications: Boolean(emailNotifications) }),
    ...(smsNotifications !== undefined && { smsNotifications: Boolean(smsNotifications) }),
    ...(pushNotifications !== undefined && { pushNotifications: Boolean(pushNotifications) }),
    updatedAt: new Date(),
  }).where(eq(users.id, req.userId!));
  res.json({ success: true });
});

// Helpers
async function refreshScore(userId: string) {
  const [user] = await db.select().from(users).where(eq(users.id, userId)).limit(1);
  const walletRows = await db.select({ id: wallets.id }).from(wallets).where(eq(wallets.userId, userId));
  const score = calcSecurityScore({
    emailVerified: user.emailVerified,
    phoneVerified: user.phoneVerified,
    twoFaEnabled: user.twoFaEnabled,
    walletCount: walletRows.length,
  });
  await db.update(users).set({ securityScore: score }).where(eq(users.id, userId));
}

function safeUser(u: typeof users.$inferSelect) {
  const { passwordHash, twoFaSecret, ...safe } = u;
  void passwordHash;
  void twoFaSecret;
  return safe;
}

function snakeCase(s: string) {
  return s.replace(/([A-Z])/g, '_$1').toLowerCase();
}

function mapKeys(obj: Record<string, unknown>): Record<string, unknown> {
  return Object.fromEntries(Object.entries(obj).map(([k, v]) => [camelCase(k), v]));
}

function camelCase(s: string) {
  return s.replace(/_([a-z])/g, (_, c) => c.toUpperCase());
}

export default router;
