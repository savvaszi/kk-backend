import { Router } from 'express';
import express from 'express';
import type { Response } from 'express';
import { db, sql as pg } from '../db/index.js';
import { users, userSessions, apiKeys, wallets, auditLogs, adminNotifications, platformSettings, fireblocksEvents, applications } from '../db/schema.js';
import { eq, desc, ilike, or, count, and, lt, sql } from 'drizzle-orm';
import { requireAuth, requireAdmin, requireFullAdmin, type AuthRequest } from '../middleware/auth.js';
import { logAudit } from '../lib/audit.js';
import { invalidateMailer, testSmtp } from '../lib/mailer.js';
import { generateKeyId, generateRawKey, hashKey } from '../lib/apiKey.js';
import { hashPassword, matchesPasswordHistory, pushPasswordHistory } from '../lib/password.js';

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
router.patch('/users/:id', requireFullAdmin, async (req: AuthRequest, res: Response) => {
  const allowed = ['firstName', 'lastName', 'email', 'username', 'level', 'status', 'isAdmin', 'adminRole'] as const;
  const updates: Record<string, unknown> = {};
  for (const field of allowed) {
    if (field in req.body) updates[field] = req.body[field];
  }
  if ('adminRole' in updates && !['full', 'kyc_reviewer', null].includes(updates.adminRole as string | null)) {
    res.status(400).json({ success: false, error: "adminRole must be 'full', 'kyc_reviewer', or null" });
    return;
  }
  // Granting admin without a role, or revoking admin, is meaningless/dangerous — keep the two fields in sync.
  if (updates.isAdmin === true && !('adminRole' in updates)) updates.adminRole = 'kyc_reviewer';
  if (updates.isAdmin === false) updates.adminRole = null;
  const [user] = await db.update(users).set({ ...updates, updatedAt: new Date() }).where(eq(users.id, req.params.id)).returning();
  await logAudit({ userId: user.id, userName: user.email, action: 'User Updated', detail: `Fields updated by admin: ${Object.keys(updates).join(', ')}`, type: 'admin', severity: 'info' });
  res.json({ success: true, data: safeUser(user) });
});

// POST /admin/users/:id/reset-password
router.post('/users/:id/reset-password', requireFullAdmin, async (req: AuthRequest, res: Response) => {
  const { password } = req.body;
  if (!password || typeof password !== 'string' || password.length < 6) {
    res.status(400).json({ success: false, error: 'Password must be at least 6 characters' });
    return;
  }
  const [target] = await db.select().from(users).where(eq(users.id, req.params.id)).limit(1);
  if (!target) { res.status(404).json({ success: false, error: 'User not found' }); return; }
  if (await matchesPasswordHistory(password, target.passwordHash, target.passwordHistory ?? [])) {
    res.status(400).json({ success: false, error: 'New password must not match any of the last 4 passwords' });
    return;
  }
  const passwordHash = await hashPassword(password);
  const [user] = await db.update(users).set({
    passwordHash,
    passwordHistory: pushPasswordHistory(target.passwordHash, target.passwordHistory ?? []),
    // Admin-assigned passwords are temporary — force a change on next login for admin accounts (PCI DSS 8.3.5)
    mustChangePassword: target.isAdmin ? true : target.mustChangePassword,
    updatedAt: new Date(),
  }).where(eq(users.id, req.params.id)).returning();
  await logAudit({ userId: user.id, userName: user.email, action: 'Password Reset', detail: 'Password reset by admin', type: 'security', severity: 'warning' });
  res.json({ success: true });
});

// POST /admin/users/:id/ban
router.post('/users/:id/ban', requireFullAdmin, async (req: AuthRequest, res: Response) => {
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
router.post('/users/:id/unban', requireFullAdmin, async (req: AuthRequest, res: Response) => {
  const [user] = await db
    .update(users)
    .set({ status: 'active', updatedAt: new Date() })
    .where(eq(users.id, req.params.id))
    .returning();
  if (!user) { res.status(404).json({ success: false, error: 'User not found' }); return; }
  await logAudit({ userId: user.id, userName: user.email, action: 'Account Unbanned', detail: 'Account restored by admin', type: 'security', severity: 'info' });
  res.json({ success: true });
});

// POST /admin/users (create manually) — full admins only, since this can also mint other admins
router.post('/users', requireFullAdmin, async (req: AuthRequest, res: Response) => {
  const { email, username, password, firstName, lastName, level = 0, status = 'active', isAdmin = false, adminRole } = req.body;
  if (!email || !username || !password) {
    res.status(400).json({ success: false, error: 'email, username and password are required' }); return;
  }
  if (typeof password !== 'string' || password.length < 6) {
    res.status(400).json({ success: false, error: 'Password must be at least 6 characters' }); return;
  }
  if (isAdmin && !['full', 'kyc_reviewer'].includes(adminRole)) {
    res.status(400).json({ success: false, error: "adminRole must be 'full' or 'kyc_reviewer' when isAdmin is true" }); return;
  }
  const passwordHash = await hashPassword(password);
  try {
    const [user] = await db.insert(users)
      .values({
        email, username, passwordHash, firstName, lastName, level, status, emailVerified: true,
        isAdmin: !!isAdmin,
        adminRole: isAdmin ? adminRole : null,
        // Individually-provisioned admin accounts start with a temporary password (PCI DSS 8.3.5)
        mustChangePassword: !!isAdmin,
      })
      .returning();
    await logAudit({ userId: user.id, userName: user.email, action: 'User Created', detail: isAdmin ? `Admin account created by admin (role: ${adminRole})` : 'Account created by admin', type: 'admin', severity: 'info' });
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
router.post('/users/:id/notify', requireFullAdmin, async (req: AuthRequest, res: Response) => {
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
router.get('/api-keys', requireFullAdmin, async (_req: AuthRequest, res: Response) => {
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
router.post('/api-keys', requireFullAdmin, async (req: AuthRequest, res: Response) => {
  const { userId, name, permissions = [] } = req.body;
  if (!userId || !name) { res.status(400).json({ success: false, error: 'userId and name required' }); return; }
  const validPerms = ['read', 'trade', 'withdraw', 'deposit', 'complaints:read'];
  const perms = (permissions as string[]).filter(p => validPerms.includes(p));
  const keyId = generateKeyId();
  const raw = generateRawKey();
  const keyHash = await hashKey(raw);
  const [key] = await db.insert(apiKeys).values({ userId, keyId, keyHash, name, permissions: perms }).returning({ id: apiKeys.id, keyId: apiKeys.keyId, name: apiKeys.name, permissions: apiKeys.permissions, createdAt: apiKeys.createdAt });
  res.status(201).json({ success: true, data: { ...key, fullKey: `${keyId}.${raw}` } });
});

// PATCH /admin/api-keys/:id/revoke
router.patch('/api-keys/:id/revoke', requireFullAdmin, async (req: AuthRequest, res: Response) => {
  await db.update(apiKeys).set({ status: 'revoked' }).where(eq(apiKeys.id, req.params.id));
  res.json({ success: true });
});

// PATCH /admin/api-keys/:id/restore
router.patch('/api-keys/:id/restore', requireFullAdmin, async (req: AuthRequest, res: Response) => {
  await db.update(apiKeys).set({ status: 'active' }).where(eq(apiKeys.id, req.params.id));
  res.json({ success: true });
});

// DELETE /admin/api-keys/:id
router.delete('/api-keys/:id', requireFullAdmin, async (req: AuthRequest, res: Response) => {
  await db.delete(apiKeys).where(eq(apiKeys.id, req.params.id));
  res.json({ success: true });
});

// GET /admin/audit
router.get('/audit', requireFullAdmin, async (req: AuthRequest, res: Response) => {
  const { severity, type, limit = '50' } = req.query as Record<string, string>;
  let query = db.select().from(auditLogs).$dynamic();
  if (severity && severity !== 'all') query = query.where(eq(auditLogs.severity, severity));
  if (type && type !== 'all') query = query.where(eq(auditLogs.type, type));
  const rows = await query.orderBy(desc(auditLogs.createdAt)).limit(Math.min(parseInt(limit), 500));
  res.json({ success: true, data: rows });
});

// GET /admin/sessions
router.get('/sessions', requireFullAdmin, async (_req: AuthRequest, res: Response) => {
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
router.delete('/sessions/:id', requireFullAdmin, async (req: AuthRequest, res: Response) => {
  await db.delete(userSessions).where(eq(userSessions.id, req.params.id));
  res.json({ success: true });
});

// DELETE /admin/sessions (revoke all except current)
router.delete('/sessions', requireFullAdmin, async (req: AuthRequest, res: Response) => {
  const all = await db.select({ id: userSessions.id }).from(userSessions);
  for (const s of all) {
    if (s.id !== req.sessionId) {
      await db.delete(userSessions).where(eq(userSessions.id, s.id));
    }
  }
  res.json({ success: true });
});

// GET /admin/notifications
router.get('/notifications', requireFullAdmin, async (_req: AuthRequest, res: Response) => {
  const rows = await db.select().from(adminNotifications).orderBy(desc(adminNotifications.createdAt)).limit(100);
  res.json({ success: true, data: rows });
});

// PATCH /admin/notifications/:id/read
router.patch('/notifications/:id/read', requireFullAdmin, async (req: AuthRequest, res: Response) => {
  await db.update(adminNotifications).set({ isRead: true }).where(eq(adminNotifications.id, req.params.id));
  res.json({ success: true });
});

// PATCH /admin/notifications/read-all
router.patch('/notifications/read-all', requireFullAdmin, async (_req: AuthRequest, res: Response) => {
  await db.update(adminNotifications).set({ isRead: true }).where(eq(adminNotifications.isRead, false));
  res.json({ success: true });
});

// GET /admin/settings
router.get('/settings', requireFullAdmin, async (_req: AuthRequest, res: Response) => {
  const rows = await db.select().from(platformSettings);
  const settings = Object.fromEntries(rows.map(r => [r.key, r.value]));
  res.json({ success: true, data: settings });
});

// PATCH /admin/settings
router.patch('/settings', requireFullAdmin, async (req: AuthRequest, res: Response) => {
  const updates = req.body as Record<string, string>;
  for (const [key, value] of Object.entries(updates)) {
    await db
      .insert(platformSettings)
      .values({ key, value, updatedAt: new Date() })
      .onConflictDoUpdate({ target: platformSettings.key, set: { value, updatedAt: new Date() } });
  }
  // If any SMTP key was updated, invalidate the cached mailer config
  const smtpKeys = ['smtp_host','smtp_port','smtp_secure','smtp_user','smtp_pass','smtp_from','smtp_recipient'];
  if (Object.keys(updates).some(k => smtpKeys.includes(k))) {
    invalidateMailer();
  }
  res.json({ success: true });
});

// POST /admin/smtp/test — verify credentials and send a test email
router.post('/smtp/test', requireFullAdmin, async (req: AuthRequest, res: Response) => {
  const { host, port, secure, user, pass, from, recipient, testTo } = req.body as Record<string, string>;
  const toEmail = testTo || recipient || 'info@krypto-knight.com';
  try {
    await testSmtp({ host, port: parseInt(port||'587'), secure: secure==='true', user, pass, from, recipient }, toEmail);
    res.json({ success: true, message: `Test email sent to ${toEmail}` });
  } catch (err: any) {
    res.status(400).json({ success: false, error: err?.message || 'SMTP test failed' });
  }
});

// GET /admin/applications — list all applications with user info (no file data)
router.get('/applications', async (req: AuthRequest, res: Response) => {
  const { type, limit = '200', offset = '0' } = req.query as Record<string, string>;

  const rows = await db
    .select({
      id:            applications.id,
      userId:        applications.userId,
      type:          applications.type,
      data:          applications.data,
      documents:     applications.documents,
      submittedAt:   applications.submittedAt,
      userEmail:     users.email,
      userFirstName: users.firstName,
      userLastName:  users.lastName,
      kycStatus:     users.kycStatus,
    })
    .from(applications)
    .leftJoin(users, eq(applications.userId, users.id))
    .where(type && type !== 'all' ? eq(applications.type, type) : sql`1=1`)
    .orderBy(desc(applications.submittedAt))
    .limit(Math.min(parseInt(limit) || 200, 500))
    .offset(parseInt(offset) || 0);

  const sanitized = rows.map(app => ({
    ...app,
    documents: (app.documents as any[]).map(({ data: _data, ...meta }) => meta),
  }));

  res.json({ success: true, data: sanitized, total: sanitized.length });
});

// GET /admin/applications/:userId — latest application for a user (no file data)
router.get('/applications/:userId', async (req: AuthRequest, res: Response) => {
  const rows = await db
    .select()
    .from(applications)
    .where(eq(applications.userId, req.params.userId))
    .orderBy(desc(applications.submittedAt))
    .limit(5);

  if (!rows.length) {
    res.json({ success: true, data: null });
    return;
  }

  // Strip base64 file data — only return metadata so the response stays small
  const sanitized = rows.map(app => ({
    ...app,
    documents: (app.documents as any[]).map(({ data: _data, ...meta }) => meta),
  }));

  res.json({ success: true, data: sanitized });
});

// GET /admin/applications/:userId/document/:docIndex — download uploaded file
router.get('/applications/:userId/document/:docIndex', async (req: AuthRequest, res: Response) => {
  const [app] = await db
    .select()
    .from(applications)
    .where(eq(applications.userId, req.params.userId))
    .orderBy(desc(applications.submittedAt))
    .limit(1);

  if (!app) { res.status(404).json({ success: false, error: 'No application found' }); return; }

  const idx = parseInt(req.params.docIndex, 10);
  const docs = app.documents as any[];
  if (!docs[idx]) { res.status(404).json({ success: false, error: 'Document not found' }); return; }

  const doc = docs[idx];
  const buffer = Buffer.from(doc.data, 'base64');
  res.setHeader('Content-Type', doc.mimetype);
  res.setHeader('Content-Disposition', `attachment; filename="${encodeURIComponent(doc.name)}"`);
  res.setHeader('Content-Length', buffer.length);
  res.send(buffer);
});

// GET /admin/fireblocks-events — paginated webhook event log
router.get('/fireblocks-events', requireFullAdmin, async (req: AuthRequest, res: Response) => {
  const { direction, eventType, limit = '100' } = req.query as Record<string, string>;
  let query = db.select().from(fireblocksEvents).$dynamic();
  if (direction && direction !== 'all') query = query.where(eq(fireblocksEvents.direction, direction));
  if (eventType && eventType !== 'all') query = query.where(eq(fireblocksEvents.eventType, eventType));
  const rows = await query.orderBy(desc(fireblocksEvents.createdAt)).limit(Math.min(parseInt(limit), 1000));
  res.json({ success: true, data: rows });
});

function safeUser(u: typeof users.$inferSelect) {
  const { passwordHash, twoFaSecret, passwordHistory, ...safe } = u;
  void passwordHash;
  void twoFaSecret;
  void passwordHistory;
  return safe;
}

const COMPLAINT_CATEGORIES = ['Execution', 'Information quality', 'Fees', 'Admin', 'Unauthorised business', 'Withdrawal issues', 'Other', 'Advice', 'Portfolio management'];
const COMPLAINT_STATUSES = ['received', 'investigating', 'resolved', 'rejected', 'closed'];
const isUuid = (value: unknown) => typeof value === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value);

const complaintRows = async () => pg`
  SELECT c.*, u.email AS user_email,
    CONCAT_WS(' ', u.first_name, u.last_name) AS user_name,
    CONCAT_WS(' ', a.first_name, a.last_name) AS assignee_name
  FROM complaints c
  LEFT JOIN users u ON u.id = c.user_id
  LEFT JOIN users a ON a.id = c.assigned_to
  ORDER BY c.submitted_at DESC
  LIMIT 1000
`;

function filterComplaints(rows: any[], query: Record<string, string>) {
  const from = query.from ? new Date(`${query.from}T00:00:00.000Z`).getTime() : 0;
  const to = query.to ? new Date(`${query.to}T23:59:59.999Z`).getTime() : Number.MAX_SAFE_INTEGER;
  return rows.filter(row =>
    (!query.status || query.status === 'all' || row.status === query.status) &&
    (!query.category || query.category === 'all' || row.category === query.category) &&
    new Date(row.submitted_at).getTime() >= from && new Date(row.submitted_at).getTime() <= to
  );
}

function csvCell(value: unknown) {
  return `"${String(value ?? '').replace(/"/g, '""').replace(/[\r\n]+/g, ' ')}"`;
}

function complaintsCsv(rows: any[]) {
  const fields = [
    'reference', 'client_name', 'client_email', 'client_phone', 'client_address',
    'account_number', 'status', 'category', 'submitted_at', 'acknowledged_at',
    'resolved_at', 'affected_date', 'affected_transaction', 'description',
    'desired_outcome', 'supporting_evidence', 'confirmation_name', 'signature',
    'resolution_summary',
  ];
  return [fields.join(','), ...rows.map(row => fields.map(field => csvCell(row[field])).join(','))].join('\r\n');
}

// ── Complaints register ─────────────────────────────────────────────────────
router.get('/complaints', requireFullAdmin, async (req: AuthRequest, res: Response) => {
  const rows = filterComplaints(await complaintRows(), req.query as Record<string, string>);
  res.json({ success: true, data: rows.map(({ internal_notes: _internal, ...row }) => row) });
});

router.get('/complaints/report', requireFullAdmin, async (req: AuthRequest, res: Response) => {
  const rows = filterComplaints(await complaintRows(), req.query as Record<string, string>);
  const summary = {
    total: rows.length,
    byStatus: Object.fromEntries(COMPLAINT_STATUSES.map(status => [status, rows.filter(row => row.status === status).length])),
    byCategory: Object.fromEntries(COMPLAINT_CATEGORIES.map(category => [category, rows.filter(row => row.category === category).length])),
  };
  await logAudit({ userId: req.userId, action: 'Complaint Report Exported', detail: `${rows.length} complaints`, type: 'admin', severity: 'info', ipAddress: req.ip });
  if ((req.query.format as string) === 'csv') {
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', 'attachment; filename="complaints-report.csv"');
    res.send(complaintsCsv(rows));
    return;
  }
  res.json({ success: true, data: { summary, csv: complaintsCsv(rows) } });
});

router.post('/complaints/integration-key', requireFullAdmin, async (req: AuthRequest, res: Response) => {
  const name = String(req.body?.name || 'Complaints CRM integration').trim().slice(0, 255);
  const keyId = generateKeyId();
  const raw = generateRawKey();
  const keyHash = await hashKey(raw);
  const [key] = await db.insert(apiKeys).values({
    userId: req.userId!, keyId, keyHash, name, permissions: ['complaints:read'],
  }).returning({ id: apiKeys.id, keyId: apiKeys.keyId, name: apiKeys.name, permissions: apiKeys.permissions, createdAt: apiKeys.createdAt });
  await logAudit({ userId: req.userId, action: 'Complaints CRM Key Created', detail: name, type: 'api', severity: 'warning', ipAddress: req.ip });
  res.status(201).json({ success: true, data: { ...key, fullKey: `${keyId}.${raw}` } });
});

router.get('/complaints/:id/attachments/:attachmentId', requireFullAdmin, async (req: AuthRequest, res: Response) => {
  const rows = await pg`
    SELECT a.filename, a.mime, a.data
    FROM complaint_attachments a
    WHERE a.id = ${req.params.attachmentId} AND a.complaint_id = ${req.params.id}
  `;
  if (!rows[0]) { res.status(404).json({ success: false, error: 'Attachment not found' }); return; }
  await logAudit({ userId: req.userId, action: 'Complaint Attachment Accessed', detail: `${req.params.id}/${req.params.attachmentId}`, type: 'admin', severity: 'info', ipAddress: req.ip, metadata: { complaintId: req.params.id } });
  res.setHeader('Content-Type', rows[0].mime);
  res.setHeader('Content-Disposition', `attachment; filename="${String(rows[0].filename).replace(/["\r\n]/g, '_')}"`);
  res.send(rows[0].data);
});

router.get('/complaints/:id', requireFullAdmin, async (req: AuthRequest, res: Response) => {
  const rows = await pg`
    SELECT c.*, u.email AS user_email,
      CONCAT_WS(' ', u.first_name, u.last_name) AS user_name,
      CONCAT_WS(' ', a.first_name, a.last_name) AS assignee_name
    FROM complaints c
    LEFT JOIN users u ON u.id = c.user_id
    LEFT JOIN users a ON a.id = c.assigned_to
    WHERE c.id = ${req.params.id}
  `;
  if (!rows[0]) { res.status(404).json({ success: false, error: 'Complaint not found' }); return; }
  const attachments = await pg`SELECT id, filename, mime, size, uploaded_at FROM complaint_attachments WHERE complaint_id = ${req.params.id} ORDER BY uploaded_at`;
  const events = await pg`
    SELECT action, detail, severity, user_name, created_at
    FROM audit_logs
    WHERE metadata->>'complaintId' = ${req.params.id}
    ORDER BY created_at DESC
  `;
  res.json({ success: true, data: { ...rows[0], attachments, events } });
});

router.patch('/complaints/:id', requireFullAdmin, async (req: AuthRequest, res: Response) => {
  const body = req.body as Record<string, unknown>;
  if (body.status !== undefined && !COMPLAINT_STATUSES.includes(String(body.status))) {
    res.status(400).json({ success: false, error: 'Invalid complaint status' }); return;
  }
  if (body.category !== undefined && body.category !== null && !COMPLAINT_CATEGORIES.includes(String(body.category))) {
    res.status(400).json({ success: false, error: 'Invalid complaint category' }); return;
  }
  if (body.assignedTo !== undefined && body.assignedTo !== null && !isUuid(body.assignedTo)) {
    res.status(400).json({ success: false, error: 'Invalid assignee' }); return;
  }
  const status = body.status === undefined ? null : String(body.status);
  const category = body.category === undefined ? null : body.category === null ? null : String(body.category);
  const internalNotes = body.internalNotes === undefined ? null : String(body.internalNotes || '');
  const resolutionSummary = body.resolutionSummary === undefined ? null : String(body.resolutionSummary || '');
  const assignedTo = body.assignedTo === undefined ? null : body.assignedTo;
  const assignedToValue = assignedTo === null ? null : String(assignedTo);
  const result = await pg`
    UPDATE complaints SET
      status = COALESCE(${status}, status),
      category = CASE WHEN ${body.category === undefined} THEN category ELSE ${category} END,
      internal_notes = CASE WHEN ${body.internalNotes === undefined} THEN internal_notes ELSE ${internalNotes} END,
      resolution_summary = CASE WHEN ${body.resolutionSummary === undefined} THEN resolution_summary ELSE ${resolutionSummary} END,
      assigned_to = CASE WHEN ${body.assignedTo === undefined} THEN assigned_to ELSE ${assignedToValue} END,
      acknowledged_at = CASE WHEN ${status} IN ('investigating', 'resolved', 'rejected', 'closed') AND acknowledged_at IS NULL THEN NOW() ELSE acknowledged_at END,
      resolved_at = CASE WHEN ${status} IN ('resolved', 'rejected', 'closed') THEN COALESCE(resolved_at, NOW()) WHEN ${status} = 'investigating' THEN NULL ELSE resolved_at END,
      updated_at = NOW()
    WHERE id = ${req.params.id}
    RETURNING *
  `;
  if (!result[0]) { res.status(404).json({ success: false, error: 'Complaint not found' }); return; }
  await logAudit({ userId: req.userId, action: 'Complaint Updated', detail: `${result[0].reference}: ${result[0].status}${result[0].category ? ` · ${result[0].category}` : ''}`, type: 'admin', severity: 'info', ipAddress: req.ip, metadata: { complaintId: req.params.id, fields: Object.keys(body) } });
  res.json({ success: true, data: result[0] });
});

// ── Complaint form (single downloadable PDF for clients) ──────────────────────
// GET metadata of the currently published form (null if none).
router.get('/complaint-form', requireFullAdmin, async (_req: AuthRequest, res: Response) => {
  const rows = await pg`SELECT filename, mime, size, uploaded_by, uploaded_at FROM complaint_form WHERE id = 1`;
  res.json({ success: true, data: rows[0] ?? null });
});

// POST upload/replace the form. Raw PDF body (max 10 MB); filename via X-Filename header.
router.post('/complaint-form', requireFullAdmin,
  express.raw({ type: ['application/pdf', 'application/octet-stream'], limit: '10mb' }),
  async (req: AuthRequest, res: Response) => {
    const buf = req.body as Buffer;
    if (!Buffer.isBuffer(buf) || buf.length === 0) {
      res.status(400).json({ success: false, error: 'No file received. Send the PDF as the raw request body.' });
      return;
    }
    if (buf.subarray(0, 5).toString('latin1') !== '%PDF-') {
      res.status(400).json({ success: false, error: 'File must be a PDF.' });
      return;
    }
    const raw = (req.headers['x-filename'] as string) || 'complaint-form.pdf';
    const filename = raw.replace(/[^\w.\- ]/g, '_').slice(0, 255) || 'complaint-form.pdf';
    await pg`
      INSERT INTO complaint_form (id, filename, mime, data, size, uploaded_by, uploaded_at)
      VALUES (1, ${filename}, 'application/pdf', ${buf}, ${buf.length}, ${req.userId ?? null}, NOW())
      ON CONFLICT (id) DO UPDATE SET
        filename = EXCLUDED.filename, mime = EXCLUDED.mime, data = EXCLUDED.data,
        size = EXCLUDED.size, uploaded_by = EXCLUDED.uploaded_by, uploaded_at = NOW()
    `;
    await logAudit({ userId: req.userId, action: 'Complaint Form Updated', detail: `${filename} (${buf.length} bytes)`, type: 'admin', severity: 'info', ipAddress: req.ip ?? undefined });
    res.json({ success: true, data: { filename, size: buf.length } });
  });

// DELETE the published form.
router.delete('/complaint-form', requireFullAdmin, async (req: AuthRequest, res: Response) => {
  await pg`DELETE FROM complaint_form WHERE id = 1`;
  await logAudit({ userId: req.userId, action: 'Complaint Form Deleted', type: 'admin', severity: 'warning', ipAddress: req.ip ?? undefined });
  res.json({ success: true });
});

export default router;
