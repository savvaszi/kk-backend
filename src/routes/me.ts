import { Router } from 'express';
import type { Request, Response } from 'express';
import { db, sql as pg } from '../db/index.js';
import { users, userSessions, apiKeys, wallets, auditLogs } from '../db/schema.js';
import { eq, and, gt, desc } from 'drizzle-orm';
import { requireAuth, type AuthRequest } from '../middleware/auth.js';
import { logAudit } from '../lib/audit.js';
import { calcSecurityScore } from '../lib/security.js';
import { generateKeyId, generateRawKey, hashKey } from '../lib/apiKey.js';
import { verifyPassword, hashPassword, matchesPasswordHistory, pushPasswordHistory } from '../lib/password.js';
import { generateSecret, generateURI, verifySync } from 'otplib';
import QRCode from 'qrcode';
import multer from 'multer';
import { randomBytes, randomUUID } from 'node:crypto';
import { sendMail, getRecipient } from '../lib/mailer.js';

const router = Router();
router.use(requireAuth);

// ── GET /me ───────────────────────────────────────────────────────────────────
router.get('/', async (req: AuthRequest, res: Response) => {
  const [user] = await db.select().from(users).where(eq(users.id, req.userId!)).limit(1);
  res.json({ success: true, data: safeUser(user) });
});

// ── PATCH /me ─────────────────────────────────────────────────────────────────
router.patch('/', async (req: AuthRequest, res: Response) => {
  const allowed = [
    'firstName', 'lastName', 'phone', 'bio',
    'country', 'state', 'city', 'zip', 'streetAddress',
    'twitter', 'github', 'instagram', 'telegram',
  ] as const;
  const updates: Partial<typeof users.$inferInsert> = {};
  for (const field of allowed) {
    if (field in req.body) (updates as Record<string, unknown>)[field] = req.body[field] ?? null;
  }
  if (Object.keys(updates).length === 0) {
    res.status(400).json({ success: false, error: 'No valid fields to update' });
    return;
  }
  const [user] = await db
    .update(users)
    .set({ ...updates, updatedAt: new Date() })
    .where(eq(users.id, req.userId!))
    .returning();

  await logAudit({ userId: req.userId, userName: user.email, action: 'Profile Updated', detail: 'User updated profile', type: 'user', severity: 'info' });
  res.json({ success: true, data: safeUser(user) });
});

// ── DELETE /me ────────────────────────────────────────────────────────────────
// GDPR-compliant account deletion — requires password confirmation
router.delete('/', async (req: AuthRequest, res: Response) => {
  const { password } = req.body;
  if (!password) {
    res.status(400).json({ success: false, error: 'password is required to confirm account deletion' });
    return;
  }
  const [user] = await db.select().from(users).where(eq(users.id, req.userId!)).limit(1);
  if (!user) { res.status(404).json({ success: false, error: 'User not found' }); return; }

  const valid = await verifyPassword(password, user.passwordHash);
  if (!valid) { res.status(401).json({ success: false, error: 'Incorrect password' }); return; }

  await logAudit({ userId: req.userId, userName: user.email, action: 'Account Deleted', detail: 'User deleted their account', type: 'user', severity: 'warning' });
  // Cascade deletes sessions, wallets, apiKeys via FK ON DELETE CASCADE
  await db.delete(users).where(eq(users.id, req.userId!));
  res.json({ success: true, message: 'Account deleted' });
});

// ── GET /me/security ──────────────────────────────────────────────────────────
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

// ── POST /me/security/verify-email ────────────────────────────────────────────
// In production this should consume a signed token emailed to the user.
// Here we mark it verified immediately (for development / stub).
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

// ── POST /me/security/setup-2fa ───────────────────────────────────────────────
// Step 1: Generate a TOTP secret, store it (unconfirmed), return QR URI.
router.post('/security/setup-2fa', async (req: AuthRequest, res: Response) => {
  const [user] = await db.select({ email: users.email, twoFaEnabled: users.twoFaEnabled }).from(users).where(eq(users.id, req.userId!)).limit(1);
  if (!user) { res.status(404).json({ success: false, error: 'User not found' }); return; }
  if (user.twoFaEnabled) {
    res.status(400).json({ success: false, error: '2FA is already enabled. Disable it first.' });
    return;
  }
  const secret = generateSecret();
  const otpUri = generateURI({ label: user.email, secret, issuer: 'KryptoKnight' });
  const qrDataUrl = await QRCode.toDataURL(otpUri);

  // Store the secret (unconfirmed). twoFaEnabled stays false until /confirm-2fa.
  await db.update(users).set({ twoFaSecret: secret, updatedAt: new Date() }).where(eq(users.id, req.userId!));

  res.json({ success: true, data: { secret, qrDataUrl, otpUri } });
});

// ── POST /me/security/confirm-2fa ─────────────────────────────────────────────
// Step 2: User submits a TOTP code to confirm setup. Also generates backup codes.
router.post('/security/confirm-2fa', async (req: AuthRequest, res: Response) => {
  const { code } = req.body;
  if (!code) { res.status(400).json({ success: false, error: 'code is required' }); return; }

  const [user] = await db.select().from(users).where(eq(users.id, req.userId!)).limit(1);
  if (!user) { res.status(404).json({ success: false, error: 'User not found' }); return; }
  if (user.twoFaEnabled) { res.status(400).json({ success: false, error: '2FA already confirmed' }); return; }
  if (!user.twoFaSecret) { res.status(400).json({ success: false, error: 'Call /setup-2fa first' }); return; }

  const submittedCode = String(code).trim();
  if (!/^\d{6}$/.test(submittedCode)) {
    res.status(400).json({ success: false, error: 'Enter the 6-digit code from your authenticator app' });
    return;
  }
  let valid = false;
  try {
    valid = verifySync({ token: submittedCode, secret: user.twoFaSecret })?.valid ?? false;
  } catch {
    res.status(400).json({ success: false, error: 'Invalid TOTP code' });
    return;
  }
  if (!valid) { res.status(400).json({ success: false, error: 'Invalid TOTP code' }); return; }

  // Generate 8 single-use backup codes
  const backupCodes = Array.from({ length: 8 }, () => {
    const value = randomBytes(5).toString('hex').toUpperCase();
    return `${value.slice(0, 5)}-${value.slice(5)}`;
  });

  await db.update(users).set({
    twoFaEnabled: true,
    twoFaBackupCodes: backupCodes,
    updatedAt: new Date(),
  }).where(eq(users.id, req.userId!));

  await refreshScore(req.userId!);
  await logAudit({ userId: req.userId, userName: user.email, action: '2FA Enabled', detail: 'TOTP authenticator confirmed', type: 'security', severity: 'success' });

  res.json({ success: true, data: { backupCodes } });
});

// ── POST /me/security/disable-2fa ─────────────────────────────────────────────
// Requires current password + valid TOTP code.
router.post('/security/disable-2fa', async (req: AuthRequest, res: Response) => {
  const { password, code } = req.body;
  if (!password || !code) {
    res.status(400).json({ success: false, error: 'password and code are required' });
    return;
  }
  const [user] = await db.select().from(users).where(eq(users.id, req.userId!)).limit(1);
  if (!user) { res.status(404).json({ success: false, error: 'User not found' }); return; }
  if (!user.twoFaEnabled || !user.twoFaSecret) {
    res.status(400).json({ success: false, error: '2FA is not enabled' });
    return;
  }
  const pwValid = await verifyPassword(password, user.passwordHash);
  if (!pwValid) { res.status(401).json({ success: false, error: 'Incorrect password' }); return; }

  // Accept TOTP code or backup code
  const submittedCode = String(code).trim().toUpperCase();
  let codeValid = false;
  if (/^\d{6}$/.test(submittedCode)) {
    try {
      codeValid = verifySync({ token: submittedCode, secret: user.twoFaSecret })?.valid ?? false;
    } catch {
      codeValid = false;
    }
  }
  let usedBackup = false;
  if (!codeValid && Array.isArray(user.twoFaBackupCodes)) {
    const idx = user.twoFaBackupCodes.indexOf(submittedCode);
    if (idx !== -1) {
      codeValid = true;
      usedBackup = true;
      const newCodes = [...user.twoFaBackupCodes];
      newCodes.splice(idx, 1);
      await db.update(users).set({ twoFaBackupCodes: newCodes }).where(eq(users.id, req.userId!));
    }
  }
  if (!codeValid) { res.status(400).json({ success: false, error: 'Invalid TOTP or backup code' }); return; }

  await db.update(users).set({
    twoFaEnabled: false,
    twoFaSecret: null,
    twoFaBackupCodes: null,
    updatedAt: new Date(),
  }).where(eq(users.id, req.userId!));

  await refreshScore(req.userId!);
  await logAudit({ userId: req.userId, userName: user.email, action: '2FA Disabled', detail: usedBackup ? 'Disabled via backup code' : 'TOTP app disabled', type: 'security', severity: 'warning' });

  res.json({ success: true });
});

// ── POST /me/security/change-password ─────────────────────────────────────────
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
  if (!/[A-Z]/.test(newPassword)) {
    res.status(400).json({ success: false, error: 'New password must contain at least one uppercase letter' });
    return;
  }
  if (!/[0-9]/.test(newPassword)) {
    res.status(400).json({ success: false, error: 'New password must contain at least one number' });
    return;
  }
  const [user] = await db.select().from(users).where(eq(users.id, req.userId!)).limit(1);
  if (!user) { res.status(404).json({ success: false, error: 'User not found' }); return; }
  const valid = await verifyPassword(currentPassword, user.passwordHash);
  if (!valid) { res.status(401).json({ success: false, error: 'Current password is incorrect' }); return; }

  if (await matchesPasswordHistory(newPassword, user.passwordHash, user.passwordHistory ?? [])) {
    res.status(400).json({ success: false, error: 'New password must not match any of your last 4 passwords' });
    return;
  }

  const newHash = await hashPassword(newPassword);
  await db.update(users).set({
    passwordHash: newHash,
    passwordHistory: pushPasswordHistory(user.passwordHash, user.passwordHistory ?? []),
    mustChangePassword: false,
    updatedAt: new Date(),
  }).where(eq(users.id, user.id));

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

// ── GET /me/sessions ──────────────────────────────────────────────────────────
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

// ── DELETE /me/sessions/:id ───────────────────────────────────────────────────
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

// ── DELETE /me/sessions (revoke all others) ───────────────────────────────────
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

// ── GET /me/api-keys ──────────────────────────────────────────────────────────
router.get('/api-keys', async (req: AuthRequest, res: Response) => {
  const keys = await db
    .select({
      id: apiKeys.id, keyId: apiKeys.keyId, name: apiKeys.name,
      permissions: apiKeys.permissions, status: apiKeys.status,
      createdAt: apiKeys.createdAt, lastUsedAt: apiKeys.lastUsedAt,
    })
    .from(apiKeys)
    .where(eq(apiKeys.userId, req.userId!))
    .orderBy(desc(apiKeys.createdAt));
  res.json({ success: true, data: keys });
});

// ── GET /me/api-keys/:id ──────────────────────────────────────────────────────
router.get('/api-keys/:id', async (req: AuthRequest, res: Response) => {
  const [key] = await db
    .select({
      id: apiKeys.id, keyId: apiKeys.keyId, name: apiKeys.name,
      permissions: apiKeys.permissions, status: apiKeys.status,
      createdAt: apiKeys.createdAt, lastUsedAt: apiKeys.lastUsedAt,
    })
    .from(apiKeys)
    .where(and(eq(apiKeys.id, req.params.id), eq(apiKeys.userId, req.userId!)))
    .limit(1);
  if (!key) { res.status(404).json({ success: false, error: 'API key not found' }); return; }
  res.json({ success: true, data: key });
});

// ── POST /me/api-keys ─────────────────────────────────────────────────────────
router.post('/api-keys', async (req: AuthRequest, res: Response) => {
  const { name, permissions = [] } = req.body;
  if (!name) { res.status(400).json({ success: false, error: 'name is required' }); return; }
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

// ── PATCH /me/api-keys/:id ────────────────────────────────────────────────────
// Rename a key or update its permissions.
router.patch('/api-keys/:id', async (req: AuthRequest, res: Response) => {
  const { name, permissions } = req.body;
  const updates: Record<string, unknown> = {};
  if (name !== undefined) updates.name = String(name);
  if (permissions !== undefined) {
    const validPerms = ['read', 'trade', 'withdraw', 'deposit'];
    updates.permissions = (permissions as string[]).filter(p => validPerms.includes(p));
  }
  if (Object.keys(updates).length === 0) {
    res.status(400).json({ success: false, error: 'Provide name or permissions to update' });
    return;
  }
  const [key] = await db
    .update(apiKeys)
    .set(updates as any)
    .where(and(eq(apiKeys.id, req.params.id), eq(apiKeys.userId, req.userId!)))
    .returning({ id: apiKeys.id, keyId: apiKeys.keyId, name: apiKeys.name, permissions: apiKeys.permissions, status: apiKeys.status });
  if (!key) { res.status(404).json({ success: false, error: 'API key not found' }); return; }
  res.json({ success: true, data: key });
});

// ── PATCH /me/api-keys/:id/revoke ─────────────────────────────────────────────
router.patch('/api-keys/:id/revoke', async (req: AuthRequest, res: Response) => {
  await db
    .update(apiKeys)
    .set({ status: 'revoked' })
    .where(and(eq(apiKeys.id, req.params.id), eq(apiKeys.userId, req.userId!)));
  res.json({ success: true });
});

// ── DELETE /me/api-keys/:id ───────────────────────────────────────────────────
router.delete('/api-keys/:id', async (req: AuthRequest, res: Response) => {
  await db
    .delete(apiKeys)
    .where(and(eq(apiKeys.id, req.params.id), eq(apiKeys.userId, req.userId!)));
  res.json({ success: true });
});

// ── GET /me/wallets ───────────────────────────────────────────────────────────
router.get('/wallets', async (req: AuthRequest, res: Response) => {
  const rows = await db.select().from(wallets).where(eq(wallets.userId, req.userId!));
  res.json({ success: true, data: rows });
});

// ── GET /me/wallets/:id ───────────────────────────────────────────────────────
router.get('/wallets/:id', async (req: AuthRequest, res: Response) => {
  const [wallet] = await db
    .select()
    .from(wallets)
    .where(and(eq(wallets.id, req.params.id), eq(wallets.userId, req.userId!)))
    .limit(1);
  if (!wallet) { res.status(404).json({ success: false, error: 'Wallet not found' }); return; }
  res.json({ success: true, data: wallet });
});

// ── POST /me/wallets ──────────────────────────────────────────────────────────
router.post('/wallets', async (req: AuthRequest, res: Response) => {
  const { address, walletType, chainId } = req.body;
  if (!address) { res.status(400).json({ success: false, error: 'address is required' }); return; }
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

// ── PATCH /me/wallets/:id ─────────────────────────────────────────────────────
// Update wallet — currently supports setting it as primary.
router.patch('/wallets/:id', async (req: AuthRequest, res: Response) => {
  const { isPrimary, walletType } = req.body;
  const updates: Record<string, unknown> = {};
  if (walletType !== undefined) updates.walletType = walletType;

  if (isPrimary === true) {
    // Unset all others first
    await db.update(wallets).set({ isPrimary: false }).where(eq(wallets.userId, req.userId!));
    updates.isPrimary = true;
  }
  if (Object.keys(updates).length === 0) {
    res.status(400).json({ success: false, error: 'Provide isPrimary or walletType to update' });
    return;
  }
  const [wallet] = await db
    .update(wallets)
    .set(updates as any)
    .where(and(eq(wallets.id, req.params.id), eq(wallets.userId, req.userId!)))
    .returning();
  if (!wallet) { res.status(404).json({ success: false, error: 'Wallet not found' }); return; }
  res.json({ success: true, data: wallet });
});

// ── DELETE /me/wallets/:id ────────────────────────────────────────────────────
router.delete('/wallets/:id', async (req: AuthRequest, res: Response) => {
  await db.delete(wallets).where(and(eq(wallets.id, req.params.id), eq(wallets.userId, req.userId!)));
  await refreshScore(req.userId!);
  res.json({ success: true });
});

// ── GET /me/notifications ─────────────────────────────────────────────────────
router.get('/notifications', async (req: AuthRequest, res: Response) => {
  const [user] = await db
    .select({ emailNotifications: users.emailNotifications, smsNotifications: users.smsNotifications, pushNotifications: users.pushNotifications })
    .from(users).where(eq(users.id, req.userId!)).limit(1);
  res.json({ success: true, data: user });
});

// ── PATCH /me/notifications ───────────────────────────────────────────────────
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

// ── GET /me/audit ─────────────────────────────────────────────────────────────
router.get('/audit', async (req: AuthRequest, res: Response) => {
  const limit = Math.min(parseInt((req.query.limit as string) ?? '25', 10), 100);
  const logs = await db
    .select()
    .from(auditLogs)
    .where(eq(auditLogs.userId, req.userId!))
    .orderBy(desc(auditLogs.createdAt))
    .limit(limit);
  res.json({ success: true, data: logs });
});

// ── Helpers ───────────────────────────────────────────────────────────────────
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
  const { passwordHash, twoFaSecret, twoFaBackupCodes, passwordResetToken, passwordResetExpiresAt, passwordHistory, ...safe } = u;
  void passwordHash; void twoFaSecret; void twoFaBackupCodes;
  void passwordResetToken; void passwordResetExpiresAt; void passwordHistory;
  return safe;
}

const complaintUpload = multer({
  storage: multer.memoryStorage(),
  limits: { files: 3, fileSize: 10 * 1024 * 1024 },
  fileFilter: (_req, file, cb) => {
    const allowed = ['application/pdf', 'image/jpeg', 'image/png', 'text/plain'];
    if (!allowed.includes(file.mimetype)) cb(new Error('Unsupported attachment type'));
    else cb(null, true);
  },
});
const complaintUploadMiddleware = (req: Request, res: Response, next: (err?: unknown) => void) => {
  complaintUpload.array('attachments', 3)(req, res, err => {
    if (err) { res.status(400).json({ success: false, error: err.message || 'Invalid attachment' }); return; }
    next();
  });
};

const htmlEscape = (value: unknown) => String(value ?? '')
  .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
  .replace(/"/g, '&quot;').replace(/'/g, '&#39;');

// ── Native complaints register ──────────────────────────────────────────────
router.post('/complaints', complaintUploadMiddleware, async (req: AuthRequest, res: Response) => {
  const description = String(req.body.description || '').trim();
  const desiredOutcome = String(req.body.desiredOutcome || '').trim();
  const clientPhone = String(req.body.phone || '').trim();
  const clientAddress = String(req.body.address || '').trim();
  const supportingEvidence = String(req.body.supportingEvidence || '').trim();
  const confirmationName = String(req.body.confirmationName || '').trim();
  const signature = String(req.body.signature || '').trim();
  const declarationAccurate = String(req.body.declarationAccurate) === 'true';
  const declarationEvidence = String(req.body.declarationEvidence) === 'true';
  const declarationAdditionalInfo = String(req.body.declarationAdditionalInfo) === 'true';
  if (description.length < 10 || desiredOutcome.length < 3) {
    res.status(400).json({ success: false, error: 'A detailed complaint and desired outcome are required.' });
    return;
  }
  if (clientPhone.length < 5 || clientAddress.length < 5 || confirmationName.length < 2) {
    res.status(400).json({ success: false, error: 'Address, telephone number, and confirmation name are required.' });
    return;
  }
  if (!declarationAccurate || !declarationEvidence || !declarationAdditionalInfo) {
    res.status(400).json({ success: false, error: 'All submission declarations must be confirmed.' });
    return;
  }
  const files = (req.files as Express.Multer.File[] | undefined) ?? [];
  if (files.some(file => !file.buffer?.length)) {
    res.status(400).json({ success: false, error: 'One or more attachments could not be read.' });
    return;
  }
  if (files.reduce((sum, file) => sum + file.size, 0) > 20 * 1024 * 1024) {
    res.status(400).json({ success: false, error: 'Attachments must be 20 MB or smaller in total.' });
    return;
  }

  const recent = await pg`
    SELECT COUNT(*)::int AS count FROM complaints
    WHERE user_id = ${req.userId!} AND submitted_at > NOW() - INTERVAL '24 hours'
  `;
  if (Number(recent[0]?.count ?? 0) >= 5) {
    res.status(429).json({ success: false, error: 'Too many complaints submitted recently. Please contact Compliance if this is urgent.' });
    return;
  }

  const [user] = await db.select().from(users).where(eq(users.id, req.userId!)).limit(1);
  if (!user) { res.status(401).json({ success: false, error: 'Account not accessible' }); return; }
  const clientName = [user.firstName, user.lastName].filter(Boolean).join(' ') || user.username || user.email;
  const id = randomUUID();
  const reference = `KK-C-${new Date().toISOString().slice(0, 10).replace(/-/g, '')}-${id.slice(0, 8).toUpperCase()}`;

  await pg.begin(async sql => {
    await sql`
      INSERT INTO complaints (
        id, reference, user_id, client_name, client_email, client_phone, client_address,
        account_number, description, affected_date, affected_transaction, desired_outcome,
        supporting_evidence, declaration_accurate, declaration_evidence,
        declaration_additional_info, confirmation_name, signature
      ) VALUES (
        ${id}, ${reference}, ${user.id}, ${clientName}, ${user.email}, ${clientPhone}, ${clientAddress},
        ${String(req.body.accountNumber || '').trim() || null}, ${description},
        ${String(req.body.affectedDate || '').trim() || null}, ${String(req.body.affectedTransaction || '').trim() || null}, ${desiredOutcome},
        ${supportingEvidence || null}, ${declarationAccurate}, ${declarationEvidence},
        ${declarationAdditionalInfo}, ${confirmationName}, ${signature || null}
      )
    `;
    for (const file of files) {
      const filename = file.originalname.replace(/[^\w.\- ]/g, '_').slice(0, 255) || 'evidence';
      await sql`
        INSERT INTO complaint_attachments (complaint_id, filename, mime, size, data)
        VALUES (${id}, ${filename}, ${file.mimetype}, ${file.size}, ${file.buffer})
      `;
    }
  });

  await logAudit({
    userId: user.id, userName: user.email, action: 'Complaint Submitted',
    detail: `${reference} submitted`, type: 'admin', severity: 'info', ipAddress: req.ip,
    metadata: { complaintId: id, reference }, notify: true,
  });

  const recipient = 'compliance@krypto-knight.com';
  const complaintSummary = `
    <table style="border-collapse:collapse;font-family:sans-serif;font-size:14px">
      <tr><td style="padding:5px 12px;font-weight:600">Reference</td><td>${htmlEscape(reference)}</td></tr>
      <tr><td style="padding:5px 12px;font-weight:600">Client</td><td>${htmlEscape(clientName)}</td></tr>
      <tr><td style="padding:5px 12px;font-weight:600">Email</td><td>${htmlEscape(user.email)}</td></tr>
      <tr><td style="padding:5px 12px;font-weight:600">Telephone</td><td>${htmlEscape(clientPhone)}</td></tr>
      <tr><td style="padding:5px 12px;font-weight:600">Address</td><td>${htmlEscape(clientAddress)}</td></tr>
      <tr><td style="padding:5px 12px;font-weight:600">Account number</td><td>${htmlEscape(req.body.accountNumber)}</td></tr>
      <tr><td style="padding:5px 12px;font-weight:600">Affected date</td><td>${htmlEscape(req.body.affectedDate)}</td></tr>
      <tr><td style="padding:5px 12px;font-weight:600">Transaction</td><td>${htmlEscape(req.body.affectedTransaction)}</td></tr>
      <tr><td style="padding:5px 12px;font-weight:600">Complaint</td><td>${htmlEscape(description).replace(/\n/g, '<br>')}</td></tr>
      <tr><td style="padding:5px 12px;font-weight:600">Desired outcome</td><td>${htmlEscape(desiredOutcome).replace(/\n/g, '<br>')}</td></tr>
      <tr><td style="padding:5px 12px;font-weight:600">Evidence description</td><td>${htmlEscape(supportingEvidence).replace(/\n/g, '<br>')}</td></tr>
      <tr><td style="padding:5px 12px;font-weight:600">Confirmed by</td><td>${htmlEscape(confirmationName)}</td></tr>
      <tr><td style="padding:5px 12px;font-weight:600">Signature</td><td>${htmlEscape(signature)}</td></tr>
    </table>`;
  await Promise.allSettled([
    sendMail({
      to: user.email,
      subject: `Krypto Knight complaint received — ${reference}`,
      html: `<p>We have received your formal complaint.</p><p>Your reference number is <strong>${htmlEscape(reference)}</strong>.</p><p>Our Compliance Department will review it and contact you according to our <a href="https://krypto-knight.com/complaints-procedure">Complaints Procedure</a>.</p>`,
    }),
    sendMail({
      to: recipient,
      subject: `New complaint — ${reference}`,
      replyTo: user.email,
      html: `<p>A new formal complaint has been submitted.</p>${complaintSummary}<p>Review and manage it in the admin complaints register.</p>`,
      attachments: files.map(file => ({ filename: file.originalname, content: file.buffer, contentType: file.mimetype })),
    }),
  ]);

  res.status(201).json({ success: true, data: { id, reference, submittedAt: new Date().toISOString(), status: 'received' } });
});

router.get('/complaints/:id', async (req: AuthRequest, res: Response) => {
  const rows = await pg`
    SELECT id, reference, status, submitted_at, updated_at
    FROM complaints WHERE id = ${req.params.id} AND user_id = ${req.userId!}
  `;
  if (!rows[0]) { res.status(404).json({ success: false, error: 'Complaint not found' }); return; }
  res.json({ success: true, data: rows[0] });
});

// ── Complaint form (downloadable by any authenticated client) ─────────────────
// Lightweight availability check for the dashboard UI.
router.get('/complaint-form/meta', async (_req: AuthRequest, res: Response) => {
  const rows = await pg`SELECT filename, size, uploaded_at FROM complaint_form WHERE id = 1`;
  res.json({ success: true, data: rows[0] ? { available: true, ...rows[0] } : { available: false } });
});

// Stream the PDF as an attachment.
router.get('/complaint-form', async (_req: AuthRequest, res: Response) => {
  const rows = await pg`SELECT filename, mime, data FROM complaint_form WHERE id = 1`;
  const row = rows[0];
  if (!row) {
    res.status(404).json({ success: false, error: 'No complaint form is currently available.' });
    return;
  }
  const filename = String(row.filename || 'complaint-form.pdf').replace(/["\r\n]/g, '');
  res.setHeader('Content-Type', row.mime || 'application/pdf');
  res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
  res.send(row.data as Buffer);
});

export default router;
