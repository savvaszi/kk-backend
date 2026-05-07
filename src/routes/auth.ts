import { Router } from 'express';
import type { Request, Response } from 'express';
import { db } from '../db/index.js';
import { users, userSessions } from '../db/schema.js';
import { eq, and, gt } from 'drizzle-orm';
import { hashPassword, verifyPassword } from '../lib/password.js';
import { signToken, verifyToken, tokenExpiresAt } from '../lib/jwt.js';
import { logAudit } from '../lib/audit.js';
import { requireAuth, type AuthRequest } from '../middleware/auth.js';
import crypto from 'crypto';
import { sendMail } from '../lib/mailer.js';

const router = Router();

// ── Helpers ───────────────────────────────────────────────────────────────────
function safeUser(u: typeof users.$inferSelect) {
  const { passwordHash, twoFaSecret, twoFaBackupCodes, passwordResetToken, passwordResetExpiresAt, ...safe } = u;
  void passwordHash; void twoFaSecret; void twoFaBackupCodes;
  void passwordResetToken; void passwordResetExpiresAt;
  return safe;
}

function validateEmail(email: string): boolean {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function validatePassword(pw: string): string | null {
  if (pw.length < 8) return 'Password must be at least 8 characters';
  if (!/[A-Z]/.test(pw)) return 'Password must contain at least one uppercase letter';
  if (!/[0-9]/.test(pw)) return 'Password must contain at least one number';
  return null;
}

function validateUsername(u: string): string | null {
  if (u.length < 3) return 'Username must be at least 3 characters';
  if (u.length > 30) return 'Username must be at most 30 characters';
  if (!/^[a-z0-9_]+$/i.test(u)) return 'Username may only contain letters, numbers and underscores';
  return null;
}

async function createSession(userId: string, req: Request) {
  const [session] = await db.insert(userSessions).values({
    userId,
    tokenHash: 'bearer',
    device: req.headers['user-agent']?.slice(0, 255) ?? null,
    ipAddress: (req.headers['x-forwarded-for'] as string)?.split(',')[0]?.trim() ?? req.ip?.slice(0, 50) ?? null,
    isCurrent: true,
    expiresAt: tokenExpiresAt(),
  }).returning();
  return session;
}

// ── POST /auth/register ───────────────────────────────────────────────────────
router.post('/register', async (req: Request, res: Response) => {
  const { email, username, password, firstName, lastName } = req.body;

  if (!email || !username || !password) {
    res.status(400).json({ success: false, error: 'email, username and password are required' });
    return;
  }
  if (!validateEmail(email)) {
    res.status(400).json({ success: false, error: 'Invalid email address' });
    return;
  }
  const usernameErr = validateUsername(username);
  if (usernameErr) { res.status(400).json({ success: false, error: usernameErr }); return; }

  const pwErr = validatePassword(password);
  if (pwErr) { res.status(400).json({ success: false, error: pwErr }); return; }

  const [byEmail] = await db.select({ id: users.id }).from(users).where(eq(users.email, email.toLowerCase())).limit(1);
  if (byEmail) { res.status(409).json({ success: false, error: 'Email already registered' }); return; }

  const [byUsername] = await db.select({ id: users.id }).from(users).where(eq(users.username, username.toLowerCase())).limit(1);
  if (byUsername) { res.status(409).json({ success: false, error: 'Username already taken' }); return; }

  const passwordHash = await hashPassword(password);
  const [user] = await db.insert(users).values({
    email: email.toLowerCase(),
    username: username.toLowerCase(),
    passwordHash,
    firstName: firstName ?? null,
    lastName: lastName ?? null,
    status: 'active',
  }).returning();

  const session = await createSession(user.id, req);
  const token = signToken({ userId: user.id, sessionId: session.id });

  await logAudit({
    userId: user.id, userName: user.email,
    action: 'Account Registered', detail: 'New user sign-up',
    type: 'auth', severity: 'info',
    ipAddress: req.ip ?? undefined, notify: true,
  });

  res.status(201).json({ success: true, data: { token, user: safeUser(user) } });
});

// ── POST /auth/login ──────────────────────────────────────────────────────────
router.post('/login', async (req: Request, res: Response) => {
  const { email, password } = req.body;
  if (!email || !password) {
    res.status(400).json({ success: false, error: 'email and password are required' });
    return;
  }

  const [user] = await db.select().from(users).where(eq(users.email, email.toLowerCase())).limit(1);
  if (!user || !(await verifyPassword(password, user.passwordHash))) {
    res.status(401).json({ success: false, error: 'Invalid credentials' });
    return;
  }
  if (user.status === 'banned') {
    res.status(403).json({ success: false, error: 'Account is banned' });
    return;
  }

  const session = await createSession(user.id, req);
  const token = signToken({ userId: user.id, sessionId: session.id });

  await db.update(users).set({ lastSeenAt: new Date() }).where(eq(users.id, user.id));
  await logAudit({
    userId: user.id, userName: user.email,
    action: 'Login', detail: `Login from ${req.headers['user-agent']?.slice(0, 80) ?? 'unknown'}`,
    type: 'auth', severity: 'info', ipAddress: req.ip ?? undefined,
  });

  res.json({ success: true, data: { token, user: safeUser(user) } });
});

// ── POST /auth/logout ─────────────────────────────────────────────────────────
router.post('/logout', requireAuth, async (req: AuthRequest, res: Response) => {
  await db.delete(userSessions).where(eq(userSessions.id, req.sessionId!));
  res.json({ success: true });
});

// ── POST /auth/refresh ────────────────────────────────────────────────────────
// Exchange a still-valid token for a fresh one with a new 7-day window.
router.post('/refresh', requireAuth, async (req: AuthRequest, res: Response) => {
  // Extend session expiry
  const newExpiry = tokenExpiresAt();
  await db.update(userSessions)
    .set({ expiresAt: newExpiry, lastActiveAt: new Date() })
    .where(eq(userSessions.id, req.sessionId!));

  const token = signToken({ userId: req.userId!, sessionId: req.sessionId! });
  const [user] = await db.select().from(users).where(eq(users.id, req.userId!)).limit(1);

  res.json({ success: true, data: { token, user: safeUser(user) } });
});

// ── POST /auth/check-availability ────────────────────────────────────────────
// Check whether an email or username is already taken (public, for sign-up UX).
router.post('/check-availability', async (req: Request, res: Response) => {
  const { email, username } = req.body;
  const result: Record<string, boolean> = {};

  if (email) {
    if (!validateEmail(email)) {
      res.status(400).json({ success: false, error: 'Invalid email format' });
      return;
    }
    const [row] = await db.select({ id: users.id }).from(users).where(eq(users.email, email.toLowerCase())).limit(1);
    result.emailAvailable = !row;
  }

  if (username) {
    const [row] = await db.select({ id: users.id }).from(users).where(eq(users.username, username.toLowerCase())).limit(1);
    result.usernameAvailable = !row;
  }

  if (!email && !username) {
    res.status(400).json({ success: false, error: 'Provide email or username to check' });
    return;
  }

  res.json({ success: true, data: result });
});

// ── POST /auth/forgot-password ────────────────────────────────────────────────
// Generate a password-reset token and send it via email only.
// The token is NEVER returned in the API response.
router.post('/forgot-password', async (req: Request, res: Response) => {
  const { email } = req.body;
  if (!email) { res.status(400).json({ success: false, error: 'email is required' }); return; }

  const [user] = await db.select({ id: users.id, email: users.email }).from(users)
    .where(eq(users.email, email.toLowerCase())).limit(1);

  // Always return the same response to avoid email enumeration
  const genericResponse = { success: true, message: 'If that email is registered, a reset link has been sent.' };

  if (!user) {
    res.json(genericResponse);
    return;
  }

  const rawToken = crypto.randomBytes(32).toString('hex');
  const tokenHash = crypto.createHash('sha256').update(rawToken).digest('hex');
  const expiresAt = new Date(Date.now() + 60 * 60 * 1000); // 1 hour

  await db.update(users).set({
    passwordResetToken: tokenHash,
    passwordResetExpiresAt: expiresAt,
    updatedAt: new Date(),
  }).where(eq(users.id, user.id));

  await logAudit({ userId: user.id, userName: user.email, action: 'Password Reset Requested', type: 'security', severity: 'warning' });

  // Send reset link via email only — never expose the token in the response
  const resetLink = `https://krypto-knight.com/reset-password?token=${rawToken}`;
  sendMail({
    to: user.email,
    subject: 'Krypto Knight — Password Reset Request',
    html: `
      <div style="font-family:sans-serif;max-width:520px;margin:0 auto;padding:32px">
        <h2 style="color:#0d1117">Password Reset</h2>
        <p>We received a request to reset the password for your Krypto Knight account.</p>
        <p>Click the button below to set a new password. This link expires in <strong>1 hour</strong>.</p>
        <a href="${resetLink}" style="display:inline-block;margin:20px 0;padding:12px 24px;background:#00FF9C;color:#000;font-weight:700;text-decoration:none;border-radius:6px">Reset Password</a>
        <p style="color:#666;font-size:12px">If you did not request this, you can safely ignore this email. Your password will not change.</p>
        <p style="color:#666;font-size:12px">Link: ${resetLink}</p>
      </div>`,
  }).catch(err => console.error('[forgot-password] email error:', err?.message));

  res.json(genericResponse);
});

// ── POST /auth/reset-password ─────────────────────────────────────────────────
router.post('/reset-password', async (req: Request, res: Response) => {
  const { token, newPassword } = req.body;
  if (!token || !newPassword) {
    res.status(400).json({ success: false, error: 'token and newPassword are required' });
    return;
  }

  const pwErr = validatePassword(newPassword);
  if (pwErr) { res.status(400).json({ success: false, error: pwErr }); return; }

  const tokenHash = crypto.createHash('sha256').update(token).digest('hex');

  const [user] = await db.select().from(users)
    .where(and(
      eq(users.passwordResetToken, tokenHash),
      gt(users.passwordResetExpiresAt!, new Date()),
    )).limit(1);

  if (!user) {
    res.status(400).json({ success: false, error: 'Invalid or expired reset token' });
    return;
  }

  const newHash = await hashPassword(newPassword);
  await db.update(users).set({
    passwordHash: newHash,
    passwordResetToken: null,
    passwordResetExpiresAt: null,
    updatedAt: new Date(),
  }).where(eq(users.id, user.id));

  // Invalidate all sessions
  await db.delete(userSessions).where(eq(userSessions.userId, user.id));

  await logAudit({ userId: user.id, userName: user.email, action: 'Password Reset', type: 'security', severity: 'success' });

  res.json({ success: true, message: 'Password reset successful. Please log in again.' });
});

export default router;
