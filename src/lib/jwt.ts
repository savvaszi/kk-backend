import jwt from 'jsonwebtoken';

const SECRET = process.env.JWT_SECRET!;
const EXPIRES_IN = '7d';

export interface JwtPayload {
  userId: string;
  sessionId: string;
}

export function signToken(payload: JwtPayload): string {
  return jwt.sign(payload, SECRET, { expiresIn: EXPIRES_IN });
}

export function verifyToken(token: string): JwtPayload {
  return jwt.verify(token, SECRET) as JwtPayload;
}

export function tokenExpiresAt(): Date {
  const d = new Date();
  d.setDate(d.getDate() + 7);
  return d;
}

// ── Pre-auth (2FA pending) tokens ────────────────────────────────────────────
// Short-lived, distinct-shape token issued after password check but before a
// TOTP/backup code is verified. Has no sessionId, so it can never be used as
// a bearer session token by requireAuth (session lookup will simply fail).
export interface PreAuthPayload {
  userId: string;
  purpose: 'pre2fa';
}

export function signPreAuthToken(userId: string): string {
  return jwt.sign({ userId, purpose: 'pre2fa' } as PreAuthPayload, SECRET, { expiresIn: '5m' });
}

export function verifyPreAuthToken(token: string): PreAuthPayload {
  const payload = jwt.verify(token, SECRET) as PreAuthPayload;
  if (payload.purpose !== 'pre2fa') throw new Error('Invalid token purpose');
  return payload;
}
