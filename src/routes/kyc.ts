/**
 * KYC routes — user-facing (requires auth)
 *
 * GET  /me/kyc/status        — get current KYC status
 * POST /me/kyc/token         — generate a Sumsub Web SDK access token
 * GET  /me/kyc/applicant     — get full Sumsub applicant details (debug/admin)
 * POST /me/kyc/reset         — reset KYC in sandbox (for re-testing)
 */

import { Router } from 'express';
import type { Response } from 'express';
import { db } from '../db/index.js';
import { users } from '../db/schema.js';
import { eq } from 'drizzle-orm';
import { requireAuth, type AuthRequest } from '../middleware/auth.js';
import { logAudit } from '../lib/audit.js';
import * as sumsub from '../services/sumsub.js';

const router = Router();
router.use(requireAuth);

function guard(res: Response): boolean {
  if (!sumsub.isConfigured()) {
    res.status(503).json({ success: false, error: 'KYC service not configured.' });
    return false;
  }
  return true;
}

// ── GET /me/kyc/status ────────────────────────────────────────────────────────
router.get('/status', async (req: AuthRequest, res: Response) => {
  const [user] = await db
    .select({
      kycStatus: users.kycStatus,
      kycLevel: users.kycLevel,
      kycReviewedAt: users.kycReviewedAt,
      sumsubApplicantId: users.sumsubApplicantId,
    })
    .from(users)
    .where(eq(users.id, req.userId!))
    .limit(1);

  res.json({
    success: true,
    data: {
      status: user?.kycStatus ?? 'none',      // none | pending | approved | rejected
      level: user?.kycLevel ?? null,
      reviewedAt: user?.kycReviewedAt ?? null,
      hasApplicant: !!user?.sumsubApplicantId,
    },
  });
});

// ── POST /me/kyc/token ────────────────────────────────────────────────────────
/**
 * Creates a Sumsub applicant if one doesn't exist yet,
 * then returns a short-lived Web SDK access token.
 * The frontend uses this token to initialise the Sumsub verification widget.
 */
router.post('/token', async (req: AuthRequest, res: Response) => {
  if (!guard(res)) return;

  try {
    const [user] = await db.select().from(users).where(eq(users.id, req.userId!)).limit(1);
    if (!user) { res.status(404).json({ success: false, error: 'User not found' }); return; }

    // Use our internal user ID as the Sumsub external user ID
    const externalUserId = user.id;
    const levelName = (req.body.levelName as string | undefined) ?? sumsub.LEVEL_NAME;

    // Create applicant in Sumsub if not yet created
    if (!user.sumsubApplicantId) {
      const applicant = await sumsub.createApplicant(externalUserId, levelName);
      await db
        .update(users)
        .set({ sumsubApplicantId: applicant.id, kycStatus: 'none', updatedAt: new Date() })
        .where(eq(users.id, user.id));

      await logAudit({
        userId: user.id,
        userName: user.email,
        action: 'KYC Applicant Created',
        detail: `Sumsub applicant ${applicant.id} created for level "${levelName}"`,
        type: 'kyc',
        severity: 'info',
      });
    }

    // Always generate a fresh short-lived token (default 30 min TTL)
    const ttl = parseInt(req.body.ttlInSecs as string ?? '1800', 10);
    const { token } = await sumsub.generateAccessToken(externalUserId, levelName, ttl);

    res.json({ success: true, data: { token, levelName, expiresInSecs: ttl } });
  } catch (err: any) {
    console.error('[KYC] Token generation error:', err);
    res.status(500).json({ success: false, error: err?.message ?? 'KYC token generation failed' });
  }
});

// ── GET /me/kyc/applicant ─────────────────────────────────────────────────────
router.get('/applicant', async (req: AuthRequest, res: Response) => {
  if (!guard(res)) return;

  const [user] = await db
    .select({ sumsubApplicantId: users.sumsubApplicantId })
    .from(users)
    .where(eq(users.id, req.userId!))
    .limit(1);

  if (!user?.sumsubApplicantId) {
    res.json({ success: true, data: null });
    return;
  }

  try {
    const applicant = await sumsub.getApplicant(user.sumsubApplicantId);
    res.json({ success: true, data: applicant });
  } catch (err: any) {
    res.status(500).json({ success: false, error: err?.message });
  }
});

// ── POST /me/kyc/reset ────────────────────────────────────────────────────────
// Sandbox only — resets the applicant so you can re-test the full KYC flow
router.post('/reset', async (req: AuthRequest, res: Response) => {
  if (!guard(res)) return;

  const [user] = await db
    .select({ sumsubApplicantId: users.sumsubApplicantId, email: users.email })
    .from(users)
    .where(eq(users.id, req.userId!))
    .limit(1);

  if (!user?.sumsubApplicantId) {
    res.status(400).json({ success: false, error: 'No KYC applicant found. Call /me/kyc/token first.' });
    return;
  }

  try {
    await sumsub.resetApplicant(user.sumsubApplicantId);
    await db
      .update(users)
      .set({ kycStatus: 'none', kycLevel: null, kycReviewedAt: null, updatedAt: new Date() })
      .where(eq(users.id, req.userId!));

    await logAudit({
      userId: req.userId,
      userName: user.email,
      action: 'KYC Reset',
      detail: 'Applicant reset in Sumsub sandbox',
      type: 'kyc',
      severity: 'info',
    });

    res.json({ success: true });
  } catch (err: any) {
    res.status(500).json({ success: false, error: err?.message });
  }
});

export default router;
