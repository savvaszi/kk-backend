/**
 * Sumsub Webhook Receiver
 *
 * POST /webhooks/sumsub
 *
 * Sumsub signs the raw body with HMAC-SHA256 using the secret key.
 * The signature is in the X-Payload-Digest header (hex string).
 *
 * Handled events:
 *   applicantReviewed   — reviewAnswer: GREEN → approved, RED → rejected
 *   applicantPending    — applicant submitted, under review
 *   applicantCreated    — applicant created in Sumsub
 *
 * Must be mounted BEFORE express.json() so this route receives the raw body.
 * Use express.raw() to capture bytes for HMAC verification.
 */

import express, { Router, Request, Response } from 'express';
import { db } from '../db/index.js';
import { users, adminNotifications } from '../db/schema.js';
import { eq } from 'drizzle-orm';
import { logAudit } from '../lib/audit.js';
import { verifyWebhookSignature } from '../services/sumsub.js';

const router = Router();

// ── Raw body capture (must come before express.json in the main app) ──────────
router.post('/', express.raw({ type: '*/*', limit: '1mb' }), async (req: Request, res: Response) => {
  // Respond immediately — Sumsub expects a fast 200
  res.json({ received: true });

  const rawBody = req.body as Buffer;
  const signature = req.headers['x-payload-digest'] as string | undefined;

  // ── Signature verification ─────────────────────────────────────────────────
  const sigValid = verifyWebhookSignature(rawBody, signature);
  if (!sigValid) {
    console.warn('[Sumsub Webhook] Invalid signature — ignoring payload');
    return;
  }

  // ── Parse payload ──────────────────────────────────────────────────────────
  let payload: Record<string, any>;
  try {
    payload = JSON.parse(rawBody.toString('utf-8'));
  } catch {
    console.warn('[Sumsub Webhook] Failed to parse JSON body');
    return;
  }

  const type: string = payload.type ?? '';
  const applicantId: string = payload.applicantId ?? '';
  const externalUserId: string = payload.externalUserId ?? '';   // this is our internal user ID
  const reviewResult = payload.reviewResult as Record<string, any> | undefined;

  console.log(`[Sumsub Webhook] Event: ${type}, applicant: ${applicantId}, user: ${externalUserId}`);

  try {
    await handleEvent(type, applicantId, externalUserId, reviewResult, payload);
  } catch (err) {
    console.error('[Sumsub Webhook] Error handling event:', err);
  }
});

// ── Event handler ─────────────────────────────────────────────────────────────
async function handleEvent(
  type: string,
  applicantId: string,
  externalUserId: string,
  reviewResult: Record<string, any> | undefined,
  payload: Record<string, any>,
): Promise<void> {
  switch (type) {
    // ── Applicant reviewed (final decision) ───────────────────────────────────
    case 'applicantReviewed': {
      const reviewAnswer: string = reviewResult?.reviewAnswer ?? '';   // GREEN | RED
      const rejectLabels: string[] = reviewResult?.rejectLabels ?? [];

      const kycStatus = reviewAnswer === 'GREEN' ? 'approved' : 'rejected';
      const kycLevel  = payload.levelName as string | undefined ?? null;

      // Update user in DB
      await db
        .update(users)
        .set({
          kycStatus,
          kycLevel: kycStatus === 'approved' ? kycLevel : null,
          kycReviewedAt: new Date(),
          updatedAt: new Date(),
        })
        .where(eq(users.id, externalUserId));

      // Audit log
      await logAudit({
        userId: externalUserId,
        action: `KYC ${kycStatus === 'approved' ? 'Approved' : 'Rejected'}`,
        detail: kycStatus === 'approved'
          ? `KYC approved. Level: ${kycLevel}`
          : `KYC rejected. Labels: ${rejectLabels.join(', ') || 'none'}`,
        type: 'kyc',
        severity: kycStatus === 'approved' ? 'info' : 'warning',
      });

      // Admin notification
      const title = kycStatus === 'approved'
        ? '✅ KYC Approved'
        : '❌ KYC Rejected';
      const body = kycStatus === 'approved'
        ? `User ${externalUserId} passed KYC (level: ${kycLevel}).`
        : `User ${externalUserId} failed KYC. Reject labels: ${rejectLabels.join(', ') || 'none'}.`;

      await db.insert(adminNotifications).values({
        title,
        body,
        type: kycStatus === 'approved' ? 'info' : 'warning',
        isRead: false,
      });

      console.log(`[Sumsub Webhook] User ${externalUserId} KYC ${kycStatus}`);
      break;
    }

    // ── Applicant pending (submitted, under review) ───────────────────────────
    case 'applicantPending': {
      await db
        .update(users)
        .set({ kycStatus: 'pending', updatedAt: new Date() })
        .where(eq(users.id, externalUserId));

      await logAudit({
        userId: externalUserId,
        action: 'KYC Pending',
        detail: `KYC application submitted, under review. Applicant: ${applicantId}`,
        type: 'kyc',
        severity: 'info',
      });

      console.log(`[Sumsub Webhook] User ${externalUserId} KYC pending`);
      break;
    }

    // ── Applicant created ─────────────────────────────────────────────────────
    case 'applicantCreated': {
      // Usually we already have this from POST /me/kyc/token, but sync just in case
      if (applicantId && externalUserId) {
        await db
          .update(users)
          .set({ sumsubApplicantId: applicantId, updatedAt: new Date() })
          .where(eq(users.id, externalUserId));
      }
      console.log(`[Sumsub Webhook] Applicant created for user ${externalUserId}`);
      break;
    }

    default:
      console.log(`[Sumsub Webhook] Unhandled event type: ${type}`);
  }
}

export default router;
