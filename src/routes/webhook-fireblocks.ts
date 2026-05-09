/**
 * Fireblocks Incoming Webhook Receiver
 *
 * Fireblocks calls this endpoint for every transaction status change,
 * vault event, etc.  We:
 *   1. Verify the RSA-SHA512 signature (using FIREBLOCKS_WEBHOOK_PUBLIC_KEY)
 *   2. Persist every event to `fireblocks_events` (DORA Art. 17 audit trail)
 *   3. Resolve the owning user from the vault ID
 *   4. Classify the direction (deposit / withdrawal / internal)
 *   5. Create admin notifications for completed deposits and failed transactions
 *   6. Write an audit log entry for compliance
 *
 * IMPORTANT: This router must be mounted BEFORE express.json() so we can
 * read the raw body bytes required for signature verification.
 */

import { Router } from 'express';
import express from 'express';
import crypto from 'crypto';
import { db } from '../db/index.js';
import { users, fireblocksEvents, adminNotifications } from '../db/schema.js';
import { eq } from 'drizzle-orm';
import { logAudit } from '../lib/audit.js';
import { sendSecurityAlert } from '../lib/security-alert.js';

const router = Router();

// ─── Signature Verification ───────────────────────────────────────────────────
/**
 * Fireblocks signs webhook bodies with its private key (RSA-SHA512).
 * The matching public key is available in the Fireblocks console:
 *   Settings → General → Workspace IP address allowlist → (scroll) → Webhook public key
 * Store it in the env var FIREBLOCKS_WEBHOOK_PUBLIC_KEY with \n for newlines.
 */
function verifySignature(rawBody: Buffer, signature: string | undefined): boolean {
  if (!signature) return false;

  const rawPublicKey = process.env.FIREBLOCKS_WEBHOOK_PUBLIC_KEY;
  if (!rawPublicKey) {
    // No key configured → sandbox / dev mode; log a warning but allow through
    console.warn('[Webhook] FIREBLOCKS_WEBHOOK_PUBLIC_KEY not set — skipping signature verification (OK in sandbox)');
    return true;
  }

  try {
    const pemKey = rawPublicKey.replace(/\\n/g, '\n');
    const verifier = crypto.createVerify('RSA-SHA512');
    verifier.update(rawBody);
    return verifier.verify(pemKey, signature, 'base64');
  } catch (err) {
    console.error('[Webhook] Signature verification error:', err);
    return false;
  }
}

// ─── Direction Classification ─────────────────────────────────────────────────
type Direction = 'deposit' | 'withdrawal' | 'internal' | 'unknown';

function classifyDirection(data: Record<string, any>): Direction {
  const srcType: string = data?.source?.type ?? '';
  const dstType: string = data?.destination?.type ?? '';

  // Inbound: external → vault
  if (
    (srcType === 'UNKNOWN' || srcType === 'EXTERNAL_WALLET' || srcType === 'ONE_TIME_ADDRESS') &&
    dstType === 'VAULT_ACCOUNT'
  ) return 'deposit';

  // Outbound: vault → external / one-time address
  if (
    srcType === 'VAULT_ACCOUNT' &&
    (dstType === 'UNKNOWN' || dstType === 'EXTERNAL_WALLET' || dstType === 'ONE_TIME_ADDRESS')
  ) return 'withdrawal';

  // Vault-to-vault (internal transfer or sweep)
  if (srcType === 'VAULT_ACCOUNT' && dstType === 'VAULT_ACCOUNT') return 'internal';

  return 'unknown';
}

// ─── Resolve user from vault ID ───────────────────────────────────────────────
async function resolveUser(vaultId: string | null | undefined): Promise<string | null> {
  if (!vaultId) return null;
  const [user] = await db
    .select({ id: users.id })
    .from(users)
    .where(eq(users.fireblocksVaultId, vaultId))
    .limit(1);
  return user?.id ?? null;
}

// ─── Admin notification helper ────────────────────────────────────────────────
async function notify(title: string, body: string, type: 'info' | 'warning' | 'danger' = 'info') {
  await db.insert(adminNotifications).values({ title, body, type });
}

// ─── Main handler ─────────────────────────────────────────────────────────────
router.post(
  '/',
  // Parse as raw Buffer so we can verify the signature before touching the body
  express.raw({ type: '*/*', limit: '1mb' }),
  async (req, res) => {
    // Always respond 200 immediately — Fireblocks retries on non-2xx
    res.json({ received: true });

    const rawBody = req.body as Buffer;
    const signature = req.headers['fireblocks-signature'] as string | undefined;

    // 1. Verify signature
    const sigValid = verifySignature(rawBody, signature);
    if (!sigValid) {
      console.warn('[Webhook] Invalid Fireblocks signature — event stored but flagged');
      sendSecurityAlert({
        code: 'WEBHOOK_SIG_FAIL_FIREBLOCKS',
        level: 'critical',
        ip: (req.headers['x-forwarded-for'] as string | undefined)?.split(',')[0]?.trim() ?? req.ip,
        path: req.path,
        detail: `Fireblocks webhook received with invalid RSA-SHA512 signature. Header: fireblocks-signature=${signature ? signature.slice(0, 16) + '…' : 'missing'}`,
      }).catch(() => {});
    }

    // 2. Parse body
    let event: Record<string, any>;
    try {
      event = JSON.parse(rawBody.toString('utf8'));
    } catch {
      console.error('[Webhook] Failed to parse JSON body');
      return;
    }

    const eventType: string = event?.type ?? 'UNKNOWN';
    const data: Record<string, any> = event?.data ?? {};

    // 3. Extract common transaction fields
    const txId: string | null        = data?.id ?? null;
    const txStatus: string | null    = data?.status ?? null;
    const assetId: string | null     = data?.assetId ?? null;
    const amount: string | null      = data?.amount != null ? String(data.amount) : null;
    const netAmount: string | null   = data?.netAmount != null ? String(data.netAmount) : null;
    const fee: string | null         = data?.fee?.networkFee != null ? String(data.fee.networkFee) : null;
    const sourceType: string | null  = data?.source?.type ?? null;
    const sourceId: string | null    = data?.source?.id ?? null;
    const destType: string | null    = data?.destination?.type ?? null;
    const destId: string | null      = data?.destination?.id ?? null;
    const destAddress: string | null = data?.destination?.address ?? data?.destinationAddress ?? null;

    // The vault that owns this event (could be source or destination)
    const vaultId: string | null =
      sourceType === 'VAULT_ACCOUNT' ? (sourceId ?? null) :
      destType === 'VAULT_ACCOUNT'   ? (destId ?? null) :
      null;

    const direction: Direction = classifyDirection(data);
    const userId: string | null = await resolveUser(vaultId).catch(() => null);

    // 4. Persist to fireblocks_events (DORA audit trail)
    try {
      await db.insert(fireblocksEvents).values({
        fireblocksEventId: event?.eventId ?? null,
        txId,
        eventType,
        txStatus,
        assetId,
        amount,
        netAmount,
        fee,
        sourceType,
        sourceId,
        destinationType: destType,
        destinationId: destId,
        destinationAddress: destAddress,
        vaultId,
        userId,
        direction,
        signatureValid: sigValid,
        rawPayload: event,
      });
    } catch (err) {
      console.error('[Webhook] Failed to persist event:', err);
    }

    // 5. Business logic per event type
    try {
      if (eventType === 'TRANSACTION_COMPLETED') {
        if (direction === 'deposit') {
          const msg = `Deposit of ${amount ?? '?'} ${assetId ?? ''} confirmed${userId ? ` for user ${userId}` : ''} (vault ${vaultId ?? 'unknown'})`;
          console.log(`[Webhook] ✅ DEPOSIT COMPLETED — ${msg}`);

          await notify(
            `Deposit Received`,
            `${amount ?? '?'} ${assetId ?? ''} deposited to vault ${vaultId ?? 'unknown'}${userId ? ` (user ${userId})` : ''}`,
            'info'
          );
          await logAudit({
            userId: userId ?? undefined,
            action: 'Deposit Received',
            detail: `${amount ?? '?'} ${assetId ?? ''} — tx ${txId ?? 'unknown'}`,
            type: 'wallet',
            severity: 'info',
          });

        } else if (direction === 'withdrawal') {
          console.log(`[Webhook] ✅ WITHDRAWAL COMPLETED — tx ${txId}`);
          await logAudit({
            userId: userId ?? undefined,
            action: 'Withdrawal Completed',
            detail: `${amount ?? '?'} ${assetId ?? ''} → ${destAddress ?? destId ?? 'unknown'} — tx ${txId ?? 'unknown'}`,
            type: 'wallet',
            severity: 'info',
          });

        } else {
          console.log(`[Webhook] ✅ TRANSACTION COMPLETED — tx ${txId} (${direction})`);
        }

      } else if (eventType === 'TRANSACTION_FAILED') {
        console.warn(`[Webhook] ❌ TRANSACTION FAILED — tx ${txId}`);
        await notify(
          `Transaction Failed`,
          `tx ${txId ?? 'unknown'} — ${amount ?? '?'} ${assetId ?? ''} (${direction})`,
          'danger'
        );
        await logAudit({
          userId: userId ?? undefined,
          action: 'Transaction Failed',
          detail: `tx ${txId ?? 'unknown'} — ${assetId ?? ''} ${amount ?? '?'} — status: ${txStatus ?? 'FAILED'}`,
          type: 'wallet',
          severity: 'danger',
        });

      } else if (eventType === 'TRANSACTION_REJECTED') {
        console.warn(`[Webhook] 🚫 TRANSACTION REJECTED — tx ${txId}`);
        await notify(
          `Transaction Rejected`,
          `tx ${txId ?? 'unknown'} was rejected — ${amount ?? '?'} ${assetId ?? ''}`,
          'warning'
        );
        await logAudit({
          userId: userId ?? undefined,
          action: 'Transaction Rejected',
          detail: `tx ${txId ?? 'unknown'}`,
          type: 'wallet',
          severity: 'warning',
        });

      } else if (eventType === 'TRANSACTION_BLOCKED') {
        // Blocked by TAP policy or AML/compliance
        console.warn(`[Webhook] 🔒 TRANSACTION BLOCKED — tx ${txId}`);
        await notify(
          `Transaction Blocked by Policy`,
          `tx ${txId ?? 'unknown'} was blocked — ${amount ?? '?'} ${assetId ?? ''} — review TAP/AML policy`,
          'danger'
        );
        await logAudit({
          userId: userId ?? undefined,
          action: 'Transaction Blocked',
          detail: `tx ${txId ?? 'unknown'} blocked by TAP/AML policy — ${assetId ?? ''} ${amount ?? '?'}`,
          type: 'security',
          severity: 'danger',
        });

      } else if (eventType === 'TRANSACTION_PENDING_AUTHORIZATION') {
        console.log(`[Webhook] ⏳ TRANSACTION PENDING AUTHORIZATION — tx ${txId}`);
        await notify(
          `Transaction Awaiting Authorization`,
          `tx ${txId ?? 'unknown'} — ${amount ?? '?'} ${assetId ?? ''} is pending manual authorization in Fireblocks console`,
          'warning'
        );

      } else if (eventType === 'TRANSACTION_CANCELLED') {
        console.log(`[Webhook] ✖ TRANSACTION CANCELLED — tx ${txId}`);
        await logAudit({
          userId: userId ?? undefined,
          action: 'Transaction Cancelled',
          detail: `tx ${txId ?? 'unknown'}`,
          type: 'wallet',
          severity: 'info',
        });

      } else {
        // Log all other events at debug level — stored in DB, no further action needed
        console.log(`[Webhook] 📨 ${eventType} — tx ${txId ?? 'n/a'} status ${txStatus ?? 'n/a'}`);
      }
    } catch (err) {
      console.error('[Webhook] Error processing event:', err);
    }
  }
);

export default router;
