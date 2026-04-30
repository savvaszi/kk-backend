/**
 * Transfer routes (auth required):
 *   GET  /me/transfers/deposit-address/:asset  – get deposit address for an asset
 *   POST /me/transfers/send                    – internal on-platform send to another user
 *   POST /me/transfers/withdraw                – withdrawal request (off-platform)
 *   GET  /me/transfers                         – transfer history
 */

import { Router } from 'express';
import type { Response } from 'express';
import { db } from '../db/index.js';
import { balances, transactions, users } from '../db/schema.js';
import { eq, and, desc, or } from 'drizzle-orm';
import { requireAuth, type AuthRequest } from '../middleware/auth.js';
import { logAudit } from '../lib/audit.js';
import { ASSETS } from './market.js';

const router = Router();
router.use(requireAuth);

// ── GET /me/transfers/deposit-address/:asset ──────────────────────────────────
// Returns a platform deposit address for the given asset.
// In a custodial platform these are pre-generated vault addresses.
// For demo/staging, we return a static placeholder per asset.

const DEPOSIT_ADDRESSES: Record<string, { address: string; network: string; memo?: string }> = {
  BTC:   { address: 'bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh', network: 'Bitcoin' },
  ETH:   { address: '0x742d35Cc6634C0532925a3b844Bc9e7595Ed5f5e', network: 'Ethereum (ERC-20)' },
  USDT:  { address: '0x742d35Cc6634C0532925a3b844Bc9e7595Ed5f5e', network: 'Ethereum (ERC-20)' },
  USDC:  { address: '0x742d35Cc6634C0532925a3b844Bc9e7595Ed5f5e', network: 'Ethereum (ERC-20)' },
  SOL:   { address: 'DRpbCBMxVnDK7maPGv7GsB4d9aGWzZFHwDGkXKGVzJmP', network: 'Solana' },
  BNB:   { address: '0x742d35Cc6634C0532925a3b844Bc9e7595Ed5f5e', network: 'BNB Smart Chain (BEP-20)' },
  ADA:   { address: 'addr1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh2kzy7pth5cr', network: 'Cardano' },
  MATIC: { address: '0x742d35Cc6634C0532925a3b844Bc9e7595Ed5f5e', network: 'Polygon' },
  AVAX:  { address: '0x742d35Cc6634C0532925a3b844Bc9e7595Ed5f5e', network: 'Avalanche C-Chain' },
  LINK:  { address: '0x742d35Cc6634C0532925a3b844Bc9e7595Ed5f5e', network: 'Ethereum (ERC-20)' },
  ATOM:  { address: 'cosmos1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh', network: 'Cosmos', memo: '1234567890' },
  ARB:   { address: '0x742d35Cc6634C0532925a3b844Bc9e7595Ed5f5e', network: 'Arbitrum One' },
  AAVE:  { address: '0x742d35Cc6634C0532925a3b844Bc9e7595Ed5f5e', network: 'Ethereum (ERC-20)' },
};

router.get('/deposit-address/:asset', async (req: AuthRequest, res: Response) => {
  const asset = req.params.asset.toUpperCase();
  if (!ASSETS[asset]) {
    res.status(400).json({ success: false, error: `Unsupported asset: ${asset}` });
    return;
  }

  const info = DEPOSIT_ADDRESSES[asset];
  if (!info) {
    res.status(503).json({ success: false, error: `Deposit address not available for ${asset}` });
    return;
  }

  res.json({
    success: true,
    data: {
      asset,
      address: info.address,
      network: info.network,
      ...(info.memo ? { memo: info.memo } : {}),
      warning: 'Only send ' + asset + ' on the ' + info.network + ' network. Sending other assets may result in permanent loss.',
    },
  });
});

// ── POST /me/transfers/send ───────────────────────────────────────────────────
// Internal on-platform transfer to another registered user (by email).

router.post('/send', async (req: AuthRequest, res: Response) => {
  const { asset, amount, recipientEmail, note } = req.body;

  if (!asset || !amount || !recipientEmail) {
    res.status(400).json({ success: false, error: 'asset, amount and recipientEmail are required' });
    return;
  }

  const assetSym = (asset as string).toUpperCase();
  if (!ASSETS[assetSym]) {
    res.status(400).json({ success: false, error: `Unsupported asset: ${assetSym}` });
    return;
  }

  const amountNum = parseFloat(amount);
  if (isNaN(amountNum) || amountNum <= 0) {
    res.status(400).json({ success: false, error: 'amount must be a positive number' });
    return;
  }

  // Find recipient
  const [recipient] = await db
    .select({ id: users.id, email: users.email })
    .from(users)
    .where(eq(users.email, (recipientEmail as string).toLowerCase().trim()))
    .limit(1);

  if (!recipient) {
    res.status(404).json({ success: false, error: 'Recipient not found. They must have a Krypto Knight account.' });
    return;
  }

  if (recipient.id === req.userId) {
    res.status(400).json({ success: false, error: 'Cannot send to yourself' });
    return;
  }

  // Check sender balance
  const [senderBal] = await db
    .select()
    .from(balances)
    .where(and(eq(balances.userId, req.userId!), eq(balances.asset, assetSym)))
    .limit(1);

  const available = parseFloat(senderBal?.amount ?? '0');
  if (available < amountNum) {
    res.status(400).json({
      success: false,
      error: `Insufficient ${assetSym} balance. Available: ${available.toFixed(8)}, Required: ${amountNum.toFixed(8)}`,
    });
    return;
  }

  // Deduct from sender
  await db
    .insert(balances)
    .values({ userId: req.userId!, asset: assetSym, amount: (available - amountNum).toFixed(18) })
    .onConflictDoUpdate({
      target: [balances.userId, balances.asset],
      set: { amount: (available - amountNum).toFixed(18), updatedAt: new Date() },
    });

  // Credit to recipient
  const [recipientBal] = await db
    .select()
    .from(balances)
    .where(and(eq(balances.userId, recipient.id), eq(balances.asset, assetSym)))
    .limit(1);
  const currentRecipient = parseFloat(recipientBal?.amount ?? '0');

  await db
    .insert(balances)
    .values({ userId: recipient.id, asset: assetSym, amount: (currentRecipient + amountNum).toFixed(18) })
    .onConflictDoUpdate({
      target: [balances.userId, balances.asset],
      set: { amount: (currentRecipient + amountNum).toFixed(18), updatedAt: new Date() },
    });

  // Record send transaction for sender
  const [sendTx] = await db
    .insert(transactions)
    .values({
      userId: req.userId!,
      type: 'send',
      fromAsset: assetSym,
      toAsset: assetSym,
      fromAmount: amountNum.toString(),
      toAmount: amountNum.toString(),
      fee: '0',
      feeAsset: assetSym,
      status: 'completed',
      note: note ?? null,
      metadata: { recipientId: recipient.id, recipientEmail: recipient.email },
    })
    .returning();

  // Record receive transaction for recipient
  const [senderUser] = await db.select({ email: users.email }).from(users).where(eq(users.id, req.userId!)).limit(1);

  await db.insert(transactions).values({
    userId: recipient.id,
    type: 'receive',
    fromAsset: assetSym,
    toAsset: assetSym,
    fromAmount: amountNum.toString(),
    toAmount: amountNum.toString(),
    fee: '0',
    feeAsset: assetSym,
    status: 'completed',
    note: note ?? null,
    metadata: { senderId: req.userId, senderEmail: senderUser?.email },
  });

  await logAudit({
    userId: req.userId,
    userName: senderUser?.email,
    action: 'Internal Transfer Sent',
    detail: `${amountNum} ${assetSym} → ${recipient.email}`,
    type: 'wallet',
    severity: 'info',
  });

  res.status(201).json({ success: true, data: sendTx });
});

// ── POST /me/transfers/withdraw ───────────────────────────────────────────────
// Off-platform withdrawal: deducts balance and records a pending transaction.
// In production this would trigger a Fireblocks transaction.

router.post('/withdraw', async (req: AuthRequest, res: Response) => {
  const { asset, amount, address, network, note } = req.body;

  if (!asset || !amount || !address) {
    res.status(400).json({ success: false, error: 'asset, amount and address are required' });
    return;
  }

  const assetSym = (asset as string).toUpperCase();
  if (!ASSETS[assetSym]) {
    res.status(400).json({ success: false, error: `Unsupported asset: ${assetSym}` });
    return;
  }

  const amountNum = parseFloat(amount);
  if (isNaN(amountNum) || amountNum <= 0) {
    res.status(400).json({ success: false, error: 'amount must be a positive number' });
    return;
  }

  // Basic address sanity check (non-empty string)
  if (typeof address !== 'string' || address.trim().length < 10) {
    res.status(400).json({ success: false, error: 'Invalid destination address' });
    return;
  }

  // Check balance
  const [bal] = await db
    .select()
    .from(balances)
    .where(and(eq(balances.userId, req.userId!), eq(balances.asset, assetSym)))
    .limit(1);

  const available = parseFloat(bal?.amount ?? '0');
  if (available < amountNum) {
    res.status(400).json({
      success: false,
      error: `Insufficient ${assetSym} balance. Available: ${available.toFixed(8)}, Required: ${amountNum.toFixed(8)}`,
    });
    return;
  }

  // Deduct balance immediately (hold on withdrawal)
  await db
    .insert(balances)
    .values({ userId: req.userId!, asset: assetSym, amount: (available - amountNum).toFixed(18) })
    .onConflictDoUpdate({
      target: [balances.userId, balances.asset],
      set: { amount: (available - amountNum).toFixed(18), updatedAt: new Date() },
    });

  // Record withdrawal transaction as 'pending' (would be updated to completed/failed by Fireblocks webhook)
  const [tx] = await db
    .insert(transactions)
    .values({
      userId: req.userId!,
      type: 'withdrawal',
      fromAsset: assetSym,
      toAsset: assetSym,
      fromAmount: amountNum.toString(),
      toAmount: amountNum.toString(),
      fee: '0',
      feeAsset: assetSym,
      status: 'pending',
      address: address.trim(),
      note: note ?? null,
      metadata: { network: network ?? null, requestedAt: new Date().toISOString() },
    })
    .returning();

  const [user] = await db.select({ email: users.email }).from(users).where(eq(users.id, req.userId!)).limit(1);
  await logAudit({
    userId: req.userId,
    userName: user?.email,
    action: 'Withdrawal Requested',
    detail: `${amountNum} ${assetSym} → ${address.trim().substring(0, 20)}...`,
    type: 'wallet',
    severity: 'warning',
  });

  res.status(201).json({
    success: true,
    data: tx,
    message: 'Withdrawal request submitted. Funds will be sent within 1-2 business hours pending compliance review.',
  });
});

// ── GET /me/transfers ─────────────────────────────────────────────────────────

router.get('/', async (req: AuthRequest, res: Response) => {
  const limit  = Math.min(parseInt((req.query.limit  as string) ?? '25', 10), 100);
  const offset = parseInt((req.query.offset as string) ?? '0', 10);

  const rows = await db
    .select()
    .from(transactions)
    .where(
      and(
        eq(transactions.userId, req.userId!),
        or(
          eq(transactions.type, 'send'),
          eq(transactions.type, 'receive'),
          eq(transactions.type, 'deposit'),
          eq(transactions.type, 'withdrawal'),
        )
      )
    )
    .orderBy(desc(transactions.createdAt))
    .limit(limit)
    .offset(offset);

  res.json({ success: true, data: rows });
});

export default router;
