/**
 * Orders routes (auth required):
 *   GET    /me/orders              – list orders (?status=open|filled|cancelled|all)
 *   GET    /me/orders/:id          – single order
 *   POST   /me/orders              – place a new order
 *   DELETE /me/orders/:id          – cancel an open order
 */

import { Router } from 'express';
import type { Response } from 'express';
import { db } from '../db/index.js';
import { orders, balances, transactions, users } from '../db/schema.js';
import { eq, and, desc, sql } from 'drizzle-orm';
import { requireAuth, type AuthRequest } from '../middleware/auth.js';
import { logAudit } from '../lib/audit.js';
import { ASSETS } from './market.js';

const router = Router();
router.use(requireAuth);

const VALID_PAIRS = [
  'BTC/USDT', 'ETH/USDT', 'SOL/USDT', 'BNB/USDT', 'ADA/USDT',
  'MATIC/USDT', 'AVAX/USDT', 'LINK/USDT', 'ATOM/USDT', 'ARB/USDT',
  'AAVE/USDT', 'ETH/BTC', 'SOL/BTC',
];

// ── GET /me/orders ────────────────────────────────────────────────────────────

router.get('/', async (req: AuthRequest, res: Response) => {
  const status = (req.query.status as string) ?? 'all';
  const limit = Math.min(parseInt((req.query.limit as string) ?? '50', 10), 200);

  const conditions = [eq(orders.userId, req.userId!)];
  if (status !== 'all' && ['open', 'filled', 'cancelled', 'partial'].includes(status)) {
    conditions.push(eq(orders.status, status));
  }

  const rows = await db
    .select()
    .from(orders)
    .where(and(...conditions))
    .orderBy(desc(orders.createdAt))
    .limit(limit);

  res.json({ success: true, data: rows });
});

// ── GET /me/orders/:id ────────────────────────────────────────────────────────

router.get('/:id', async (req: AuthRequest, res: Response) => {
  const [order] = await db
    .select()
    .from(orders)
    .where(and(eq(orders.id, req.params.id), eq(orders.userId, req.userId!)))
    .limit(1);

  if (!order) { res.status(404).json({ success: false, error: 'Order not found' }); return; }
  res.json({ success: true, data: order });
});

// ── POST /me/orders ───────────────────────────────────────────────────────────
// For market orders: executes immediately (balance check → fill → record tx).
// For limit orders:  queued as 'open' (requires background matching engine for real fills).

router.post('/', async (req: AuthRequest, res: Response) => {
  const { pair, side, orderType, price, amount } = req.body;

  if (!pair || !side || !orderType || !amount) {
    res.status(400).json({ success: false, error: 'pair, side, orderType and amount are required' });
    return;
  }
  if (!VALID_PAIRS.includes(pair)) {
    res.status(400).json({ success: false, error: `Unsupported pair. Supported: ${VALID_PAIRS.join(', ')}` });
    return;
  }
  if (!['buy', 'sell'].includes(side)) {
    res.status(400).json({ success: false, error: 'side must be buy or sell' });
    return;
  }
  if (!['limit', 'market'].includes(orderType)) {
    res.status(400).json({ success: false, error: 'orderType must be limit or market' });
    return;
  }
  if (orderType === 'limit' && !price) {
    res.status(400).json({ success: false, error: 'price is required for limit orders' });
    return;
  }

  const amountNum = parseFloat(amount);
  if (isNaN(amountNum) || amountNum <= 0) {
    res.status(400).json({ success: false, error: 'amount must be a positive number' });
    return;
  }

  const [baseAsset, quoteAsset] = pair.split('/');

  // For market orders: check balance and fill immediately
  if (orderType === 'market') {
    const spendAsset = side === 'buy' ? quoteAsset : baseAsset;
    const receiveAsset = side === 'buy' ? baseAsset : quoteAsset;

    // Fetch current price
    let fillPrice = parseFloat(price ?? '0');
    if (!fillPrice) {
      try {
        const cgId = ASSETS[baseAsset];
        if (cgId) {
          const r = await fetch(
            `https://api.coingecko.com/api/v3/simple/price?ids=${cgId}&vs_currencies=usd`,
            { signal: AbortSignal.timeout(5_000) }
          );
          const d = await r.json() as any;
          fillPrice = d[cgId]?.usd ?? 0;
        }
      } catch { /* use 0 if unavailable */ }
    }

    const spendAmount = side === 'buy' ? amountNum * fillPrice : amountNum;
    const receiveAmount = side === 'buy' ? amountNum : amountNum * fillPrice;

    // Check balance
    const [spendBalance] = await db
      .select()
      .from(balances)
      .where(and(eq(balances.userId, req.userId!), eq(balances.asset, spendAsset)))
      .limit(1);

    const available = parseFloat(spendBalance?.amount ?? '0');
    if (available < spendAmount) {
      res.status(400).json({
        success: false,
        error: `Insufficient ${spendAsset} balance. Available: ${available.toFixed(8)}, Required: ${spendAmount.toFixed(8)}`,
      });
      return;
    }

    // Deduct spend asset
    await db
      .insert(balances)
      .values({ userId: req.userId!, asset: spendAsset, amount: (available - spendAmount).toFixed(18) })
      .onConflictDoUpdate({
        target: [balances.userId, balances.asset],
        set: { amount: (available - spendAmount).toFixed(18), updatedAt: new Date() },
      });

    // Credit receive asset
    const [receiveBalance] = await db
      .select()
      .from(balances)
      .where(and(eq(balances.userId, req.userId!), eq(balances.asset, receiveAsset)))
      .limit(1);
    const currentReceive = parseFloat(receiveBalance?.amount ?? '0');

    await db
      .insert(balances)
      .values({ userId: req.userId!, asset: receiveAsset, amount: (currentReceive + receiveAmount).toFixed(18) })
      .onConflictDoUpdate({
        target: [balances.userId, balances.asset],
        set: { amount: (currentReceive + receiveAmount).toFixed(18), updatedAt: new Date() },
      });

    // Record as filled order
    const [order] = await db
      .insert(orders)
      .values({
        userId: req.userId!,
        pair,
        side,
        orderType: 'market',
        price: fillPrice.toString(),
        amount: amountNum.toString(),
        filled: amountNum.toString(),
        status: 'filled',
      })
      .returning();

    // Record transaction
    await db.insert(transactions).values({
      userId: req.userId!,
      type: 'swap',
      fromAsset: spendAsset,
      toAsset: receiveAsset,
      fromAmount: spendAmount.toString(),
      toAmount: receiveAmount.toString(),
      fee: '0',
      feeAsset: quoteAsset,
      status: 'completed',
      metadata: { orderId: order.id, pair, side, fillPrice },
    });

    const [user] = await db.select({ email: users.email }).from(users).where(eq(users.id, req.userId!)).limit(1);
    await logAudit({
      userId: req.userId,
      userName: user.email,
      action: 'Market Order Filled',
      detail: `${side.toUpperCase()} ${amountNum} ${baseAsset} on ${pair} @ ${fillPrice}`,
      type: 'wallet',
      severity: 'info',
    });

    res.status(201).json({ success: true, data: order });
    return;
  }

  // Limit order — queue it
  const [order] = await db
    .insert(orders)
    .values({
      userId: req.userId!,
      pair, side,
      orderType: 'limit',
      price: parseFloat(price).toString(),
      amount: amountNum.toString(),
      filled: '0',
      status: 'open',
    })
    .returning();

  res.status(201).json({ success: true, data: order });
});

// ── DELETE /me/orders/:id ─────────────────────────────────────────────────────

router.delete('/:id', async (req: AuthRequest, res: Response) => {
  const [order] = await db
    .select()
    .from(orders)
    .where(and(eq(orders.id, req.params.id), eq(orders.userId, req.userId!)))
    .limit(1);

  if (!order) { res.status(404).json({ success: false, error: 'Order not found' }); return; }
  if (order.status !== 'open' && order.status !== 'partial') {
    res.status(400).json({ success: false, error: `Cannot cancel a ${order.status} order` });
    return;
  }

  await db
    .update(orders)
    .set({ status: 'cancelled', updatedAt: new Date() })
    .where(eq(orders.id, order.id));

  res.json({ success: true });
});

export default router;
