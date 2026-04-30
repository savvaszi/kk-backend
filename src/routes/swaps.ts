/**
 * Swap routes (auth required):
 *   GET  /me/swaps/quote   – get a swap quote (?from=ETH&to=USDT&amount=1)
 *   POST /me/swaps         – execute a swap
 *   GET  /me/swaps         – swap history (from transaction records)
 */

import { Router } from 'express';
import type { Response } from 'express';
import { db } from '../db/index.js';
import { balances, transactions, users } from '../db/schema.js';
import { eq, and, desc } from 'drizzle-orm';
import { requireAuth, type AuthRequest } from '../middleware/auth.js';
import { logAudit } from '../lib/audit.js';
import { ASSETS } from './market.js';

const router = Router();
router.use(requireAuth);

// Fetch spot prices for a set of symbols → { SYMBOL: usdPrice }
async function fetchSpotPrices(symbols: string[]): Promise<Record<string, number>> {
  const ids = symbols.map(s => ASSETS[s]).filter(Boolean).join(',');
  if (!ids) return {};
  try {
    const r = await fetch(
      `https://api.coingecko.com/api/v3/simple/price?ids=${ids}&vs_currencies=usd`,
      { headers: { Accept: 'application/json' }, signal: AbortSignal.timeout(8_000) }
    );
    if (!r.ok) throw new Error(`CG ${r.status}`);
    const raw = (await r.json()) as Record<string, { usd: number }>;
    const result: Record<string, number> = {};
    for (const sym of symbols) {
      const cgId = ASSETS[sym];
      if (cgId && raw[cgId]) result[sym] = raw[cgId].usd;
    }
    return result;
  } catch {
    return {};
  }
}

// ── GET /me/swaps/quote ───────────────────────────────────────────────────────

router.get('/quote', async (req: AuthRequest, res: Response) => {
  const from = (req.query.from as string)?.toUpperCase();
  const to   = (req.query.to   as string)?.toUpperCase();
  const amountStr = req.query.amount as string;

  if (!from || !to || !amountStr) {
    res.status(400).json({ success: false, error: 'from, to and amount query params are required' });
    return;
  }
  if (!ASSETS[from]) {
    res.status(400).json({ success: false, error: `Unsupported asset: ${from}` });
    return;
  }
  if (!ASSETS[to]) {
    res.status(400).json({ success: false, error: `Unsupported asset: ${to}` });
    return;
  }

  const amount = parseFloat(amountStr);
  if (isNaN(amount) || amount <= 0) {
    res.status(400).json({ success: false, error: 'amount must be a positive number' });
    return;
  }

  // Fetch prices for both assets
  const prices = await fetchSpotPrices([from, to]);
  const fromPrice = prices[from] ?? 0;
  const toPrice   = prices[to]   ?? 0;

  if (!fromPrice || !toPrice) {
    res.status(503).json({ success: false, error: 'Price data temporarily unavailable' });
    return;
  }

  // rate = how many `to` tokens you get per 1 `from` token
  const rate = fromPrice / toPrice;
  const toAmount = amount * rate;
  const feePercent = 0.001; // 0.1% platform fee
  const feeInFrom = amount * feePercent;
  const toAmountAfterFee = (amount - feeInFrom) * rate;

  res.json({
    success: true,
    data: {
      from,
      to,
      fromAmount: amount,
      toAmount: parseFloat(toAmountAfterFee.toFixed(18)),
      toAmountBeforeFee: parseFloat(toAmount.toFixed(18)),
      rate: parseFloat(rate.toFixed(18)),
      fee: parseFloat(feeInFrom.toFixed(18)),
      feeAsset: from,
      feePercent: feePercent * 100,
      fromPriceUsd: fromPrice,
      toPriceUsd: toPrice,
      expiresIn: 30, // seconds — indicative only
    },
  });
});

// ── POST /me/swaps ────────────────────────────────────────────────────────────

router.post('/', async (req: AuthRequest, res: Response) => {
  const { from, to, fromAmount } = req.body;

  if (!from || !to || !fromAmount) {
    res.status(400).json({ success: false, error: 'from, to and fromAmount are required' });
    return;
  }

  const fromSym = (from as string).toUpperCase();
  const toSym   = (to   as string).toUpperCase();

  if (!ASSETS[fromSym]) {
    res.status(400).json({ success: false, error: `Unsupported asset: ${fromSym}` });
    return;
  }
  if (!ASSETS[toSym]) {
    res.status(400).json({ success: false, error: `Unsupported asset: ${toSym}` });
    return;
  }
  if (fromSym === toSym) {
    res.status(400).json({ success: false, error: 'from and to must be different assets' });
    return;
  }

  const fromAmountNum = parseFloat(fromAmount);
  if (isNaN(fromAmountNum) || fromAmountNum <= 0) {
    res.status(400).json({ success: false, error: 'fromAmount must be a positive number' });
    return;
  }

  // Fetch live prices
  const prices = await fetchSpotPrices([fromSym, toSym]);
  const fromPrice = prices[fromSym] ?? 0;
  const toPrice   = prices[toSym]   ?? 0;

  if (!fromPrice || !toPrice) {
    res.status(503).json({ success: false, error: 'Price data temporarily unavailable — swap cannot be executed' });
    return;
  }

  const feePercent = 0.001;
  const feeInFrom = fromAmountNum * feePercent;
  const netFrom = fromAmountNum - feeInFrom;
  const toAmountNum = netFrom * (fromPrice / toPrice);

  // Check balance
  const [fromBal] = await db
    .select()
    .from(balances)
    .where(and(eq(balances.userId, req.userId!), eq(balances.asset, fromSym)))
    .limit(1);

  const available = parseFloat(fromBal?.amount ?? '0');
  if (available < fromAmountNum) {
    res.status(400).json({
      success: false,
      error: `Insufficient ${fromSym} balance. Available: ${available.toFixed(8)}, Required: ${fromAmountNum.toFixed(8)}`,
    });
    return;
  }

  // Deduct from asset
  await db
    .insert(balances)
    .values({ userId: req.userId!, asset: fromSym, amount: (available - fromAmountNum).toFixed(18) })
    .onConflictDoUpdate({
      target: [balances.userId, balances.asset],
      set: { amount: (available - fromAmountNum).toFixed(18), updatedAt: new Date() },
    });

  // Credit to asset
  const [toBal] = await db
    .select()
    .from(balances)
    .where(and(eq(balances.userId, req.userId!), eq(balances.asset, toSym)))
    .limit(1);
  const currentTo = parseFloat(toBal?.amount ?? '0');

  await db
    .insert(balances)
    .values({ userId: req.userId!, asset: toSym, amount: (currentTo + toAmountNum).toFixed(18) })
    .onConflictDoUpdate({
      target: [balances.userId, balances.asset],
      set: { amount: (currentTo + toAmountNum).toFixed(18), updatedAt: new Date() },
    });

  // Record transaction
  const [tx] = await db
    .insert(transactions)
    .values({
      userId: req.userId!,
      type: 'swap',
      fromAsset: fromSym,
      toAsset: toSym,
      fromAmount: fromAmountNum.toString(),
      toAmount: toAmountNum.toFixed(18),
      fee: feeInFrom.toFixed(18),
      feeAsset: fromSym,
      status: 'completed',
      metadata: { fromPrice, toPrice, rate: fromPrice / toPrice, feePercent: feePercent * 100 },
    })
    .returning();

  const [user] = await db.select({ email: users.email }).from(users).where(eq(users.id, req.userId!)).limit(1);
  await logAudit({
    userId: req.userId,
    userName: user.email,
    action: 'Swap Executed',
    detail: `${fromAmountNum} ${fromSym} → ${toAmountNum.toFixed(8)} ${toSym} (fee: ${feeInFrom.toFixed(8)} ${fromSym})`,
    type: 'wallet',
    severity: 'info',
  });

  res.status(201).json({ success: true, data: tx });
});

// ── GET /me/swaps ─────────────────────────────────────────────────────────────

router.get('/', async (req: AuthRequest, res: Response) => {
  const limit  = Math.min(parseInt((req.query.limit  as string) ?? '25', 10), 100);
  const offset = parseInt((req.query.offset as string) ?? '0', 10);

  const rows = await db
    .select()
    .from(transactions)
    .where(and(eq(transactions.userId, req.userId!), eq(transactions.type, 'swap')))
    .orderBy(desc(transactions.createdAt))
    .limit(limit)
    .offset(offset);

  res.json({ success: true, data: rows });
});

export default router;
