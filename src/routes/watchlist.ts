/**
 * Watchlist routes (auth required):
 *   GET    /me/watchlist           – list all watched symbols
 *   PUT    /me/watchlist/:symbol   – add symbol to watchlist
 *   DELETE /me/watchlist/:symbol   – remove symbol from watchlist
 */

import { Router } from 'express';
import type { Response } from 'express';
import { db } from '../db/index.js';
import { watchlist } from '../db/schema.js';
import { eq, and } from 'drizzle-orm';
import { requireAuth, type AuthRequest } from '../middleware/auth.js';
import { ASSETS } from './market.js';

const router = Router();
router.use(requireAuth);

// ── GET /me/watchlist ─────────────────────────────────────────────────────────

router.get('/', async (req: AuthRequest, res: Response) => {
  const rows = await db
    .select()
    .from(watchlist)
    .where(eq(watchlist.userId, req.userId!));

  res.json({ success: true, data: rows.map(r => r.symbol) });
});

// ── PUT /me/watchlist/:symbol ─────────────────────────────────────────────────

router.put('/:symbol', async (req: AuthRequest, res: Response) => {
  const symbol = req.params.symbol.toUpperCase();
  if (!ASSETS[symbol]) {
    res.status(400).json({ success: false, error: `Unsupported asset: ${symbol}` });
    return;
  }

  await db
    .insert(watchlist)
    .values({ userId: req.userId!, symbol })
    .onConflictDoNothing();

  res.json({ success: true, symbol });
});

// ── DELETE /me/watchlist/:symbol ──────────────────────────────────────────────

router.delete('/:symbol', async (req: AuthRequest, res: Response) => {
  const symbol = req.params.symbol.toUpperCase();
  await db
    .delete(watchlist)
    .where(and(eq(watchlist.userId, req.userId!), eq(watchlist.symbol, symbol)));

  res.json({ success: true });
});

export default router;
