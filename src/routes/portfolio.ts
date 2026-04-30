/**
 * Portfolio routes (auth required):
 *   GET /me/portfolio              – current balances + USD totals
 *   GET /me/portfolio/chart        – portfolio value over time (?range=1D|7D|1M|6M|1Y)
 */

import { Router } from 'express';
import type { Response } from 'express';
import { db } from '../db/index.js';
import { balances } from '../db/schema.js';
import { eq } from 'drizzle-orm';
import { requireAuth, type AuthRequest } from '../middleware/auth.js';
import { ASSETS, ALL_IDS, SYMBOL_BY_ID } from './market.js';

const router = Router();
router.use(requireAuth);

// Fetch fresh prices from CoinGecko (simple price endpoint — lightest call)
async function fetchPrices(): Promise<Record<string, number>> {
  try {
    const res = await fetch(
      `https://api.coingecko.com/api/v3/simple/price?ids=${ALL_IDS}&vs_currencies=usd`,
      { headers: { Accept: 'application/json' }, signal: AbortSignal.timeout(8_000) }
    );
    if (!res.ok) throw new Error(`CG ${res.status}`);
    const raw = (await res.json()) as Record<string, { usd: number }>;
    // Remap from cgId -> usd to SYMBOL -> usd
    return Object.fromEntries(
      Object.entries(raw).map(([cgId, v]) => [SYMBOL_BY_ID[cgId] ?? cgId, v.usd])
    );
  } catch {
    return {};
  }
}

// ── GET /me/portfolio ─────────────────────────────────────────────────────────

router.get('/', async (req: AuthRequest, res: Response) => {
  const [rows, prices] = await Promise.all([
    db.select().from(balances).where(eq(balances.userId, req.userId!)),
    fetchPrices(),
  ]);

  // Merge DB balances with all supported assets (so 0-balance assets still appear)
  const balanceMap: Record<string, string> = {};
  for (const row of rows) balanceMap[row.asset] = row.amount;

  const assets = Object.keys(ASSETS).map(symbol => {
    const amount = parseFloat(balanceMap[symbol] ?? '0');
    const price = prices[symbol] ?? 0;
    const usdValue = amount * price;
    return { symbol, amount: amount.toString(), price, usdValue };
  });

  const totalUsd = assets.reduce((sum, a) => sum + a.usdValue, 0);

  res.json({
    success: true,
    data: {
      totalUsd,
      assets,
      updatedAt: new Date().toISOString(),
    },
  });
});

// ── GET /me/portfolio/chart ───────────────────────────────────────────────────
// Builds a synthetic portfolio value chart by multiplying historical prices
// by the user's current holdings. This is approximate but gives the right shape.

router.get('/chart', async (req: AuthRequest, res: Response) => {
  const range = (req.query.range as string) ?? '1M';
  const rangeMap: Record<string, string> = {
    '1D': '1', '7D': '7', '1M': '30', '6M': '180', '1Y': '365', 'All': 'max',
  };
  const days = rangeMap[range] ?? '30';

  const rows = await db.select().from(balances).where(eq(balances.userId, req.userId!));
  const balanceMap: Record<string, number> = {};
  for (const row of rows) balanceMap[row.asset] = parseFloat(row.amount);

  // Assets the user actually holds
  const heldAssets = Object.entries(balanceMap).filter(([, amt]) => amt > 0);

  if (heldAssets.length === 0) {
    // Return empty chart with zero values
    const points = Array.from({ length: 30 }, (_, i) => ({
      time: Date.now() - (29 - i) * 86_400_000,
      value: 0,
    }));
    res.json({ success: true, data: { range, points } });
    return;
  }

  try {
    // Fetch historical price charts for all held assets in parallel
    const chartPromises = heldAssets.map(([symbol]) => {
      const cgId = ASSETS[symbol];
      if (!cgId) return Promise.resolve([]);
      return fetch(
        `https://api.coingecko.com/api/v3/coins/${cgId}/market_chart?vs_currency=usd&days=${days}`,
        { headers: { Accept: 'application/json' }, signal: AbortSignal.timeout(10_000) }
      )
        .then(r => r.json())
        .then((d: any) => (d.prices as [number, number][]).map(([ts, price]) => ({ ts, price, symbol })))
        .catch(() => []);
    });

    const results = await Promise.all(chartPromises);

    // Align timestamps: use the first asset as the time backbone
    const backbone = results[0];
    if (!backbone || backbone.length === 0) throw new Error('no chart data');

    const points = backbone.map(({ ts }, idx) => {
      let value = 0;
      for (let i = 0; i < heldAssets.length; i++) {
        const [symbol, amount] = heldAssets[i];
        const pricePoint = results[i]?.[idx];
        const price = pricePoint ? pricePoint.price : 0;
        value += amount * price;
      }
      return { time: ts, value: parseFloat(value.toFixed(2)) };
    });

    res.json({ success: true, data: { range, points } });
  } catch (err: any) {
    console.error('[portfolio/chart]', err.message);
    res.status(503).json({ success: false, error: 'Chart data temporarily unavailable' });
  }
});

export default router;
