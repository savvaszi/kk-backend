/**
 * Public market data routes (no auth required):
 *   GET /public/market/prices           – current prices for all supported assets
 *   GET /public/market/ticker/:symbol   – full 24h ticker for one asset
 *   GET /public/market/candles/:symbol  – OHLC candles (interval: 1H default)
 *
 * Data sourced from CoinGecko free API, cached in-memory with 60-second TTL.
 */

import { Router, Request, Response } from 'express';

const router = Router();

// ── Asset catalogue ───────────────────────────────────────────────────────────

export const ASSETS: Record<string, string> = {
  BTC:   'bitcoin',
  ETH:   'ethereum',
  SOL:   'solana',
  BNB:   'binancecoin',
  ADA:   'cardano',
  MATIC: 'matic-network',
  AVAX:  'avalanche-2',
  LINK:  'chainlink',
  ATOM:  'cosmos',
  ARB:   'arbitrum',
  AAVE:  'aave',
  USDT:  'tether',
  USDC:  'usd-coin',
};

export const SYMBOL_BY_ID: Record<string, string> = Object.fromEntries(
  Object.entries(ASSETS).map(([sym, id]) => [id, sym])
);

export const ALL_IDS = Object.values(ASSETS).join(',');

// ── Simple in-memory cache ────────────────────────────────────────────────────

interface CacheEntry { data: unknown; expiresAt: number }
const cache = new Map<string, CacheEntry>();
const TTL_MS = 60_000; // 60 seconds

function getCached(key: string) {
  const entry = cache.get(key);
  if (entry && Date.now() < entry.expiresAt) return entry.data;
  return null;
}

function setCache(key: string, data: unknown) {
  cache.set(key, { data, expiresAt: Date.now() + TTL_MS });
}

// ── CoinGecko fetch helper ────────────────────────────────────────────────────

async function cgFetch(path: string): Promise<unknown> {
  const res = await fetch(`https://api.coingecko.com/api/v3${path}`, {
    headers: { 'Accept': 'application/json' },
    signal: AbortSignal.timeout(10_000),
  });
  if (!res.ok) throw new Error(`CoinGecko ${res.status}: ${path}`);
  return res.json();
}

// ── GET /public/market/prices ─────────────────────────────────────────────────
// Returns price, 24h change, 24h volume, market cap for every supported asset.

router.get('/prices', async (_req: Request, res: Response) => {
  const cacheKey = 'market:prices';
  const cached = getCached(cacheKey);
  if (cached) { res.json({ success: true, data: cached, cached: true }); return; }

  try {
    const raw = await cgFetch(
      `/coins/markets?vs_currency=usd&ids=${ALL_IDS}&order=market_cap_desc&per_page=50&sparkline=false&price_change_percentage=24h`
    ) as any[];

    const data = raw.map((coin: any) => ({
      symbol:        SYMBOL_BY_ID[coin.id] ?? coin.symbol?.toUpperCase(),
      id:            coin.id,
      name:          coin.name,
      price:         coin.current_price,
      change24h:     coin.price_change_percentage_24h,
      high24h:       coin.high_24h,
      low24h:        coin.low_24h,
      volume24h:     coin.total_volume,
      marketCap:     coin.market_cap,
      image:         coin.image,
    }));

    setCache(cacheKey, data);
    res.json({ success: true, data });
  } catch (err: any) {
    console.error('[market/prices]', err.message);
    const stale = cache.get(cacheKey);
    if (stale) res.json({ success: true, data: stale.data, cached: true, stale: true });
    else res.status(503).json({ success: false, error: 'Market data unavailable' });
  }
});

// ── GET /public/market/ticker/:symbol ─────────────────────────────────────────

router.get('/ticker/:symbol', async (req: Request, res: Response) => {
  const symbol = req.params.symbol.toUpperCase();
  const cgId = ASSETS[symbol];
  if (!cgId) { res.status(404).json({ success: false, error: `Unsupported asset: ${symbol}` }); return; }

  const cacheKey = `market:ticker:${symbol}`;
  const cached = getCached(cacheKey);
  if (cached) { res.json({ success: true, data: cached, cached: true }); return; }

  try {
    const raw = await cgFetch(
      `/coins/${cgId}?localization=false&tickers=false&market_data=true&community_data=false&developer_data=false`
    ) as any;

    const data = {
      symbol,
      id:          cgId,
      name:        raw.name,
      price:       raw.market_data.current_price.usd,
      change24h:   raw.market_data.price_change_percentage_24h,
      change7d:    raw.market_data.price_change_percentage_7d,
      change30d:   raw.market_data.price_change_percentage_30d,
      high24h:     raw.market_data.high_24h.usd,
      low24h:      raw.market_data.low_24h.usd,
      volume24h:   raw.market_data.total_volume.usd,
      marketCap:   raw.market_data.market_cap.usd,
      ath:         raw.market_data.ath.usd,
      athDate:     raw.market_data.ath_date.usd,
      image:       raw.image?.large,
    };

    setCache(cacheKey, data);
    res.json({ success: true, data });
  } catch (err: any) {
    console.error(`[market/ticker/${symbol}]`, err.message);
    res.status(503).json({ success: false, error: 'Market data unavailable' });
  }
});

// ── GET /public/market/candles/:symbol ───────────────────────────────────────
// Returns OHLC candles. Query param: interval = 1H (default) | 4H | 1D
// CoinGecko free OHLC: days=1→hourly, days=7→4-hourly, days=max→daily

router.get('/candles/:symbol', async (req: Request, res: Response) => {
  const symbol = req.params.symbol.toUpperCase();
  const cgId = ASSETS[symbol];
  if (!cgId) { res.status(404).json({ success: false, error: `Unsupported asset: ${symbol}` }); return; }

  const interval = (req.query.interval as string) ?? '1H';
  const days = interval === '1D' ? 7 : interval === '4H' ? 7 : 1;

  const cacheKey = `market:candles:${symbol}:${days}`;
  const cached = getCached(cacheKey);
  if (cached) { res.json({ success: true, data: cached, cached: true }); return; }

  try {
    const raw = await cgFetch(`/coins/${cgId}/ohlc?vs_currency=usd&days=${days}`) as number[][];

    // CoinGecko returns [timestamp, open, high, low, close]
    const data = raw.map(([ts, o, h, l, c]) => ({
      time: ts,
      open: o, high: h, low: l, close: c,
    }));

    setCache(cacheKey, data);
    res.json({ success: true, data });
  } catch (err: any) {
    console.error(`[market/candles/${symbol}]`, err.message);
    res.status(503).json({ success: false, error: 'Market data unavailable' });
  }
});

// ── GET /public/market/chart/:symbol ──────────────────────────────────────────
// Returns price chart data for portfolio history calculations.
// Query: range = 1D | 7D | 1M | 6M | 1Y | max

router.get('/chart/:symbol', async (req: Request, res: Response) => {
  const symbol = req.params.symbol.toUpperCase();
  const cgId = ASSETS[symbol];
  if (!cgId) { res.status(404).json({ success: false, error: `Unsupported asset: ${symbol}` }); return; }

  const rangeMap: Record<string, string> = {
    '1D': '1', '7D': '7', '1M': '30', '6M': '180', '1Y': '365', 'max': 'max',
  };
  const range = (req.query.range as string) ?? '1M';
  const days = rangeMap[range] ?? '30';

  const cacheKey = `market:chart:${symbol}:${days}`;
  const cached = getCached(cacheKey);
  if (cached) { res.json({ success: true, data: cached, cached: true }); return; }

  try {
    const raw = await cgFetch(`/coins/${cgId}/market_chart?vs_currency=usd&days=${days}`) as any;
    const data = (raw.prices as [number, number][]).map(([ts, price]) => ({ time: ts, price }));
    setCache(cacheKey, data);
    res.json({ success: true, data });
  } catch (err: any) {
    console.error(`[market/chart/${symbol}]`, err.message);
    res.status(503).json({ success: false, error: 'Market data unavailable' });
  }
});

export default router;
