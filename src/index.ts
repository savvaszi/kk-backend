import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import path from 'path';
import { fileURLToPath } from 'url';
import { initDb } from './db/index.js';
import authRouter from './routes/auth.js';
import meRouter from './routes/me.js';
import adminRouter from './routes/admin.js';
import fireblocksAdminRouter from './routes/fireblocks-admin.js';
import fireblocksUserRouter from './routes/fireblocks-me.js';
import publicRouter from './routes/public.js';
import fireblocksWebhookRouter from './routes/webhook-fireblocks.js';
import sumsubWebhookRouter from './routes/webhook-sumsub.js';
import kycRouter from './routes/kyc.js';
import marketRouter from './routes/market.js';
import portfolioRouter from './routes/portfolio.js';
import transactionsRouter from './routes/transactions.js';
import watchlistRouter from './routes/watchlist.js';
import ordersRouter from './routes/orders.js';
import swapsRouter from './routes/swaps.js';
import transfersRouter from './routes/transfers.js';
import { sendSecurityAlert } from './lib/security-alert.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const app = express();
const PORT = parseInt(process.env.PORT ?? '4000', 10);

const ALLOWED_ORIGINS_DEFAULT = [
  'https://krypto-knight.com',
  'https://k2.krypto-knight.com',
  'https://k1.krypto-knight.com',
];
const origins = process.env.ALLOWED_ORIGINS
  ? process.env.ALLOWED_ORIGINS.split(',').map(o => o.trim())
  : ALLOWED_ORIGINS_DEFAULT;

app.use(helmet({
  contentSecurityPolicy: false,
  hsts: {
    maxAge: 31536000,       // 365 days (KK-03 fix)
    includeSubDomains: true,
    preload: true,
  },
}));
app.use(cors({ origin: origins, credentials: true })); // KK-05: explicit allowlist

// ── Webhooks (raw body — MUST be before express.json()) ──────────────────────
// Fireblocks: RSA-SHA512 signature over raw body (fireblocks-signature header)
app.use('/webhooks/fireblocks', fireblocksWebhookRouter);
// Sumsub: HMAC-SHA256 signature over raw body (x-payload-digest header)
app.use('/webhooks/sumsub', sumsubWebhookRouter);

app.use(express.json());

// ── Rate Limiting ─────────────────────────────────────────────────────────────
// Strict limit for auth endpoints (login, register, forgot-password, reset-password)
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, error: 'Too many requests, please try again later.' },
  handler: (req, res, next, options) => {
    sendSecurityAlert({
      code: 'RATE_LIMIT_AUTH',
      level: 'critical',
      ip: (req.headers['x-forwarded-for'] as string | undefined)?.split(',')[0]?.trim() ?? req.ip,
      path: req.path,
      detail: `Auth rate limit hit: ${options.max} requests / ${options.windowMs / 60000} min`,
    }).catch(() => {});
    res.status(options.statusCode).json(options.message);
  },
});

// Relaxed limit for general API usage
const apiLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 120,
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, error: 'Too many requests, please try again later.' },
  handler: (req, res, next, options) => {
    sendSecurityAlert({
      code: 'RATE_LIMIT_API',
      level: 'warning',
      ip: (req.headers['x-forwarded-for'] as string | undefined)?.split(',')[0]?.trim() ?? req.ip,
      path: req.path,
      detail: `API rate limit hit: ${options.max} requests / ${options.windowMs / 1000} sec`,
    }).catch(() => {});
    res.status(options.statusCode).json(options.message);
  },
});
app.use(express.static(path.join(__dirname, '..', 'public')));

app.get('/', (_, res) => res.redirect('/login.html'));
app.get('/health', (_, res) => res.json({ status: 'ok', timestamp: new Date().toISOString() }));

app.use('/public', publicRouter);
app.use('/public/market', marketRouter);
app.use('/auth', authLimiter, authRouter);
app.use('/me', apiLimiter, meRouter);
app.use('/me/kyc', apiLimiter, kycRouter);
app.use('/me/fireblocks', apiLimiter, fireblocksUserRouter);
app.use('/me/portfolio', apiLimiter, portfolioRouter);
app.use('/me/transactions', apiLimiter, transactionsRouter);
app.use('/me/watchlist', apiLimiter, watchlistRouter);
app.use('/me/orders', apiLimiter, ordersRouter);
app.use('/me/swaps', apiLimiter, swapsRouter);
app.use('/me/transfers', apiLimiter, transfersRouter);
app.use('/admin', adminRouter);
app.use('/admin/fireblocks', fireblocksAdminRouter);

app.use((_, res) => res.status(404).json({ success: false, error: 'Not found' }));

async function main() {
  if (!process.env.DATABASE_URL) {
    console.error('DATABASE_URL is required');
    process.exit(1);
  }
  if (!process.env.JWT_SECRET) {
    console.error('JWT_SECRET is required');
    process.exit(1);
  }

  await initDb();
  app.listen(PORT, '0.0.0.0', () => {
    console.log(`KryptoKnight API running on port ${PORT}`);
  });
}

main().catch(err => {
  console.error('Startup error:', err);
  process.exit(1);
});
