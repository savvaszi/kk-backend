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

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const app = express();
const PORT = parseInt(process.env.PORT ?? '4000', 10);

const origins = process.env.ALLOWED_ORIGINS
  ? process.env.ALLOWED_ORIGINS.split(',').map(o => o.trim())
  : true;

app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({ origin: origins, credentials: true }));

// ── Fireblocks Webhook ────────────────────────────────────────────────────────
// Must be mounted BEFORE express.json() so the route handler can read the raw
// body bytes needed for RSA-SHA512 signature verification.
app.use('/webhooks/fireblocks', fireblocksWebhookRouter);

app.use(express.json());

// ── Rate Limiting ─────────────────────────────────────────────────────────────
// Strict limit for auth endpoints (login, register, forgot-password, reset-password)
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, error: 'Too many requests, please try again later.' },
});

// Relaxed limit for general API usage
const apiLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 120,
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, error: 'Too many requests, please try again later.' },
});
app.use(express.static(path.join(__dirname, '..', 'public')));

app.get('/', (_, res) => res.redirect('/login.html'));
app.get('/health', (_, res) => res.json({ status: 'ok', timestamp: new Date().toISOString() }));

app.use('/public', publicRouter);
app.use('/auth', authLimiter, authRouter);
app.use('/me', apiLimiter, meRouter);
app.use('/me/fireblocks', apiLimiter, fireblocksUserRouter);
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
