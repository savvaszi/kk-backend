import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import path from 'path';
import { fileURLToPath } from 'url';
import { initDb } from './db/index.js';
import authRouter from './routes/auth.js';
import meRouter from './routes/me.js';
import adminRouter from './routes/admin.js';
import fireblocksAdminRouter from './routes/fireblocks-admin.js';
import fireblocksUserRouter from './routes/fireblocks-me.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const app = express();
const PORT = parseInt(process.env.PORT ?? '4000', 10);

const origins = process.env.ALLOWED_ORIGINS
  ? process.env.ALLOWED_ORIGINS.split(',').map(o => o.trim())
  : true;

app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({ origin: origins, credentials: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, '..', 'public')));

app.get('/', (_, res) => res.redirect('/login.html'));
app.get('/health', (_, res) => res.json({ status: 'ok', timestamp: new Date().toISOString() }));

app.use('/auth', authRouter);
app.use('/me', meRouter);
app.use('/me/fireblocks', fireblocksUserRouter);
app.use('/admin', adminRouter);
app.use('/admin/fireblocks', fireblocksAdminRouter);

// Fireblocks webhook receiver
app.post('/webhooks/fireblocks', async (req, res) => {
  const { logAudit } = await import('./lib/audit.js');
  const event = req.body;
  const type = event?.type ?? 'UNKNOWN';
  const txId = event?.data?.id ?? event?.data?.txId ?? '';
  await logAudit({
    action: `Fireblocks Webhook: ${type}`,
    detail: txId ? `Transaction ${txId}` : JSON.stringify(event).slice(0, 200),
    type: 'webhook',
    severity: 'info',
  }).catch(() => {});
  res.json({ success: true });
});

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
