import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import { initDb } from './db/index.js';
import authRouter from './routes/auth.js';
import meRouter from './routes/me.js';
import adminRouter from './routes/admin.js';

const app = express();
const PORT = parseInt(process.env.PORT ?? '4000', 10);

const origins = process.env.ALLOWED_ORIGINS
  ? process.env.ALLOWED_ORIGINS.split(',').map(o => o.trim())
  : true;

app.use(helmet());
app.use(cors({ origin: origins, credentials: true }));
app.use(express.json());

app.get('/', (_, res) => res.json({ name: 'KryptoKnight API', version: '1.0.0', status: 'ok' }));
app.get('/health', (_, res) => res.json({ status: 'ok', timestamp: new Date().toISOString() }));

app.use('/auth', authRouter);
app.use('/me', meRouter);
app.use('/admin', adminRouter);

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
