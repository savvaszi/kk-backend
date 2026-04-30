/**
 * Transaction history routes (auth required):
 *   GET  /me/transactions           – paginated list (?type=swap|send|receive|deposit|withdrawal&limit=25&offset=0)
 *   GET  /me/transactions/:id       – single transaction
 */

import { Router } from 'express';
import type { Response } from 'express';
import { db } from '../db/index.js';
import { transactions } from '../db/schema.js';
import { eq, and, desc } from 'drizzle-orm';
import { requireAuth, type AuthRequest } from '../middleware/auth.js';

const router = Router();
router.use(requireAuth);

// ── GET /me/transactions ──────────────────────────────────────────────────────

router.get('/', async (req: AuthRequest, res: Response) => {
  const limit = Math.min(parseInt((req.query.limit as string) ?? '25', 10), 100);
  const offset = parseInt((req.query.offset as string) ?? '0', 10);
  const type = req.query.type as string | undefined;

  const conditions = [eq(transactions.userId, req.userId!)];
  if (type && ['swap', 'send', 'receive', 'deposit', 'withdrawal'].includes(type)) {
    conditions.push(eq(transactions.type, type));
  }

  const rows = await db
    .select()
    .from(transactions)
    .where(and(...conditions))
    .orderBy(desc(transactions.createdAt))
    .limit(limit)
    .offset(offset);

  res.json({ success: true, data: rows });
});

// ── GET /me/transactions/:id ──────────────────────────────────────────────────

router.get('/:id', async (req: AuthRequest, res: Response) => {
  const [tx] = await db
    .select()
    .from(transactions)
    .where(and(eq(transactions.id, req.params.id), eq(transactions.userId, req.userId!)))
    .limit(1);

  if (!tx) { res.status(404).json({ success: false, error: 'Transaction not found' }); return; }
  res.json({ success: true, data: tx });
});

export default router;
