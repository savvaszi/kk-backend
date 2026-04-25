import { Router } from 'express';
import type { Response } from 'express';
import { requireAuth, type AuthRequest } from '../middleware/auth.js';
import * as fb from '../services/fireblocks.js';
import { db } from '../db/index.js';
import { users } from '../db/schema.js';
import { eq } from 'drizzle-orm';
import { logAudit } from '../lib/audit.js';

const router = Router();
router.use(requireAuth);

function fbGuard(res: Response): boolean {
  if (!fb.isConfigured()) {
    res.status(503).json({ success: false, error: 'Fireblocks credentials not configured.' });
    return false;
  }
  return true;
}

async function ensureVault(req: AuthRequest, res: Response): Promise<string | null> {
  const [user] = await db.select().from(users).where(eq(users.id, req.userId!)).limit(1);
  if (!user) { res.status(404).json({ success: false, error: 'User not found' }); return null; }

  if (user.fireblocksVaultId) return user.fireblocksVaultId;

  // Auto-create vault on first access
  const name = `${user.email.split('@')[0]}-${user.id.slice(0, 8)}`;
  const result = await fb.createVaultAccount(name, true);
  const vaultId = result.data?.id;
  if (!vaultId) { res.status(500).json({ success: false, error: 'Failed to create vault' }); return null; }

  await db.update(users).set({ fireblocksVaultId: vaultId, updatedAt: new Date() }).where(eq(users.id, user.id));
  await logAudit({ userId: user.id, userName: user.email, action: 'Fireblocks Vault Created', detail: `Auto-created vault ${vaultId}`, type: 'wallet', severity: 'info' });
  return vaultId;
}

// GET /me/fireblocks/vault
router.get('/vault', async (req: AuthRequest, res: Response) => {
  if (!fbGuard(res)) return;
  try {
    const vaultId = await ensureVault(req, res);
    if (!vaultId) return;
    const result = await fb.getVaultAccount(vaultId);
    res.json({ success: true, data: result.data });
  } catch (e: any) {
    res.status(500).json({ success: false, error: e.message });
  }
});

// POST /me/fireblocks/vault/assets/:assetId — activate asset
router.post('/vault/assets/:assetId', async (req: AuthRequest, res: Response) => {
  if (!fbGuard(res)) return;
  try {
    const vaultId = await ensureVault(req, res);
    if (!vaultId) return;
    const result = await fb.activateVaultAsset(vaultId, req.params.assetId);
    await logAudit({ userId: req.userId, action: 'Asset Activated', detail: `Asset ${req.params.assetId} activated in vault`, type: 'wallet', severity: 'info' });
    res.json({ success: true, data: result.data });
  } catch (e: any) {
    res.status(500).json({ success: false, error: e.message });
  }
});

// GET /me/fireblocks/vault/assets/:assetId
router.get('/vault/assets/:assetId', async (req: AuthRequest, res: Response) => {
  if (!fbGuard(res)) return;
  try {
    const vaultId = await ensureVault(req, res);
    if (!vaultId) return;
    const result = await fb.getVaultAsset(vaultId, req.params.assetId);
    res.json({ success: true, data: result.data });
  } catch (e: any) {
    res.status(500).json({ success: false, error: e.message });
  }
});

// GET /me/fireblocks/vault/assets/:assetId/addresses
router.get('/vault/assets/:assetId/addresses', async (req: AuthRequest, res: Response) => {
  if (!fbGuard(res)) return;
  try {
    const vaultId = await ensureVault(req, res);
    if (!vaultId) return;
    const result = await fb.getVaultAddresses(vaultId, req.params.assetId);
    res.json({ success: true, data: result.data });
  } catch (e: any) {
    res.status(500).json({ success: false, error: e.message });
  }
});

// POST /me/fireblocks/vault/assets/:assetId/addresses — create deposit address
router.post('/vault/assets/:assetId/addresses', async (req: AuthRequest, res: Response) => {
  if (!fbGuard(res)) return;
  try {
    const vaultId = await ensureVault(req, res);
    if (!vaultId) return;
    const result = await fb.createDepositAddress(vaultId, req.params.assetId, req.body.description);
    res.json({ success: true, data: result.data });
  } catch (e: any) {
    res.status(500).json({ success: false, error: e.message });
  }
});

// PUT /me/fireblocks/vault/assets/:assetId/refresh — refresh balance
router.put('/vault/assets/:assetId/refresh', async (req: AuthRequest, res: Response) => {
  if (!fbGuard(res)) return;
  try {
    const vaultId = await ensureVault(req, res);
    if (!vaultId) return;
    const result = await fb.refreshVaultBalance(vaultId, req.params.assetId);
    res.json({ success: true, data: result.data });
  } catch (e: any) {
    res.status(500).json({ success: false, error: e.message });
  }
});

// ─── Transactions ─────────────────────────────────────────────────────────────

// GET /me/fireblocks/transactions
router.get('/transactions', async (req: AuthRequest, res: Response) => {
  if (!fbGuard(res)) return;
  try {
    const [user] = await db.select({ fireblocksVaultId: users.fireblocksVaultId }).from(users).where(eq(users.id, req.userId!)).limit(1);
    if (!user?.fireblocksVaultId) { res.json({ success: true, data: [] }); return; }
    const { limit, assetId, after } = req.query as Record<string, string>;
    const result = await fb.listTransactions({
      vaultAccountId: user.fireblocksVaultId,
      limit: limit ? parseInt(limit) : 25,
      after,
    });
    res.json({ success: true, data: result.data });
  } catch (e: any) {
    res.status(500).json({ success: false, error: e.message });
  }
});

// GET /me/fireblocks/transactions/:txId
router.get('/transactions/:txId', async (req: AuthRequest, res: Response) => {
  if (!fbGuard(res)) return;
  try {
    const result = await fb.getTransaction(req.params.txId);
    res.json({ success: true, data: result.data });
  } catch (e: any) {
    res.status(500).json({ success: false, error: e.message });
  }
});

// POST /me/fireblocks/transactions — send
router.post('/transactions', async (req: AuthRequest, res: Response) => {
  if (!fbGuard(res)) return;
  try {
    const vaultId = await ensureVault(req, res);
    if (!vaultId) return;

    const { assetId, amount, destinationAddress, note } = req.body;
    if (!assetId || !amount || !destinationAddress) {
      res.status(400).json({ success: false, error: 'assetId, amount, and destinationAddress are required' });
      return;
    }

    const result = await fb.createTransaction({
      assetId,
      source: { type: 'VAULT_ACCOUNT', id: vaultId },
      destination: { type: 'ONE_TIME_ADDRESS', oneTimeAddress: { address: destinationAddress } },
      amount: String(amount),
      note: note ?? '',
    });

    await logAudit({
      userId: req.userId,
      action: 'Transaction Submitted',
      detail: `${amount} ${assetId} → ${destinationAddress}`,
      type: 'wallet',
      severity: 'info',
    });

    res.status(201).json({ success: true, data: result.data });
  } catch (e: any) {
    res.status(500).json({ success: false, error: e.message });
  }
});

// ─── Staking ─────────────────────────────────────────────────────────────────

// GET /me/fireblocks/staking/positions
router.get('/staking/positions', async (_req: AuthRequest, res: Response) => {
  if (!fbGuard(res)) return;
  try {
    const result = await fb.getStakingPositions();
    res.json({ success: true, data: result.data });
  } catch (e: any) {
    res.status(500).json({ success: false, error: e.message });
  }
});

export default router;
