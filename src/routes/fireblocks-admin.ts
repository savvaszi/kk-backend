import { Router } from 'express';
import type { Response } from 'express';
import { requireAuth, requireAdmin, type AuthRequest } from '../middleware/auth.js';
import * as fb from '../services/fireblocks.js';
import { db } from '../db/index.js';
import { users } from '../db/schema.js';
import { eq } from 'drizzle-orm';
import { logAudit } from '../lib/audit.js';

const router = Router();
router.use(requireAuth, requireAdmin);

function fbGuard(res: Response): boolean {
  if (!fb.isConfigured()) {
    res.status(503).json({ success: false, error: 'Fireblocks credentials not configured.' });
    return false;
  }
  return true;
}

// GET /admin/fireblocks/status
router.get('/status', (_req, res) => {
  res.json({ success: true, data: { configured: fb.isConfigured() } });
});

// ─── Vault Accounts ───────────────────────────────────────────────────────────

// GET /admin/fireblocks/vaults
router.get('/vaults', async (_req: AuthRequest, res: Response) => {
  if (!fbGuard(res)) return;
  try {
    const result = await fb.listVaultAccounts();
    res.json({ success: true, data: result.data });
  } catch (e: any) {
    res.status(500).json({ success: false, error: e.message });
  }
});

// GET /admin/fireblocks/vaults/:vaultId
router.get('/vaults/:vaultId', async (req: AuthRequest, res: Response) => {
  if (!fbGuard(res)) return;
  try {
    const result = await fb.getVaultAccount(req.params.vaultId);
    res.json({ success: true, data: result.data });
  } catch (e: any) {
    res.status(500).json({ success: false, error: e.message });
  }
});

// POST /admin/fireblocks/vaults — create vault and link to user
router.post('/vaults', async (req: AuthRequest, res: Response) => {
  if (!fbGuard(res)) return;
  const { userId, name } = req.body;
  if (!userId || !name) {
    res.status(400).json({ success: false, error: 'userId and name required' });
    return;
  }
  try {
    const result = await fb.createVaultAccount(name);
    const vaultId = result.data?.id;
    if (!vaultId) throw new Error('Vault creation did not return an ID');
    await db.update(users).set({ fireblocksVaultId: vaultId, updatedAt: new Date() }).where(eq(users.id, userId));
    await logAudit({ userId, action: 'Fireblocks Vault Created', detail: `Vault ${vaultId} created and linked`, type: 'admin', severity: 'info' });
    res.status(201).json({ success: true, data: result.data });
  } catch (e: any) {
    res.status(500).json({ success: false, error: e.message });
  }
});

// POST /admin/fireblocks/vaults/:vaultId/assets/:assetId — activate asset in vault
router.post('/vaults/:vaultId/assets/:assetId', async (req: AuthRequest, res: Response) => {
  if (!fbGuard(res)) return;
  try {
    const result = await fb.activateVaultAsset(req.params.vaultId, req.params.assetId);
    res.json({ success: true, data: result.data });
  } catch (e: any) {
    res.status(500).json({ success: false, error: e.message });
  }
});

// ─── Transactions ─────────────────────────────────────────────────────────────

// GET /admin/fireblocks/transactions
router.get('/transactions', async (req: AuthRequest, res: Response) => {
  if (!fbGuard(res)) return;
  try {
    const { limit, assetId, status, after } = req.query as Record<string, string>;
    const result = await fb.listTransactions({
      limit: limit ? parseInt(limit) : 50,
      status: status as any,
      after,
    });
    res.json({ success: true, data: result.data });
  } catch (e: any) {
    res.status(500).json({ success: false, error: e.message });
  }
});

// GET /admin/fireblocks/transactions/:txId
router.get('/transactions/:txId', async (req: AuthRequest, res: Response) => {
  if (!fbGuard(res)) return;
  try {
    const result = await fb.getTransaction(req.params.txId);
    res.json({ success: true, data: result.data });
  } catch (e: any) {
    res.status(500).json({ success: false, error: e.message });
  }
});

// DELETE /admin/fireblocks/transactions/:txId — cancel
router.delete('/transactions/:txId', async (req: AuthRequest, res: Response) => {
  if (!fbGuard(res)) return;
  try {
    await fb.cancelTransaction(req.params.txId);
    res.json({ success: true });
  } catch (e: any) {
    res.status(500).json({ success: false, error: e.message });
  }
});

// ─── Assets ──────────────────────────────────────────────────────────────────

// GET /admin/fireblocks/assets
router.get('/assets', async (_req: AuthRequest, res: Response) => {
  if (!fbGuard(res)) return;
  try {
    const result = await fb.getSupportedAssets();
    res.json({ success: true, data: result.data });
  } catch (e: any) {
    res.status(500).json({ success: false, error: e.message });
  }
});

// ─── Staking ─────────────────────────────────────────────────────────────────

// GET /admin/fireblocks/staking/positions
router.get('/staking/positions', async (_req: AuthRequest, res: Response) => {
  if (!fbGuard(res)) return;
  try {
    const result = await fb.getStakingPositions();
    res.json({ success: true, data: result.data });
  } catch (e: any) {
    res.status(500).json({ success: false, error: e.message });
  }
});

// ─── Network Connections ──────────────────────────────────────────────────────

// GET /admin/fireblocks/network
router.get('/network', async (_req: AuthRequest, res: Response) => {
  if (!fbGuard(res)) return;
  try {
    const result = await fb.listNetworkConnections();
    res.json({ success: true, data: result.data });
  } catch (e: any) {
    res.status(500).json({ success: false, error: e.message });
  }
});

// ─── Webhooks ─────────────────────────────────────────────────────────────────

// POST /admin/fireblocks/webhooks/resend
router.post('/webhooks/resend', async (req: AuthRequest, res: Response) => {
  if (!fbGuard(res)) return;
  try {
    const result = await fb.resendWebhooks(req.body.txId);
    res.json({ success: true, data: result.data });
  } catch (e: any) {
    res.status(500).json({ success: false, error: e.message });
  }
});

// ─── Whitelisted Wallets ──────────────────────────────────────────────────────

// GET /admin/fireblocks/wallets/internal
router.get('/wallets/internal', async (_req: AuthRequest, res: Response) => {
  if (!fbGuard(res)) return;
  try {
    const result = await fb.listInternalWallets();
    res.json({ success: true, data: result.data });
  } catch (e: any) {
    res.status(500).json({ success: false, error: e.message });
  }
});

// GET /admin/fireblocks/wallets/external
router.get('/wallets/external', async (_req: AuthRequest, res: Response) => {
  if (!fbGuard(res)) return;
  try {
    const result = await fb.listExternalWallets();
    res.json({ success: true, data: result.data });
  } catch (e: any) {
    res.status(500).json({ success: false, error: e.message });
  }
});

export default router;
