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

function guard(res: Response): boolean {
  if (!fb.isConfigured()) {
    res.status(503).json({ success: false, error: 'Fireblocks not configured.' });
    return false;
  }
  return true;
}

async function wrap(res: Response, fn: () => Promise<any>) {
  try {
    const r = await fn();
    res.json({ success: true, data: r?.data ?? r ?? null });
  } catch (e: any) {
    res.status(500).json({ success: false, error: e?.message ?? 'Fireblocks error' });
  }
}

async function getUserVaultId(req: AuthRequest): Promise<string | null> {
  const [user] = await db.select({ fireblocksVaultId: users.fireblocksVaultId }).from(users).where(eq(users.id, req.userId!)).limit(1);
  return user?.fireblocksVaultId ?? null;
}

async function ensureVault(req: AuthRequest, res: Response): Promise<string | null> {
  const [user] = await db.select().from(users).where(eq(users.id, req.userId!)).limit(1);
  if (!user) { res.status(404).json({ success: false, error: 'User not found' }); return null; }

  if (user.fireblocksVaultId) return user.fireblocksVaultId;

  const name = `${(user.email ?? '').split('@')[0]}-${user.id.slice(0, 8)}`;
  const r = await fb.vaults.create(name, true);
  const vaultId = r.data?.id;
  if (!vaultId) { res.status(500).json({ success: false, error: 'Failed to create vault' }); return null; }

  await db.update(users).set({ fireblocksVaultId: vaultId, updatedAt: new Date() }).where(eq(users.id, user.id));
  await logAudit({ userId: user.id, userName: user.email, action: 'Fireblocks Vault Created', detail: `Auto-created vault ${vaultId}`, type: 'wallet', severity: 'info' });
  return vaultId;
}

// ── Vault ─────────────────────────────────────────────────────────────────────
router.get('/vault', async (req: AuthRequest, res) => {
  if (!guard(res)) return;
  try {
    const vaultId = await ensureVault(req, res);
    if (!vaultId) return;
    await wrap(res, () => fb.vaults.get(vaultId));
  } catch (e: any) { res.status(500).json({ success: false, error: e.message }); }
});

router.post('/vault/assets/:assetId', async (req: AuthRequest, res) => {
  if (!guard(res)) return;
  try {
    const vaultId = await ensureVault(req, res);
    if (!vaultId) return;
    const r = await fb.vaults.activateAsset(vaultId, req.params.assetId);
    await logAudit({ userId: req.userId, action: 'Asset Activated', detail: `${req.params.assetId} in vault ${vaultId}`, type: 'wallet', severity: 'info' });
    res.json({ success: true, data: r.data });
  } catch (e: any) { res.status(500).json({ success: false, error: e.message }); }
});

router.get('/vault/assets/:assetId', async (req: AuthRequest, res) => {
  if (!guard(res)) return;
  const vaultId = await getUserVaultId(req);
  if (!vaultId) { res.json({ success: true, data: null }); return; }
  await wrap(res, () => fb.vaults.getAsset(vaultId, req.params.assetId));
});

router.get('/vault/assets/:assetId/addresses', async (req: AuthRequest, res) => {
  if (!guard(res)) return;
  const vaultId = await getUserVaultId(req);
  if (!vaultId) { res.json({ success: true, data: [] }); return; }
  await wrap(res, () => fb.vaults.getAddresses(vaultId, req.params.assetId));
});

router.post('/vault/assets/:assetId/addresses', async (req: AuthRequest, res) => {
  if (!guard(res)) return;
  try {
    const vaultId = await ensureVault(req, res);
    if (!vaultId) return;
    await wrap(res, () => fb.vaults.createAddress(vaultId, req.params.assetId, req.body.description));
  } catch (e: any) { res.status(500).json({ success: false, error: e.message }); }
});

router.put('/vault/assets/:assetId/refresh', async (req: AuthRequest, res) => {
  if (!guard(res)) return;
  const vaultId = await getUserVaultId(req);
  if (!vaultId) { res.json({ success: true, data: null }); return; }
  await wrap(res, () => fb.vaults.refreshBalance(vaultId, req.params.assetId));
});

router.get('/vault/assets/:assetId/max-spendable', async (req: AuthRequest, res) => {
  if (!guard(res)) return;
  const vaultId = await getUserVaultId(req);
  if (!vaultId) { res.json({ success: true, data: null }); return; }
  await wrap(res, () => fb.vaults.getMaxSpendable(vaultId, req.params.assetId));
});

// ── Transactions ──────────────────────────────────────────────────────────────
router.get('/transactions', async (req: AuthRequest, res) => {
  if (!guard(res)) return;
  const vaultId = await getUserVaultId(req);
  if (!vaultId) { res.json({ success: true, data: [] }); return; }
  const { limit, after } = req.query as Record<string, string>;
  await wrap(res, () => fb.transactions.list({ vaultAccountId: vaultId, limit: limit ? parseInt(limit) : 25, after }));
});

router.get('/transactions/:txId', async (_req, res) => {
  if (!guard(res)) return;
  await wrap(res, () => fb.transactions.get(_req.params.txId));
});

router.post('/transactions', async (req: AuthRequest, res) => {
  if (!guard(res)) return;
  try {
    const vaultId = await ensureVault(req, res);
    if (!vaultId) return;
    const { assetId, amount, destinationAddress, note } = req.body;
    if (!assetId || !amount || !destinationAddress) {
      res.status(400).json({ success: false, error: 'assetId, amount, destinationAddress required' });
      return;
    }
    const r = await fb.transactions.create({
      assetId,
      source: { type: 'VAULT_ACCOUNT', id: vaultId },
      destination: { type: 'ONE_TIME_ADDRESS', oneTimeAddress: { address: destinationAddress } },
      amount: String(amount),
      note: note ?? '',
    });
    await logAudit({ userId: req.userId, action: 'Transaction Submitted', detail: `${amount} ${assetId} → ${destinationAddress}`, type: 'wallet', severity: 'info' });
    res.status(201).json({ success: true, data: r.data });
  } catch (e: any) { res.status(500).json({ success: false, error: e.message }); }
});

router.post('/transactions/estimate-fee', async (req: AuthRequest, res) => {
  if (!guard(res)) return;
  try {
    const vaultId = await ensureVault(req, res);
    if (!vaultId) return;
    const { assetId, amount, destinationAddress } = req.body;
    const r = await fb.transactions.estimateFee({
      assetId,
      source: { type: 'VAULT_ACCOUNT', id: vaultId },
      destination: { type: 'ONE_TIME_ADDRESS', oneTimeAddress: { address: destinationAddress } },
      amount: String(amount),
    });
    res.json({ success: true, data: r.data });
  } catch (e: any) { res.status(500).json({ success: false, error: e.message }); }
});

router.get('/transactions/network-fee/:assetId', async (req, res) => {
  if (!guard(res)) return;
  await wrap(res, () => fb.transactions.estimateNetworkFee(req.params.assetId));
});

router.get('/validate-address/:assetId/:address', async (req, res) => {
  if (!guard(res)) return;
  await wrap(res, () => fb.transactions.validateAddress(req.params.assetId, req.params.address));
});

// ── Staking ───────────────────────────────────────────────────────────────────
router.get('/staking/providers', async (_req, res) => { if (!guard(res)) return; await wrap(res, () => fb.staking.getProviders()); });
router.get('/staking/chains', async (_req, res) => { if (!guard(res)) return; await wrap(res, () => fb.staking.getChains()); });
router.get('/staking/positions', async (req: AuthRequest, res) => {
  if (!guard(res)) return;
  const vaultId = await getUserVaultId(req);
  if (!vaultId) { res.json({ success: true, data: [] }); return; }
  await wrap(res, () => fb.staking.getSummaryByVault(vaultId));
});
router.get('/staking/positions/:chain', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.staking.getPositions(req.params.chain)); });
router.post('/staking/stake', async (req: AuthRequest, res) => {
  if (!guard(res)) return;
  try {
    const vaultId = await ensureVault(req, res);
    if (!vaultId) return;
    const { chainDescriptor, providerId, stakedAmount, txNote } = req.body;
    if (!chainDescriptor || !providerId || !stakedAmount) {
      res.status(400).json({ success: false, error: 'chainDescriptor, providerId, stakedAmount required' });
      return;
    }
    const r = await fb.staking.stake(chainDescriptor, vaultId, providerId, stakedAmount, txNote);
    await logAudit({ userId: req.userId, action: 'Stake Created', detail: `${stakedAmount} on ${chainDescriptor} via ${providerId}`, type: 'wallet', severity: 'info' });
    res.json({ success: true, data: r.data });
  } catch (e: any) { res.status(500).json({ success: false, error: e.message }); }
});
router.post('/staking/positions/:id/unstake', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.staking.unstake(req.params.id)); });
router.post('/staking/positions/:id/withdraw', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.staking.withdraw(req.params.id)); });
router.post('/staking/positions/:id/claim', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.staking.claimRewards(req.params.id)); });
router.post('/staking/terms/:providerId', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.staking.approveTerms(req.params.providerId)); });

// ── Earn / Yield ──────────────────────────────────────────────────────────────
router.get('/earn/opportunities', async (_req, res) => { if (!guard(res)) return; await wrap(res, () => fb.earn.getOpportunities()); });
router.get('/earn/positions', async (req: AuthRequest, res) => {
  if (!guard(res)) return;
  const vaultId = await getUserVaultId(req);
  await wrap(res, () => fb.earn.getPositions(vaultId ?? undefined));
});
router.post('/earn/actions', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.earn.createAction(req.body)); });

// ── NFTs ──────────────────────────────────────────────────────────────────────
router.get('/nfts', async (req: AuthRequest, res) => {
  if (!guard(res)) return;
  const vaultId = await getUserVaultId(req);
  await wrap(res, () => fb.nfts.getOwned(vaultId ?? undefined));
});
router.get('/nfts/:id', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.nfts.getNFT(req.params.id)); });

export default router;
