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

// ── Status ────────────────────────────────────────────────────────────────────
router.get('/status', (_req, res) => res.json({ success: true, data: { configured: fb.isConfigured() } }));

// ── Vaults ────────────────────────────────────────────────────────────────────
router.get('/vaults', async (_req, res) => { if (!guard(res)) return; await wrap(res, () => fb.vaults.list()); });
router.get('/vaults/:id', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.vaults.get(req.params.id)); });
router.post('/vaults', async (req: AuthRequest, res) => {
  if (!guard(res)) return;
  const { userId, name } = req.body;
  if (!userId || !name) { res.status(400).json({ success: false, error: 'userId and name required' }); return; }
  try {
    const r = await fb.vaults.create(name);
    const vaultId = r.data?.id;
    if (!vaultId) throw new Error('No vault ID returned');
    await db.update(users).set({ fireblocksVaultId: vaultId, updatedAt: new Date() }).where(eq(users.id, userId));
    await logAudit({ userId, action: 'Fireblocks Vault Created', detail: `Vault ${vaultId}`, type: 'admin', severity: 'info' });
    res.status(201).json({ success: true, data: r.data });
  } catch (e: any) { res.status(500).json({ success: false, error: e.message }); }
});
router.post('/vaults/:id/hide', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.vaults.hide(req.params.id)); });
router.post('/vaults/:id/unhide', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.vaults.unhide(req.params.id)); });
router.patch('/vaults/:id/autofuel', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.vaults.setAutoFuel(req.params.id, !!req.body.autoFuel)); });
router.post('/vaults/:id/assets/:assetId', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.vaults.activateAsset(req.params.id, req.params.assetId)); });
router.get('/vaults/:id/assets/:assetId', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.vaults.getAsset(req.params.id, req.params.assetId)); });
router.post('/vaults/:id/assets/:assetId/refresh', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.vaults.refreshBalance(req.params.id, req.params.assetId)); });
router.get('/vaults/:id/assets/:assetId/addresses', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.vaults.getAddresses(req.params.id, req.params.assetId)); });
router.post('/vaults/:id/assets/:assetId/addresses', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.vaults.createAddress(req.params.id, req.params.assetId, req.body.description)); });
router.get('/vaults/:id/assets/:assetId/max-spendable', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.vaults.getMaxSpendable(req.params.id, req.params.assetId)); });

// ── Transactions ──────────────────────────────────────────────────────────────
router.get('/transactions', async (req, res) => {
  if (!guard(res)) return;
  const { limit, status, after, orderBy } = req.query as Record<string, string>;
  await wrap(res, () => fb.transactions.list({ limit: limit ? parseInt(limit) : 50, status: status as any, after, orderBy: orderBy as any }));
});
router.get('/transactions/:txId', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.transactions.get(req.params.txId)); });
router.delete('/transactions/:txId', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.transactions.cancel(req.params.txId)); });
router.post('/transactions/:txId/freeze', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.transactions.freeze(req.params.txId)); });
router.post('/transactions/:txId/unfreeze', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.transactions.unfreeze(req.params.txId)); });
router.post('/transactions/:txId/drop', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.transactions.drop(req.params.txId, req.body.feeLevel)); });
router.post('/transactions/estimate-fee', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.transactions.estimateFee(req.body)); });
router.get('/transactions/network-fee/:assetId', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.transactions.estimateNetworkFee(req.params.assetId)); });
router.post('/transactions/:txId/confirmation-threshold', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.transactions.setConfirmationThreshold(req.params.txId, req.body.numOfConfirmations)); });
router.get('/validate-address/:assetId/:address', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.transactions.validateAddress(req.params.assetId, req.params.address)); });

// ── Policy Engine (TAP) ───────────────────────────────────────────────────────
router.get('/policy/active', async (_req, res) => { if (!guard(res)) return; await wrap(res, () => fb.policy.getActive()); });
router.get('/policy/draft', async (_req, res) => { if (!guard(res)) return; await wrap(res, () => fb.policy.getDraft()); });
router.put('/policy/draft', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.policy.updateDraft(req.body.rules)); });
router.post('/policy/publish', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.policy.publishDraft(req.body.checksum)); });

// ── Compliance / AML ──────────────────────────────────────────────────────────
router.get('/compliance/policy', async (_req, res) => { if (!guard(res)) return; await wrap(res, () => fb.compliance.getScreeningPolicy()); });
router.get('/compliance/post-screening', async (_req, res) => { if (!guard(res)) return; await wrap(res, () => fb.compliance.getPostScreeningPolicy()); });
router.get('/compliance/config', async (_req, res) => { if (!guard(res)) return; await wrap(res, () => fb.compliance.getScreeningConfig()); });
router.get('/compliance/transactions/:txId', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.compliance.getScreeningDetails(req.params.txId)); });
router.post('/compliance/transactions/:txId/verdict', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.compliance.setAmlVerdict(req.params.txId, req.body.verdict)); });
router.post('/compliance/transactions/:txId/retry', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.compliance.retryBypassed(req.params.txId)); });

// ── Gas Station ────────────────────────────────────────────────────────────────
router.get('/gas-station', async (_req, res) => { if (!guard(res)) return; await wrap(res, () => fb.gasStation.getInfo()); });
router.get('/gas-station/:assetId', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.gasStation.getByAsset(req.params.assetId)); });
router.put('/gas-station/config', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.gasStation.updateConfig(req.body)); });
router.put('/gas-station/:assetId/config', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.gasStation.updateConfigByAsset(req.params.assetId, req.body)); });

// ── Staking ────────────────────────────────────────────────────────────────────
router.get('/staking/providers', async (_req, res) => { if (!guard(res)) return; await wrap(res, () => fb.staking.getProviders()); });
router.get('/staking/chains', async (_req, res) => { if (!guard(res)) return; await wrap(res, () => fb.staking.getChains()); });
router.get('/staking/chains/:chain', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.staking.getChainInfo(req.params.chain)); });
router.get('/staking/positions', async (_req, res) => { if (!guard(res)) return; await wrap(res, () => fb.staking.getAllDelegations()); });
router.get('/staking/positions/:chain', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.staking.getPositions(req.params.chain)); });
router.get('/staking/summary', async (_req, res) => { if (!guard(res)) return; await wrap(res, () => fb.staking.getSummary()); });
router.get('/staking/summary/:vaultId', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.staking.getSummaryByVault(req.params.vaultId)); });
router.post('/staking/stake', async (req: AuthRequest, res) => {
  if (!guard(res)) return;
  const { chainDescriptor, vaultAccountId, providerId, stakedAmount, txNote } = req.body;
  try {
    const r = await fb.staking.stake(chainDescriptor, vaultAccountId, providerId, stakedAmount, txNote);
    await logAudit({ userId: req.userId, action: 'Staking Created', detail: `${stakedAmount} on ${chainDescriptor}`, type: 'admin', severity: 'info' });
    res.json({ success: true, data: r.data });
  } catch (e: any) { res.status(500).json({ success: false, error: e.message }); }
});
router.post('/staking/positions/:id/unstake', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.staking.unstake(req.params.id)); });
router.post('/staking/positions/:id/withdraw', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.staking.withdraw(req.params.id)); });
router.post('/staking/positions/:id/claim', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.staking.claimRewards(req.params.id)); });
router.post('/staking/positions/:id/split', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.staking.split(req.params.id, req.body.amount)); });
router.post('/staking/merge', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.staking.merge(req.body.chainDescriptor, req.body.ids)); });
router.post('/staking/terms/:providerId', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.staking.approveTerms(req.params.providerId)); });

// ── Exchange Accounts ──────────────────────────────────────────────────────────
router.get('/exchange', async (_req, res) => { if (!guard(res)) return; await wrap(res, () => fb.exchange.list()); });
router.get('/exchange/:id', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.exchange.get(req.params.id)); });
router.get('/exchange/:id/assets/:assetId', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.exchange.getAsset(req.params.id, req.params.assetId)); });
router.post('/exchange/:id/transfer', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.exchange.internalTransfer(req.params.id, req.body.assetId, req.body.amount, req.body.subType)); });

// ── Fiat Accounts ──────────────────────────────────────────────────────────────
router.get('/fiat', async (_req, res) => { if (!guard(res)) return; await wrap(res, () => fb.fiat.list()); });
router.get('/fiat/:id', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.fiat.get(req.params.id)); });
router.post('/fiat/:id/deposit', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.fiat.deposit(req.params.id, req.body.amount)); });
router.post('/fiat/:id/redeem', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.fiat.redeem(req.params.id, req.body.amount)); });

// ── NCW / Embedded Wallets ────────────────────────────────────────────────────
router.get('/ncw', async (_req, res) => { if (!guard(res)) return; await wrap(res, () => fb.ncw.list()); });
router.get('/ncw/assets', async (_req, res) => { if (!guard(res)) return; await wrap(res, () => fb.ncw.getSupportedAssets()); });
router.post('/ncw', async (req: AuthRequest, res) => {
  if (!guard(res)) return;
  try {
    const r = await fb.ncw.create();
    const walletId = r.data?.walletId;
    if (req.body.userId && walletId) {
      await fb.ncw.assign(walletId, req.body.userId);
    }
    res.status(201).json({ success: true, data: r.data });
  } catch (e: any) { res.status(500).json({ success: false, error: e.message }); }
});
router.get('/ncw/:walletId', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.ncw.get(req.params.walletId)); });
router.patch('/ncw/:walletId/status', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.ncw.setStatus(req.params.walletId, req.body.status)); });
router.post('/ncw/:walletId/assign', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.ncw.assign(req.params.walletId, req.body.userId)); });
router.get('/ncw/:walletId/accounts', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.ncw.getAccount(req.params.walletId, '0')); });
router.post('/ncw/:walletId/accounts', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.ncw.createAccount(req.params.walletId)); });
router.get('/ncw/:walletId/devices', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.ncw.getDevices(req.params.walletId)); });
router.get('/ncw/:walletId/backup', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.ncw.getBackup(req.params.walletId)); });

// ── Audit Logs (Fireblocks) ───────────────────────────────────────────────────
router.get('/audit-logs', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.fbAuditLogs.get(req.query.cursor as string)); });

// ── NFTs ──────────────────────────────────────────────────────────────────────
router.get('/nfts', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.nfts.getOwned(req.query.vaultId as string)); });
router.get('/nfts/collections', async (_req, res) => { if (!guard(res)) return; await wrap(res, () => fb.nfts.listCollections()); });
router.get('/nfts/:id', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.nfts.getNFT(req.params.id)); });
router.post('/nfts/:id/refresh', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.nfts.refreshMetadata(req.params.id)); });

// ── Earn / Yield ──────────────────────────────────────────────────────────────
router.get('/earn/providers', async (_req, res) => { if (!guard(res)) return; await wrap(res, () => fb.earn.getProviders()); });
router.get('/earn/opportunities', async (_req, res) => { if (!guard(res)) return; await wrap(res, () => fb.earn.getOpportunities()); });
router.get('/earn/positions', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.earn.getPositions(req.query.vaultId as string)); });
router.get('/earn/actions', async (_req, res) => { if (!guard(res)) return; await wrap(res, () => fb.earn.getActions()); });
router.post('/earn/actions', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.earn.createAction(req.body)); });

// ── Smart Contracts ────────────────────────────────────────────────────────────
router.get('/contracts/templates', async (_req, res) => { if (!guard(res)) return; await wrap(res, () => fb.contracts.getTemplates()); });
router.get('/contracts/templates/:id', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.contracts.getTemplate(req.params.id)); });
router.post('/contracts/templates/:id/deploy', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.contracts.deploy(req.params.id, req.body)); });
router.get('/contracts/deployed', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.contracts.getDeployed({ assetId: req.query.assetId as string, limit: 50 })); });
router.post('/contracts/read', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.contracts.readFunction(req.body)); });
router.post('/contracts/write', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.contracts.writeFunction(req.body)); });

// ── Workspace Users ────────────────────────────────────────────────────────────
router.get('/workspace/users/console', async (_req, res) => { if (!guard(res)) return; await wrap(res, () => fb.workspaceUsers.getConsoleUsers()); });
router.post('/workspace/users/console', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.workspaceUsers.createConsoleUser(req.body)); });
router.get('/workspace/users/api', async (_req, res) => { if (!guard(res)) return; await wrap(res, () => fb.workspaceUsers.getApiUsers()); });
router.post('/workspace/users/api', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.workspaceUsers.createApiUser(req.body)); });

// ── Cosigners ─────────────────────────────────────────────────────────────────
router.get('/cosigners', async (_req, res) => { if (!guard(res)) return; await wrap(res, () => fb.cosigners.list()); });
router.get('/cosigners/:id', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.cosigners.get(req.params.id)); });
router.patch('/cosigners/:id/rename', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.cosigners.rename(req.params.id, req.body.name)); });
router.get('/cosigners/:id/api-keys', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.cosigners.getApiKeys(req.params.id)); });
router.post('/cosigners/:id/api-keys/:keyId/pair', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.cosigners.pairApiKey(req.params.id, req.params.keyId)); });
router.delete('/cosigners/:id/api-keys/:keyId', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.cosigners.unpairApiKey(req.params.id, req.params.keyId)); });

// ── Off-Exchange ───────────────────────────────────────────────────────────────
router.get('/off-exchange', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.offExchange.list(req.query.mainExchangeAccountId as string ?? '')); });
router.get('/off-exchange/settlements', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.offExchange.getSettlements(req.query.mainExchangeAccountId as string ?? '')); });
router.post('/off-exchange/settle', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.offExchange.settle(req.body.mainExchangeAccountId)); });

// ── Network ───────────────────────────────────────────────────────────────────
router.get('/network', async (_req, res) => { if (!guard(res)) return; await wrap(res, () => fb.network.list()); });
router.get('/network/:id', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.network.get(req.params.id)); });
router.get('/network-ids', async (_req, res) => { if (!guard(res)) return; await wrap(res, () => fb.network.getNetworkIds()); });

// ── Webhooks ──────────────────────────────────────────────────────────────────
router.post('/webhooks/resend', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.webhooks.resend(req.body.txId)); });

// ── Assets ────────────────────────────────────────────────────────────────────
router.get('/assets', async (_req, res) => { if (!guard(res)) return; await wrap(res, () => fb.assets.getSupportedAssets()); });
router.get('/assets/:assetId', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.assets.getAsset(req.params.assetId)); });
router.get('/blockchains', async (_req, res) => { if (!guard(res)) return; await wrap(res, () => fb.assets.listBlockchains()); });

export default router;
