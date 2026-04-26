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

// ── Webhooks V1 ───────────────────────────────────────────────────────────────
router.post('/webhooks/resend', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.webhooks.resend(req.body.txId)); });

// ── Webhooks V2 ───────────────────────────────────────────────────────────────
router.get('/webhooks-v2', async (_req, res) => { if (!guard(res)) return; await wrap(res, () => fb.webhooksV2.list()); });
router.post('/webhooks-v2', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.webhooksV2.create(req.body)); });
router.get('/webhooks-v2/metrics', async (_req, res) => { if (!guard(res)) return; await wrap(res, () => fb.webhooksV2.getMetrics()); });
router.get('/webhooks-v2/:id', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.webhooksV2.get(req.params.id)); });
router.put('/webhooks-v2/:id', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.webhooksV2.update(req.params.id, req.body)); });
router.delete('/webhooks-v2/:id', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.webhooksV2.delete(req.params.id)); });
router.get('/webhooks-v2/:id/notifications', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.webhooksV2.getNotifications(req.params.id)); });
router.post('/webhooks-v2/:id/resend-failed', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.webhooksV2.resendFailed(req.params.id)); });
router.post('/webhooks-v2/:id/notifications/:nid/resend', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.webhooksV2.resendById(req.params.id, req.params.nid)); });

// ── Assets ────────────────────────────────────────────────────────────────────
router.get('/assets', async (_req, res) => { if (!guard(res)) return; await wrap(res, () => fb.assets.getSupportedAssets()); });
router.get('/assets/:assetId', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.assets.getAsset(req.params.assetId)); });
router.get('/blockchains', async (_req, res) => { if (!guard(res)) return; await wrap(res, () => fb.assets.listBlockchains()); });

// ── Web3 Connections (WalletConnect) ──────────────────────────────────────────
router.get('/web3', async (_req, res) => { if (!guard(res)) return; await wrap(res, () => fb.web3.list()); });
router.post('/web3', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.web3.create(req.body.uri, req.body.vaultAccountId)); });
router.delete('/web3/:id', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.web3.remove(req.params.id)); });
router.post('/web3/:id/submit', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.web3.submit(req.params.id, req.body.approve)); });

// ── Travel Rule ───────────────────────────────────────────────────────────────
router.get('/travel-rule/vasps', async (_req, res) => { if (!guard(res)) return; await wrap(res, () => fb.travelRule.getVASPs()); });
router.get('/travel-rule/vasps/:did', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.travelRule.getVASP(req.params.did)); });
router.put('/travel-rule/vasps', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.travelRule.updateVASP(req.body)); });
router.post('/travel-rule/validate', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.travelRule.validateTransaction(req.body)); });
router.get('/travel-rule/vaults/:vaultId/vasp', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.travelRule.getVaspForVault(req.params.vaultId)); });
router.post('/travel-rule/vaults/:vaultId/vasp', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.travelRule.setVaspForVault(req.params.vaultId, req.body.vaspDid)); });
router.post('/travel-rule/proof-of-address', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.travelRule.createProofOfAddress(req.body)); });
router.get('/travel-rule/proof-of-address/:address', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.travelRule.getProofOfAddress(req.params.address)); });

// ── Tokenization ──────────────────────────────────────────────────────────────
router.get('/tokenization/collections', async (_req, res) => { if (!guard(res)) return; await wrap(res, () => fb.tokenization.listCollections()); });
router.post('/tokenization/collections', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.tokenization.createCollection(req.body)); });
router.get('/tokenization/collections/:id', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.tokenization.getCollection(req.params.id)); });
router.post('/tokenization/collections/:id/mint', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.tokenization.mintToken(req.params.id, req.body)); });
router.post('/tokenization/collections/:id/burn', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.tokenization.burnToken(req.params.id, req.body)); });
router.get('/tokenization/collections/:id/tokens/:tokenId', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.tokenization.getTokenDetails(req.params.id, req.params.tokenId)); });
router.post('/tokenization/issue', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.tokenization.issueToken(req.body)); });
router.post('/tokenization/issue-multichain', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.tokenization.issueMultiChain(req.body)); });
router.get('/tokenization/linked', async (_req, res) => { if (!guard(res)) return; await wrap(res, () => fb.tokenization.listLinkedTokens()); });
router.get('/tokenization/linked/:id', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.tokenization.getLinkedToken(req.params.id)); });
router.post('/tokenization/link', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.tokenization.link(req.body)); });
router.delete('/tokenization/link/:id', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.tokenization.unlink(req.params.id)); });
router.post('/tokenization/deployable-address', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.tokenization.getDeployableAddress(req.body)); });

// ── Smart Transfer ────────────────────────────────────────────────────────────
router.get('/smart-transfer', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.smartTransfer.list(req.query)); });
router.post('/smart-transfer', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.smartTransfer.create(req.body)); });
router.get('/smart-transfer/statistics', async (_req, res) => { if (!guard(res)) return; await wrap(res, () => fb.smartTransfer.getStatistics()); });
router.get('/smart-transfer/user-groups', async (_req, res) => { if (!guard(res)) return; await wrap(res, () => fb.smartTransfer.getUserGroups()); });
router.post('/smart-transfer/user-groups', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.smartTransfer.setUserGroups(req.body)); });
router.get('/smart-transfer/:id', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.smartTransfer.get(req.params.id)); });
router.post('/smart-transfer/:id/submit', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.smartTransfer.submit(req.params.id)); });
router.post('/smart-transfer/:id/cancel', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.smartTransfer.cancel(req.params.id)); });
router.post('/smart-transfer/:id/fulfill', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.smartTransfer.fulfill(req.params.id)); });
router.patch('/smart-transfer/:id/expiration', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.smartTransfer.setExpiration(req.params.id, req.body.expiresAt)); });
router.post('/smart-transfer/:id/terms', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.smartTransfer.createTerm(req.params.id, req.body)); });
router.get('/smart-transfer/:id/terms/:termId', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.smartTransfer.getTerm(req.params.id, req.params.termId)); });
router.put('/smart-transfer/:id/terms/:termId', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.smartTransfer.updateTerm(req.params.id, req.params.termId, req.body)); });
router.delete('/smart-transfer/:id/terms/:termId', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.smartTransfer.removeTerm(req.params.id, req.params.termId)); });
router.post('/smart-transfer/:id/terms/:termId/fund', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.smartTransfer.fundTerm(req.params.id, req.params.termId)); });

// ── Key Link (Signing / Validation Keys) ──────────────────────────────────────
router.get('/key-link/signing-keys', async (_req, res) => { if (!guard(res)) return; await wrap(res, () => fb.keyLink.listSigningKeys()); });
router.post('/key-link/signing-keys', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.keyLink.createSigningKey(req.body)); });
router.get('/key-link/signing-keys/:id', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.keyLink.getSigningKey(req.params.id)); });
router.put('/key-link/signing-keys/:id', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.keyLink.updateSigningKey(req.params.id, req.body)); });
router.post('/key-link/signing-keys/:id/agent', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.keyLink.setAgentId(req.params.id, req.body.agentUserId)); });
router.get('/key-link/validation-keys', async (_req, res) => { if (!guard(res)) return; await wrap(res, () => fb.keyLink.listValidationKeys()); });
router.post('/key-link/validation-keys', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.keyLink.createValidationKey(req.body)); });
router.get('/key-link/validation-keys/:id', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.keyLink.getValidationKey(req.params.id)); });
router.patch('/key-link/validation-keys/:id/disable', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.keyLink.disableValidationKey(req.params.id, req.body)); });

// ── Payments / Payout ─────────────────────────────────────────────────────────
router.post('/payments/payout', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.payments.createPayout(req.body)); });
router.get('/payments/payout/:id', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.payments.getPayout(req.params.id)); });
router.post('/payments/payout/:id/action', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.payments.executeAction(req.params.id, req.body.action)); });

// ── Tags ──────────────────────────────────────────────────────────────────────
router.get('/tags', async (_req, res) => { if (!guard(res)) return; await wrap(res, () => fb.tags.list()); });
router.post('/tags', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.tags.create(req.body.name)); });
router.get('/tags/:id', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.tags.get(req.params.id)); });
router.put('/tags/:id', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.tags.update(req.params.id, req.body.name)); });
router.delete('/tags/:id', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.tags.delete(req.params.id)); });

// ── User Groups ───────────────────────────────────────────────────────────────
router.get('/user-groups', async (_req, res) => { if (!guard(res)) return; await wrap(res, () => fb.userGroups.list()); });
router.post('/user-groups', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.userGroups.create(req.body)); });
router.get('/user-groups/:id', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.userGroups.get(req.params.id)); });
router.put('/user-groups/:id', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.userGroups.update(req.params.id, req.body)); });
router.delete('/user-groups/:id', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.userGroups.delete(req.params.id)); });

// ── Trading ───────────────────────────────────────────────────────────────────
router.get('/trading/providers', async (_req, res) => { if (!guard(res)) return; await wrap(res, () => fb.trading.getProviders()); });
router.get('/trading/providers/:id', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.trading.getProvider(req.params.id)); });
router.post('/trading/orders', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.trading.createOrder(req.body)); });
router.get('/trading/orders', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.trading.listOrders(req.query)); });
router.get('/trading/orders/:id', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.trading.getOrder(req.params.id)); });
router.post('/trading/quotes', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.trading.createQuote(req.body)); });

// ── Connected Accounts ────────────────────────────────────────────────────────
router.get('/connected-accounts', async (_req, res) => { if (!guard(res)) return; await wrap(res, () => fb.connectedAccounts.list()); });
router.get('/connected-accounts/:id', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.connectedAccounts.get(req.params.id)); });
router.patch('/connected-accounts/:id/rename', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.connectedAccounts.rename(req.params.id, req.body.name)); });
router.get('/connected-accounts/:id/balances', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.connectedAccounts.getBalances(req.params.id)); });
router.get('/connected-accounts/:id/rates', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.connectedAccounts.getRates(req.params.id)); });
router.get('/connected-accounts/:id/trading-pairs', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.connectedAccounts.getTradingPairs(req.params.id)); });
router.delete('/connected-accounts/:id', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.connectedAccounts.disconnect(req.params.id)); });

// ── On-Chain Data ─────────────────────────────────────────────────────────────
router.get('/onchain/balances/:contractAddress/:assetId', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.onchainData.getContractBalances(req.params.contractAddress, req.params.assetId)); });
router.get('/onchain/supply/:contractAddress/:assetId', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.onchainData.getContractSupply(req.params.contractAddress, req.params.assetId)); });

// ── UTXO Management ───────────────────────────────────────────────────────────
router.get('/utxo', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.utxo.list(req.query)); });
router.patch('/utxo/labels', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.utxo.updateLabels(req.body)); });

// ── Whitelisted Contracts ─────────────────────────────────────────────────────
router.get('/whitelisted-contracts', async (_req, res) => { if (!guard(res)) return; await wrap(res, () => fb.whitelistedContracts.list()); });
router.post('/whitelisted-contracts', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.whitelistedContracts.create(req.body)); });
router.get('/whitelisted-contracts/:id', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.whitelistedContracts.get(req.params.id)); });
router.delete('/whitelisted-contracts/:id', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.whitelistedContracts.delete(req.params.id)); });
router.post('/whitelisted-contracts/:id/assets/:assetId', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.whitelistedContracts.addAsset(req.params.id, req.params.assetId, req.body)); });
router.get('/whitelisted-contracts/:id/assets/:assetId', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.whitelistedContracts.getAsset(req.params.id, req.params.assetId)); });
router.delete('/whitelisted-contracts/:id/assets/:assetId', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.whitelistedContracts.deleteAsset(req.params.id, req.params.assetId)); });

// ── MPC Keys ──────────────────────────────────────────────────────────────────
router.get('/mpc-keys', async (_req, res) => { if (!guard(res)) return; await wrap(res, () => fb.mpcKeys.list()); });
router.get('/mpc-keys/user/:userId', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.mpcKeys.listByUser(req.params.userId)); });

// ── Workspace ─────────────────────────────────────────────────────────────────
router.get('/workspace', async (_req, res) => { if (!guard(res)) return; await wrap(res, () => fb.workspace.get()); });
router.get('/workspace/status', async (_req, res) => { if (!guard(res)) return; await wrap(res, () => fb.workspace.getStatus()); });
router.get('/workspace/users', async (_req, res) => { if (!guard(res)) return; await wrap(res, () => fb.workspace.getUsers()); });
router.get('/workspace/ip-whitelist', async (_req, res) => { if (!guard(res)) return; await wrap(res, () => fb.workspace.getWhitelistIps()); });

// ── Device Management (OTA / Reset) ───────────────────────────────────────────
router.get('/ncw/:walletId/ota', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.deviceMgmt.getOtaStatus(req.params.walletId)); });
router.put('/ncw/:walletId/ota', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.deviceMgmt.setOtaStatus(req.params.walletId, req.body.enabled)); });
router.post('/ncw/:walletId/devices/:deviceId/reset', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.deviceMgmt.resetDevice(req.params.walletId, req.params.deviceId)); });

// ── TR-Link ───────────────────────────────────────────────────────────────────
router.get('/tr-link/partners', async (_req, res) => { if (!guard(res)) return; await wrap(res, () => fb.trLink.getPartners()); });
router.get('/tr-link/policy', async (_req, res) => { if (!guard(res)) return; await wrap(res, () => fb.trLink.getPolicy()); });
router.get('/tr-link/integrations', async (_req, res) => { if (!guard(res)) return; await wrap(res, () => fb.trLink.listIntegrations()); });
router.post('/tr-link/integrations', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.trLink.createIntegration(req.body)); });
router.post('/tr-link/integrations/:id/connect', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.trLink.connectIntegration(req.params.id, req.body)); });
router.post('/tr-link/integrations/:id/disconnect', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.trLink.disconnectIntegration(req.params.id)); });
router.post('/tr-link/integrations/:id/test', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.trLink.testConnection(req.params.id)); });
router.get('/tr-link/integrations/:id/public-key', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.trLink.getPublicKey(req.params.id)); });
router.get('/tr-link/customers', async (_req, res) => { if (!guard(res)) return; await wrap(res, () => fb.trLink.listCustomers()); });
router.post('/tr-link/customers', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.trLink.createCustomer(req.body)); });
router.get('/tr-link/customers/:id', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.trLink.getCustomer(req.params.id)); });
router.put('/tr-link/customers/:id', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.trLink.updateCustomer(req.params.id, req.body)); });
router.delete('/tr-link/customers/:id', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.trLink.deleteCustomer(req.params.id)); });
router.get('/tr-link/vasps', async (_req, res) => { if (!guard(res)) return; await wrap(res, () => fb.trLink.listVasps()); });
router.get('/tr-link/assets', async (_req, res) => { if (!guard(res)) return; await wrap(res, () => fb.trLink.listSupportedAssets()); });
router.post('/tr-link/assess', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.trLink.assessRequirement(req.body)); });
router.post('/tr-link/trm', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.trLink.createTrm(req.body)); });
router.get('/tr-link/trm/:id', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.trLink.getTrm(req.params.id)); });
router.post('/tr-link/trm/:id/cancel', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.trLink.cancelTrm(req.params.id)); });

// ── Legacy Policy (V1) ────────────────────────────────────────────────────────
router.get('/policy-legacy/active', async (_req, res) => { if (!guard(res)) return; await wrap(res, () => fb.policyLegacy.getActive()); });
router.get('/policy-legacy/draft', async (_req, res) => { if (!guard(res)) return; await wrap(res, () => fb.policyLegacy.getDraft()); });
router.put('/policy-legacy/draft', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.policyLegacy.updateDraft(req.body)); });
router.post('/policy-legacy/publish', async (_req, res) => { if (!guard(res)) return; await wrap(res, () => fb.policyLegacy.publishDraft()); });
router.post('/policy-legacy/rules', async (req, res) => { if (!guard(res)) return; await wrap(res, () => fb.policyLegacy.publishRules(req.body)); });

export default router;
