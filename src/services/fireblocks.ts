import { Fireblocks, TransactionRequest, TransactionStateEnum } from '@fireblocks/ts-sdk';

let _sdk: Fireblocks | null = null;

export function getFireblocks(): Fireblocks {
  if (_sdk) return _sdk;
  const apiKey = process.env.FIREBLOCKS_API_KEY;
  const secretKey = process.env.FIREBLOCKS_SECRET_KEY;
  if (!apiKey || !secretKey) {
    throw new Error('Fireblocks credentials not configured. Set FIREBLOCKS_API_KEY and FIREBLOCKS_SECRET_KEY.');
  }
  const basePath = process.env.FIREBLOCKS_BASE_URL || 'https://api.fireblocks.io';
  _sdk = new Fireblocks({ apiKey, secretKey, basePath });
  return _sdk;
}

export function isConfigured(): boolean {
  return !!(process.env.FIREBLOCKS_API_KEY && process.env.FIREBLOCKS_SECRET_KEY);
}

// ─── Vault ───────────────────────────────────────────────────────────────────

export async function createVaultAccount(name: string, hiddenOnUI = false) {
  return getFireblocks().vaults.createVaultAccount({ createVaultAccountRequest: { name, hiddenOnUI } });
}

export async function getVaultAccount(vaultId: string) {
  return getFireblocks().vaults.getVaultAccount({ vaultAccountId: vaultId });
}

export async function listVaultAccounts(namePrefix?: string) {
  return getFireblocks().vaults.getPagedVaultAccounts({
    ...(namePrefix ? { namePrefix } : {}),
    limit: 200,
  });
}

export async function activateVaultAsset(vaultId: string, assetId: string) {
  return getFireblocks().vaults.createVaultAccountAsset({ vaultAccountId: vaultId, assetId });
}

export async function getVaultAsset(vaultId: string, assetId: string) {
  return getFireblocks().vaults.getVaultAccountAsset({ vaultAccountId: vaultId, assetId });
}

export async function getVaultAddresses(vaultId: string, assetId: string) {
  return getFireblocks().vaults.getVaultAccountAssetAddressesPaginated({ vaultAccountId: vaultId, assetId });
}

export async function createDepositAddress(vaultId: string, assetId: string, description?: string) {
  return getFireblocks().vaults.createVaultAccountAssetAddress({
    vaultAccountId: vaultId,
    assetId,
    createAddressRequest: { description },
  });
}

export async function refreshVaultBalance(vaultId: string, assetId: string) {
  return getFireblocks().vaults.updateVaultAccountAssetBalance({ vaultAccountId: vaultId, assetId });
}

// ─── Transactions ─────────────────────────────────────────────────────────────

export async function createTransaction(args: TransactionRequest) {
  return getFireblocks().transactions.createTransaction({ transactionRequest: args });
}

export async function getTransaction(txId: string) {
  return getFireblocks().transactions.getTransaction({ txId });
}

export async function listTransactions(params: {
  vaultAccountId?: string;
  limit?: number;
  status?: TransactionStateEnum;
  after?: string;
}) {
  return getFireblocks().transactions.getTransactions({
    sourceId: params.vaultAccountId,
    sourceType: params.vaultAccountId ? ('VAULT_ACCOUNT' as any) : undefined,
    limit: params.limit ?? 50,
    status: params.status,
    after: params.after,
  });
}

export async function cancelTransaction(txId: string) {
  return getFireblocks().transactions.cancelTransaction({ txId });
}

// ─── Assets ──────────────────────────────────────────────────────────────────

export async function getSupportedAssets() {
  return getFireblocks().blockchainsAssets.getSupportedAssets();
}

// ─── Staking ─────────────────────────────────────────────────────────────────

export async function getStakingPositions() {
  return getFireblocks().staking.getAllDelegations();
}

// ─── Network ─────────────────────────────────────────────────────────────────

export async function listNetworkConnections() {
  return getFireblocks().networkConnections.getNetworkConnections();
}

export async function getNetworkConnection(connectionId: string) {
  return getFireblocks().networkConnections.getNetwork({ connectionId });
}

// ─── Webhooks ────────────────────────────────────────────────────────────────

export async function resendWebhooks(txId?: string) {
  if (txId) {
    return getFireblocks().webhooks.resendTransactionWebhooks({
      txId,
      resendTransactionWebhooksRequest: {},
    });
  }
  return getFireblocks().webhooks.resendWebhooks();
}

// ─── Whitelisted wallets ──────────────────────────────────────────────────────

export async function listInternalWallets() {
  return getFireblocks().internalWallets.getInternalWallets();
}

export async function listExternalWallets() {
  return getFireblocks().externalWallets.getExternalWallets();
}
