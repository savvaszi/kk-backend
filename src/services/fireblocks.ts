/* eslint-disable @typescript-eslint/no-explicit-any */
import { Fireblocks, TransactionRequest, TransactionStateEnum } from '@fireblocks/ts-sdk';

let _sdk: Fireblocks | null = null;

export function getFireblocks(): Fireblocks {
  if (_sdk) return _sdk;
  const apiKey = process.env.FIREBLOCKS_API_KEY;
  const secretKey = process.env.FIREBLOCKS_SECRET_KEY;
  if (!apiKey || !secretKey) throw new Error('Fireblocks credentials not configured.');
  _sdk = new Fireblocks({
    apiKey,
    secretKey,
    basePath: process.env.FIREBLOCKS_BASE_URL || 'https://api.fireblocks.io',
  });
  return _sdk;
}

export function isConfigured(): boolean {
  return !!(process.env.FIREBLOCKS_API_KEY && process.env.FIREBLOCKS_SECRET_KEY);
}

const fb = () => getFireblocks();

// ─── Vaults ───────────────────────────────────────────────────────────────────
export const vaults = {
  create: (name: string, hiddenOnUI = false) =>
    fb().vaults.createVaultAccount({ createVaultAccountRequest: { name, hiddenOnUI } }),
  get: (vaultId: string) => fb().vaults.getVaultAccount({ vaultAccountId: vaultId }),
  list: (namePrefix?: string) =>
    fb().vaults.getPagedVaultAccounts({ ...(namePrefix ? { namePrefix } : {}), limit: 200 }),
  hide: (vaultId: string) => fb().vaults.hideVaultAccount({ vaultAccountId: vaultId }),
  unhide: (vaultId: string) => fb().vaults.unhideVaultAccount({ vaultAccountId: vaultId }),
  setAutoFuel: (vaultId: string, autoFuel: boolean) =>
    fb().vaults.setVaultAccountAutoFuel({ vaultAccountId: vaultId, setAutoFuelRequest: { autoFuel } } as any),
  activateAsset: (vaultId: string, assetId: string) =>
    fb().vaults.createVaultAccountAsset({ vaultAccountId: vaultId, assetId }),
  getAsset: (vaultId: string, assetId: string) =>
    fb().vaults.getVaultAccountAsset({ vaultAccountId: vaultId, assetId }),
  refreshBalance: (vaultId: string, assetId: string) =>
    fb().vaults.updateVaultAccountAssetBalance({ vaultAccountId: vaultId, assetId }),
  getAddresses: (vaultId: string, assetId: string) =>
    fb().vaults.getVaultAccountAssetAddressesPaginated({ vaultAccountId: vaultId, assetId }),
  createAddress: (vaultId: string, assetId: string, description?: string) =>
    fb().vaults.createVaultAccountAssetAddress({
      vaultAccountId: vaultId, assetId,
      createAddressRequest: { description },
    }),
  getMaxSpendable: (vaultId: string, assetId: string) =>
    fb().vaults.getMaxSpendableAmount({ vaultAccountId: vaultId, assetId } as any),
  getUnspentInputs: (vaultId: string, assetId: string) =>
    fb().vaults.getUnspentInputs({ vaultAccountId: vaultId, assetId } as any),
  getAllAssets: () => (fb().vaults as any).getVaultAssets({}),
};

// ─── Transactions ─────────────────────────────────────────────────────────────
export const transactions = {
  create: (args: TransactionRequest) =>
    fb().transactions.createTransaction({ transactionRequest: args }),
  get: (txId: string) => fb().transactions.getTransaction({ txId }),
  list: (params: { vaultAccountId?: string; limit?: number; status?: TransactionStateEnum; after?: string; orderBy?: any }) =>
    fb().transactions.getTransactions({
      sourceId: params.vaultAccountId,
      sourceType: params.vaultAccountId ? ('VAULT_ACCOUNT' as any) : undefined,
      limit: params.limit ?? 50,
      status: params.status,
      after: params.after,
      orderBy: params.orderBy,
    }),
  cancel: (txId: string) => fb().transactions.cancelTransaction({ txId }),
  drop: (txId: string, feeLevel?: string) =>
    fb().transactions.dropTransaction({ txId, dropTransactionRequest: { feeLevel: feeLevel as any } } as any),
  freeze: (txId: string) => fb().transactions.freezeTransaction({ txId }),
  unfreeze: (txId: string) => fb().transactions.unfreezeTransaction({ txId }),
  estimateFee: (args: TransactionRequest) =>
    fb().transactions.estimateTransactionFee({ transactionRequest: args }),
  estimateNetworkFee: (assetId: string) =>
    fb().transactions.estimateNetworkFee({ assetId }),
  setConfirmationThreshold: (txId: string, numOfConfirmations: number) =>
    fb().transactions.setTransactionConfirmationThreshold({
      txId, setConfirmationsThresholdRequest: { numOfConfirmations },
    } as any),
  validateAddress: (assetId: string, address: string) =>
    fb().transactions.validateAddress({ assetId, address }),
};

// ─── Assets ───────────────────────────────────────────────────────────────────
export const assets = {
  getSupportedAssets: () => fb().blockchainsAssets.getSupportedAssets(),
  getAsset: (assetId: string) => (fb().blockchainsAssets as any).getAsset({ assetId }),
  listBlockchains: () => (fb().blockchainsAssets as any).listBlockchains({}),
  listAssets: (blockchainId?: string) =>
    (fb().blockchainsAssets as any).listAssets({ ...(blockchainId ? { blockchainId } : {}) }),
};

// ─── Policy Engine (TAP) ──────────────────────────────────────────────────────
export const policy = {
  getActive: () => (fb().policyEditorV2Beta as any).getActivePolicy({}),
  getDraft: () => (fb().policyEditorV2Beta as any).getDraft({}),
  updateDraft: (rules: any[]) =>
    (fb().policyEditorV2Beta as any).updateDraft({ rules } as any),
  publishDraft: (checksum: string) =>
    (fb().policyEditorV2Beta as any).publishDraft({ checksum } as any),
};

// ─── Compliance / AML ─────────────────────────────────────────────────────────
export const compliance = {
  getScreeningPolicy: () => fb().compliance.getAmlScreeningPolicy(),
  getPostScreeningPolicy: () => fb().compliance.getPostScreeningPolicy(),
  getScreeningConfig: () => fb().complianceScreeningConfiguration.getAmlScreeningConfiguration(),
  getScreeningDetails: (txId: string) =>
    fb().compliance.getScreeningFullDetails({ txId }),
  setAmlVerdict: (txId: string, verdict: string) =>
    (fb().compliance as any).setAmlVerdict({ txId, verdict } as any),
  retryBypassed: (txId: string) =>
    fb().compliance.retryRejectedTransactionBypassScreeningChecks({ txId }),
};

// ─── Gas Station ─────────────────────────────────────────────────────────────
export const gasStation = {
  getInfo: () => fb().gasStations.getGasStationInfo(),
  getByAsset: (assetId: string) =>
    fb().gasStations.getGasStationByAssetId({ assetId }),
  updateConfig: (config: any) =>
    (fb().gasStations as any).updateGasStationConfiguration({ gasStationConfiguration: config }),
  updateConfigByAsset: (assetId: string, config: any) =>
    (fb().gasStations as any).updateGasStationConfigurationByAssetId({ assetId, gasStationConfiguration: config }),
};

// ─── Staking ─────────────────────────────────────────────────────────────────
export const staking = {
  getProviders: () => fb().staking.getProviders(),
  getChains: () => (fb().staking as any).getChains(),
  getChainInfo: (chainDescriptor: string) =>
    (fb().staking as any).getChainInfo({ chainDescriptor }),
  getAllDelegations: () => fb().staking.getAllDelegations(),
  getPositions: (chainDescriptor: string) =>
    (fb().staking as any).getPositions({ chainDescriptor }),
  getDelegation: (id: string) => (fb().staking as any).getDelegationById({ id }),
  getSummary: () => (fb().staking as any).getSummary(),
  getSummaryByVault: (vaultAccountId: string) =>
    (fb().staking as any).getSummaryByVault({ vaultAccountId }),
  stake: (chainDescriptor: string, vaultAccountId: string, providerId: string, stakedAmount: string, txNote?: string) =>
    (fb().staking as any).stake({ chainDescriptor, vaultAccountId, providerId, stakedAmount, txNote }),
  unstake: (id: string) => (fb().staking as any).unstake({ id }),
  withdraw: (id: string) => (fb().staking as any).withdraw({ id }),
  claimRewards: (id: string) => (fb().staking as any).claimRewards({ id }),
  split: (id: string, amount: string) => (fb().staking as any).split({ id, amount }),
  merge: (chainDescriptor: string, ids: string[]) =>
    (fb().staking as any).mergeStakeAccounts({ chainDescriptor, ids }),
  consolidate: (vaultAccountId: string, chainDescriptor: string) =>
    (fb().staking as any).consolidate({ chainDescriptor, vaultAccountId }),
  approveTerms: (providerId: string) =>
    (fb().staking as any).approveTermsOfServiceByProviderId({ providerId }),
};

// ─── Exchange Accounts ────────────────────────────────────────────────────────
export const exchange = {
  list: () => fb().exchangeAccounts.getPagedExchangeAccounts({ limit: 50 }),
  get: (exchangeAccountId: string) =>
    fb().exchangeAccounts.getExchangeAccount({ exchangeAccountId }),
  getAsset: (exchangeAccountId: string, assetId: string) =>
    fb().exchangeAccounts.getExchangeAccountAsset({ exchangeAccountId, assetId }),
  internalTransfer: (exchangeAccountId: string, assetId: string, amount: string, subType: string) =>
    (fb().exchangeAccounts as any).internalTransfer({ exchangeAccountId, assetId, amount, subType }),
};

// ─── Fiat Accounts ────────────────────────────────────────────────────────────
export const fiat = {
  list: () => fb().fiatAccounts.getFiatAccounts(),
  get: (accountId: string) => fb().fiatAccounts.getFiatAccount({ accountId }),
  deposit: (accountId: string, amount: number) =>
    (fb().fiatAccounts as any).depositFundsFromLinkedDDA({ accountId, amount }),
  redeem: (accountId: string, amount: number) =>
    (fb().fiatAccounts as any).redeemFundsToLinkedDDA({ accountId, amount }),
};

// ─── NCW / Embedded Wallets ───────────────────────────────────────────────────
export const ncw = {
  create: () => fb().embeddedWallets.createEmbeddedWallet({}),
  list: (pageCursor?: string) =>
    fb().embeddedWallets.getEmbeddedWallets({ ...(pageCursor ? { pageCursor } : {}), pageSize: 50 } as any),
  get: (walletId: string) => fb().embeddedWallets.getEmbeddedWallet({ walletId }),
  assign: (walletId: string, userId: string) =>
    (fb().embeddedWallets as any).assignEmbeddedWallet({ walletId, userId }),
  setStatus: (walletId: string, status: string) =>
    (fb().embeddedWallets as any).updateEmbeddedWalletStatus({ walletId, status }),
  getSupportedAssets: () =>
    fb().embeddedWallets.getEmbeddedWalletSupportedAssets({} as any),
  createAccount: (walletId: string) =>
    fb().embeddedWallets.createEmbeddedWalletAccount({ walletId }),
  getAccount: (walletId: string, accountId: string) =>
    (fb().embeddedWallets as any).getEmbeddedWalletAccount({ walletId, accountId }),
  addAsset: (walletId: string, accountId: string, assetId: string) =>
    (fb().embeddedWallets as any).addEmbeddedWalletAsset({ walletId, accountId, assetId }),
  getAsset: (walletId: string, accountId: string, assetId: string) =>
    (fb().embeddedWallets as any).getEmbeddedWalletAsset({ walletId, accountId, assetId }),
  getAssets: (walletId: string, accountId: string) =>
    (fb().embeddedWallets as any).getEmbeddedWalletAssets({ walletId, accountId }),
  getAddresses: (walletId: string, accountId: string, assetId: string) =>
    (fb().embeddedWallets as any).getEmbeddedWalletAddresses({ walletId, accountId, assetId }),
  refreshBalance: (walletId: string, accountId: string, assetId: string) =>
    (fb().embeddedWallets as any).refreshEmbeddedWalletAssetBalance({ walletId, accountId, assetId }),
  getDevices: (walletId: string) =>
    (fb().embeddedWallets as any).getEmbeddedWalletDevicesPaginated({ walletId }),
  getDevice: (walletId: string, deviceId: string) =>
    fb().embeddedWallets.getEmbeddedWalletDevice({ walletId, deviceId }),
  getSetupStatus: (walletId: string) =>
    (fb().embeddedWallets as any).getEmbeddedWalletSetupStatus({ walletId }),
  updateDeviceStatus: (walletId: string, deviceId: string, status: string) =>
    (fb().embeddedWallets as any).updateEmbeddedWalletDeviceStatus({ walletId, deviceId, status }),
  getBackup: (walletId: string) =>
    fb().embeddedWallets.getEmbeddedWalletLatestBackup({ walletId }),
};

// ─── Audit Logs ───────────────────────────────────────────────────────────────
export const fbAuditLogs = {
  get: (cursor?: string) =>
    (fb().auditLogs as any).getAuditLogs({ ...(cursor ? { cursor } : {}) }),
};

// ─── NFTs ─────────────────────────────────────────────────────────────────────
export const nfts = {
  getNFT: (id: string) => fb().nfts.getNFT({ id }),
  getNFTs: (ids: string[]) => (fb().nfts as any).getNFTs({ ids }),
  getOwned: (vaultAccountId?: string) =>
    fb().nfts.getOwnershipTokens({ ...(vaultAccountId ? { vaultAccountId } : {}), limit: 50 } as any),
  listCollections: () => fb().nfts.listOwnedCollections({ limit: 50 } as any),
  refreshMetadata: (id: string) => (fb().nfts as any).refreshNFTMetadata({ id }),
};

// ─── Earn / Yield ─────────────────────────────────────────────────────────────
export const earn = {
  getProviders: () => (fb().earnBeta as any).getEarnProviders({}),
  getOpportunities: () => (fb().earnBeta as any).getEarnOpportunities({}),
  getPositions: (vaultAccountId?: string) =>
    (fb().earnBeta as any).getEarnPositions({ ...(vaultAccountId ? { vaultAccountId } : {}) }),
  getActions: () => (fb().earnBeta as any).getEarnActions({}),
  createAction: (body: any) =>
    (fb().earnBeta as any).createEarnAction(body),
  getAction: (id: string) => (fb().earnBeta as any).getEarnAction({ id }),
};

// ─── Smart Contracts ──────────────────────────────────────────────────────────
export const contracts = {
  getTemplates: () => (fb().contractTemplates as any).getContractTemplates({}),
  getTemplate: (contractTemplateId: string) =>
    fb().contractTemplates.getContractTemplateById({ contractTemplateId }),
  deploy: (contractTemplateId: string, body: any) =>
    (fb().contractTemplates as any).deployContract({ contractTemplateId, ...body }),
  getDeployed: (params?: any) =>
    (fb().deployedContracts as any).getDeployedContracts({ ...(params ?? {}) }),
  getByAddress: (assetId: string, address: string) =>
    (fb().deployedContracts as any).getDeployedContractByAddress({ assetId, address }),
  readFunction: (body: any) =>
    (fb().contractInteractions as any).readCallFunction(body),
  writeFunction: (body: any) =>
    (fb().contractInteractions as any).writeCallFunction(body),
};

// ─── Workspace Users ──────────────────────────────────────────────────────────
export const workspaceUsers = {
  getConsoleUsers: () => (fb().consoleUser as any).getConsoleUsers(),
  createConsoleUser: (body: any) =>
    (fb().consoleUser as any).createConsoleUser(body),
  getApiUsers: () => (fb().apiUser as any).getApiUsers(),
  createApiUser: (body: any) =>
    (fb().apiUser as any).createApiUser(body),
};

// ─── Cosigners ────────────────────────────────────────────────────────────────
export const cosigners = {
  list: () => fb().cosignersBeta.getCosigners({} as any),
  get: (cosignerId: string) => fb().cosignersBeta.getCosigner({ cosignerId }),
  rename: (cosignerId: string, name: string) =>
    fb().cosignersBeta.renameCosigner({ cosignerId, renameCosigner: { name } } as any),
  getApiKeys: (cosignerId: string) =>
    fb().cosignersBeta.getApiKeys({ cosignerId } as any),
  getApiKey: (cosignerId: string, apiKeyId: string) =>
    fb().cosignersBeta.getApiKey({ cosignerId, apiKeyId } as any),
  pairApiKey: (cosignerId: string, apiKeyId: string) =>
    fb().cosignersBeta.pairApiKey({ cosignerId, apiKeyId, pairApiKeyRequest: {} } as any),
  unpairApiKey: (cosignerId: string, apiKeyId: string) =>
    fb().cosignersBeta.unpairApiKey({ cosignerId, apiKeyId } as any),
};

// ─── Off-Exchange ─────────────────────────────────────────────────────────────
export const offExchange = {
  list: (mainExchangeAccountId: string) =>
    (fb().offExchanges as any).getOffExchangeCollateralAccounts({ mainExchangeAccountId }),
  getSettlements: (mainExchangeAccountId: string) =>
    (fb().offExchanges as any).getOffExchangeSettlementTransactions({ mainExchangeAccountId }),
  settle: (mainExchangeAccountId: string) =>
    (fb().offExchanges as any).settleOffExchangeTrades({ mainExchangeAccountId }),
};

// ─── Webhooks ─────────────────────────────────────────────────────────────────
export const webhooks = {
  resend: (txId?: string) => txId
    ? fb().webhooks.resendTransactionWebhooks({ txId, resendTransactionWebhooksRequest: {} } as any)
    : fb().webhooks.resendWebhooks(),
};

// ─── Whitelisted Wallets ──────────────────────────────────────────────────────
export const whitelisted = {
  listInternal: () => fb().internalWallets.getInternalWallets(),
  listExternal: () => fb().externalWallets.getExternalWallets(),
};

// ─── Network ─────────────────────────────────────────────────────────────────
export const network = {
  list: () => fb().networkConnections.getNetworkConnections(),
  get: (connectionId: string) => fb().networkConnections.getNetwork({ connectionId }),
  getNetworkIds: () => (fb().networkConnections as any).getNetworkIds({}),
  searchNetworkIds: (search: string) =>
    (fb().networkConnections as any).searchNetworkIds({ search }),
};
