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

// ─── Webhooks (V1) ───────────────────────────────────────────────────────────
export const webhooks = {
  resend: (txId?: string) => txId
    ? fb().webhooks.resendTransactionWebhooks({ txId, resendTransactionWebhooksRequest: {} } as any)
    : fb().webhooks.resendWebhooks(),
};

// ─── Webhooks V2 ─────────────────────────────────────────────────────────────
export const webhooksV2 = {
  list: () => (fb().webhooksV2 as any).getWebhooks({}),
  get: (webhookId: string) => (fb().webhooksV2 as any).getWebhook({ webhookId }),
  create: (body: any) => (fb().webhooksV2 as any).createWebhook(body),
  update: (webhookId: string, body: any) => (fb().webhooksV2 as any).updateWebhook({ webhookId, ...body }),
  delete: (webhookId: string) => (fb().webhooksV2 as any).deleteWebhook({ webhookId }),
  getMetrics: () => (fb().webhooksV2 as any).getMetrics({}),
  getNotifications: (webhookId: string) => (fb().webhooksV2 as any).getNotifications({ webhookId }),
  resendById: (webhookId: string, notificationId: string) =>
    (fb().webhooksV2 as any).resendNotificationById({ webhookId, notificationId }),
  resendFailed: (webhookId: string) => (fb().webhooksV2 as any).resendFailedNotifications({ webhookId }),
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

// ─── Web3 Connections (WalletConnect) ────────────────────────────────────────
export const web3 = {
  list: (params?: any) => (fb().web3Connections as any).get({ ...(params ?? {}) }),
  get: (id: string) => (fb().web3Connections as any).get({ id }),
  create: (uri: string, vaultAccountId: number) =>
    (fb().web3Connections as any).create({ createWeb3ConnectionRequest: { uri, vaultAccountId } }),
  submit: (id: string, approve: boolean) =>
    (fb().web3Connections as any).submit({ id, respondToConnectionRequest: { approve } }),
  remove: (id: string) => (fb().web3Connections as any).remove({ id }),
};

// ─── Travel Rule ─────────────────────────────────────────────────────────────
export const travelRule = {
  getVASPs: (params?: any) => (fb().travelRule as any).getVASPs({ ...(params ?? {}) }),
  getVASP: (did: string) => (fb().travelRule as any).getVASPByDID({ did }),
  updateVASP: (body: any) => (fb().travelRule as any).updateVasp(body),
  setVaspForVault: (vaultAccountId: string, vaspDid: string) =>
    (fb().travelRule as any).setVaspForVault({ vaultAccountId, vaspDid }),
  getVaspForVault: (vaultAccountId: string) =>
    (fb().travelRule as any).getVaspForVault({ vaultAccountId }),
  validateTransaction: (body: any) =>
    (fb().travelRule as any).validateFullTravelRuleTransaction(body),
  createProofOfAddress: (body: any) =>
    (fb().travelRule as any).createTrustProofOfAddress(body),
  getProofOfAddress: (address: string) =>
    (fb().travelRule as any).getTrustProofOfAddress({ address }),
};

// ─── Tokenization ─────────────────────────────────────────────────────────────
export const tokenization = {
  listCollections: () => (fb().tokenization as any).getLinkedCollections({}),
  getCollection: (id: string) => (fb().tokenization as any).getCollectionById({ id }),
  createCollection: (body: any) => (fb().tokenization as any).createNewCollection(body),
  issueToken: (body: any) => (fb().tokenization as any).issueNewToken(body),
  issueMultiChain: (body: any) => (fb().tokenization as any).issueTokenMultiChain(body),
  mintToken: (collectionId: string, body: any) =>
    (fb().tokenization as any).mintCollectionToken({ collectionId, ...body }),
  burnToken: (collectionId: string, body: any) =>
    (fb().tokenization as any).burnCollectionToken({ collectionId, ...body }),
  getTokenDetails: (collectionId: string, tokenId: string) =>
    (fb().tokenization as any).fetchCollectionTokenDetails({ collectionId, tokenId }),
  listLinkedTokens: () => (fb().tokenization as any).getLinkedTokens({}),
  getLinkedToken: (id: string) => (fb().tokenization as any).getLinkedToken({ id }),
  link: (body: any) => (fb().tokenization as any).link(body),
  unlink: (id: string) => (fb().tokenization as any).unlink({ id }),
  getDeployableAddress: (body: any) => (fb().tokenization as any).getDeployableAddress(body),
};

// ─── Smart Transfer ───────────────────────────────────────────────────────────
export const smartTransfer = {
  list: (params?: any) => (fb().smartTransfer as any).searchTickets({ ...(params ?? {}) }),
  get: (ticketId: string) => (fb().smartTransfer as any).findTicketById({ ticketId }),
  create: (body: any) => (fb().smartTransfer as any).createTicket(body),
  submit: (ticketId: string) => (fb().smartTransfer as any).submitTicket({ ticketId }),
  cancel: (ticketId: string) => (fb().smartTransfer as any).cancelTicket({ ticketId }),
  fulfill: (ticketId: string) => (fb().smartTransfer as any).fulfillTicket({ ticketId }),
  setExpiration: (ticketId: string, expiresAt: string) =>
    (fb().smartTransfer as any).setTicketExpiration({ ticketId, smartTransferSetTicketExpiration: { expiresAt } }),
  createTerm: (ticketId: string, body: any) =>
    (fb().smartTransfer as any).createTicketTerm({ ticketId, ...body }),
  getTerm: (ticketId: string, termId: string) =>
    (fb().smartTransfer as any).findTicketTermById({ ticketId, termId }),
  updateTerm: (ticketId: string, termId: string, body: any) =>
    (fb().smartTransfer as any).updateTicketTerm({ ticketId, termId, ...body }),
  removeTerm: (ticketId: string, termId: string) =>
    (fb().smartTransfer as any).removeTicketTerm({ ticketId, termId }),
  fundTerm: (ticketId: string, termId: string) =>
    (fb().smartTransfer as any).fundTicketTerm({ ticketId, termId }),
  getStatistics: () => (fb().smartTransfer as any).getSmartTransferStatistic({}),
  getUserGroups: () => (fb().smartTransfer as any).getSmartTransferUserGroups({}),
  setUserGroups: (body: any) => (fb().smartTransfer as any).setUserGroups(body),
};

// ─── Key Link (Signing / Validation Keys) ────────────────────────────────────
export const keyLink = {
  listSigningKeys: () => (fb().keyLinkBeta as any).getSigningKeysList({}),
  getSigningKey: (signingKeyId: string) => (fb().keyLinkBeta as any).getSigningKey({ signingKeyId }),
  createSigningKey: (body: any) => (fb().keyLinkBeta as any).createSigningKey(body),
  updateSigningKey: (signingKeyId: string, body: any) =>
    (fb().keyLinkBeta as any).updateSigningKey({ signingKeyId, ...body }),
  setAgentId: (signingKeyId: string, agentUserId: string) =>
    (fb().keyLinkBeta as any).setAgentId({ signingKeyId, agentUserId }),
  listValidationKeys: () => (fb().keyLinkBeta as any).getValidationKeysList({}),
  getValidationKey: (keyId: string) => (fb().keyLinkBeta as any).getValidationKey({ keyId }),
  createValidationKey: (body: any) => (fb().keyLinkBeta as any).createValidationKey(body),
  disableValidationKey: (keyId: string, body: any) =>
    (fb().keyLinkBeta as any).disableValidationKey({ keyId, ...body }),
};

// ─── Payments / Payout ────────────────────────────────────────────────────────
export const payments = {
  createPayout: (body: any) => (fb().paymentsPayout as any).createPayout(body),
  getPayout: (payoutId: string) => (fb().paymentsPayout as any).getPayout({ payoutId }),
  executeAction: (payoutId: string, action: string) =>
    (fb().paymentsPayout as any).executePayoutAction({ payoutId, payoutAction: { action } }),
};

// ─── Tags ─────────────────────────────────────────────────────────────────────
export const tags = {
  list: () => (fb().tags as any).getTags({}),
  get: (tagId: string) => (fb().tags as any).getTag({ tagId }),
  create: (name: string) => (fb().tags as any).createTag({ tagBody: { name } }),
  update: (tagId: string, name: string) => (fb().tags as any).updateTag({ tagId, tagBody: { name } }),
  delete: (tagId: string) => (fb().tags as any).deleteTag({ tagId }),
};

// ─── User Groups ──────────────────────────────────────────────────────────────
export const userGroups = {
  list: () => (fb().userGroupsBeta as any).getUserGroups({}),
  get: (groupId: string) => (fb().userGroupsBeta as any).getUserGroup({ groupId }),
  create: (body: any) => (fb().userGroupsBeta as any).createUserGroup(body),
  update: (groupId: string, body: any) => (fb().userGroupsBeta as any).updateUserGroup({ groupId, ...body }),
  delete: (groupId: string) => (fb().userGroupsBeta as any).deleteUserGroup({ groupId }),
};

// ─── Trading ──────────────────────────────────────────────────────────────────
export const trading = {
  getProviders: () => (fb().tradingBeta as any).getTradingProviders({}),
  getProvider: (providerId: string) => (fb().tradingBeta as any).getTradingProviderById({ providerId }),
  createOrder: (body: any) => (fb().tradingBeta as any).createOrder(body),
  getOrder: (orderId: string) => (fb().tradingBeta as any).getOrder({ orderId }),
  listOrders: (params?: any) => (fb().tradingBeta as any).getOrders({ ...(params ?? {}) }),
  createQuote: (body: any) => (fb().tradingBeta as any).createQuote(body),
};

// ─── Connected Accounts ───────────────────────────────────────────────────────
export const connectedAccounts = {
  list: () => (fb().connectedAccountsBeta as any).getConnectedAccounts({}),
  get: (accountId: string) => (fb().connectedAccountsBeta as any).getConnectedAccount({ accountId }),
  rename: (accountId: string, name: string) =>
    (fb().connectedAccountsBeta as any).renameConnectedAccount({ accountId, renameConnectedAccountRequest: { name } }),
  getBalances: (accountId: string) => (fb().connectedAccountsBeta as any).getConnectedAccountBalances({ accountId }),
  getRates: (accountId: string) => (fb().connectedAccountsBeta as any).getConnectedAccountRates({ accountId }),
  getTradingPairs: (accountId: string) => (fb().connectedAccountsBeta as any).getConnectedAccountTradingPairs({ accountId }),
  disconnect: (accountId: string) => (fb().connectedAccountsBeta as any).disconnectConnectedAccount({ accountId }),
};

// ─── On-Chain Data ────────────────────────────────────────────────────────────
export const onchainData = {
  getRegistryState: (body: any) => (fb().onchainData as any).getAccessRegistryCurrentState(body),
  getRegistrySummary: (body: any) => (fb().onchainData as any).getAccessRegistrySummary(body),
  getContractBalances: (contractAddress: string, assetId: string) =>
    (fb().onchainData as any).getContractBalancesSummary({ contractAddress, assetId }),
  getContractBalanceHistory: (body: any) => (fb().onchainData as any).getContractBalanceHistory(body),
  getContractSupply: (contractAddress: string, assetId: string) =>
    (fb().onchainData as any).getContractTotalSupply({ contractAddress, assetId }),
  getOnchainTransactions: (body: any) => (fb().onchainData as any).getOnchainTransactions(body),
};

// ─── UTXO Management ──────────────────────────────────────────────────────────
export const utxo = {
  list: (params?: any) => (fb().utxoManagementBeta as any).getUtxos({ ...(params ?? {}) }),
  updateLabels: (body: any) => (fb().utxoManagementBeta as any).updateUtxoLabels(body),
};

// ─── Whitelisted Contracts ────────────────────────────────────────────────────
export const whitelistedContracts = {
  list: () => (fb().contracts as any).getContracts({}),
  get: (contractId: string) => (fb().contracts as any).getContract({ contractId }),
  create: (body: any) => (fb().contracts as any).createContract(body),
  delete: (contractId: string) => (fb().contracts as any).deleteContract({ contractId }),
  addAsset: (contractId: string, assetId: string, body: any) =>
    (fb().contracts as any).addContractAsset({ contractId, assetId, ...body }),
  getAsset: (contractId: string, assetId: string) =>
    (fb().contracts as any).getContractAsset({ contractId, assetId }),
  deleteAsset: (contractId: string, assetId: string) =>
    (fb().contracts as any).deleteContractAsset({ contractId, assetId }),
};

// ─── MPC Keys ─────────────────────────────────────────────────────────────────
export const mpcKeys = {
  list: () => (fb().keysBeta as any).getMpcKeysList({}),
  listByUser: (userId: string) => (fb().keysBeta as any).getMpcKeysListByUser({ userId }),
};

// ─── Workspace ────────────────────────────────────────────────────────────────
export const workspace = {
  get: () => (fb().workspace as any).getWorkspace({}),
  getStatus: () => (fb().workspaceStatusBeta as any).getWorkspaceStatus({}),
  getUsers: () => (fb().users as any).getUsers({}),
  getWhitelistIps: () => (fb().whitelistIpAddresses as any).getWhitelistIpAddresses({}),
};

// ─── OTA / Device Management ──────────────────────────────────────────────────
export const deviceMgmt = {
  getOtaStatus: (walletId: string) => (fb().otaBeta as any).getOtaStatus({ walletId }),
  setOtaStatus: (walletId: string, enabled: boolean) =>
    (fb().otaBeta as any).setOtaStatus({ walletId, setOtaStatusRequest: { enabled } }),
  resetDevice: (walletId: string, deviceId: string) =>
    (fb().resetDevice as any).resetDevice({ walletId, deviceId }),
};

// ─── Legacy Policy Editor (V1) ────────────────────────────────────────────────
export const policyLegacy = {
  getActive: () => (fb().policyEditorBeta as any).getActivePolicyLegacy({}),
  getDraft: () => (fb().policyEditorBeta as any).getDraftLegacy({}),
  publishDraft: () => (fb().policyEditorBeta as any).publishDraftLegacy({}),
  publishRules: (body: any) => (fb().policyEditorBeta as any).publishPolicyRules(body),
  updateDraft: (body: any) => (fb().policyEditorBeta as any).updateDraftLegacy(body),
};

// ─── TR-Link ──────────────────────────────────────────────────────────────────
export const trLink = {
  getPartners: () => (fb().trLink as any).getTRLinkPartners({}),
  getPolicy: () => (fb().trLink as any).getTRLinkPolicy({}),
  listIntegrations: () => (fb().trLink as any).getTRLinkCustomerIntegrations({}),
  createIntegration: (body: any) => (fb().trLink as any).createTRLinkIntegration(body),
  connectIntegration: (integrationId: string, body: any) =>
    (fb().trLink as any).connectTRLinkIntegration({ integrationId, ...body }),
  disconnectIntegration: (integrationId: string) =>
    (fb().trLink as any).disconnectTRLinkIntegration({ integrationId }),
  testConnection: (integrationId: string) =>
    (fb().trLink as any).testTRLinkIntegrationConnection({ integrationId }),
  getPublicKey: (integrationId: string) =>
    (fb().trLink as any).getTRLinkIntegrationPublicKey({ integrationId }),
  listCustomers: () => (fb().trLink as any).getTRLinkCustomers({}),
  getCustomer: (customerId: string) => (fb().trLink as any).getTRLinkCustomerById({ customerId }),
  createCustomer: (body: any) => (fb().trLink as any).createTRLinkCustomer(body),
  updateCustomer: (customerId: string, body: any) =>
    (fb().trLink as any).updateTRLinkCustomer({ customerId, ...body }),
  deleteCustomer: (customerId: string) => (fb().trLink as any).deleteTRLinkCustomer({ customerId }),
  listVasps: () => (fb().trLink as any).listTRLinkVasps({}),
  getVasp: (vaspId: string) => (fb().trLink as any).getTRLinkVaspById({ vaspId }),
  listSupportedAssets: () => (fb().trLink as any).listTRLinkSupportedAssets({}),
  assessRequirement: (body: any) => (fb().trLink as any).assessTRLinkTravelRuleRequirement(body),
  createTrm: (body: any) => (fb().trLink as any).createTRLinkTrm(body),
  getTrm: (trmId: string) => (fb().trLink as any).getTRLinkTrmById({ trmId }),
  redirectTrm: (trmId: string, body: any) => (fb().trLink as any).redirectTRLinkTrm({ trmId, ...body }),
  cancelTrm: (trmId: string) => (fb().trLink as any).cancelTRLinkTrm({ trmId }),
};
