import { pgTable, uuid, varchar, boolean, smallint, text, jsonb, timestamp } from 'drizzle-orm/pg-core';

export const users = pgTable('users', {
  id: uuid('id').primaryKey().defaultRandom(),
  email: varchar('email', { length: 255 }).unique().notNull(),
  username: varchar('username', { length: 100 }).unique().notNull(),
  passwordHash: varchar('password_hash', { length: 255 }).notNull(),
  firstName: varchar('first_name', { length: 100 }),
  lastName: varchar('last_name', { length: 100 }),
  phone: varchar('phone', { length: 50 }),
  bio: text('bio'),
  country: varchar('country', { length: 100 }),
  state: varchar('state', { length: 100 }),
  city: varchar('city', { length: 100 }),
  zip: varchar('zip', { length: 20 }),
  streetAddress: varchar('street_address', { length: 255 }),
  twitter: varchar('twitter', { length: 100 }),
  github: varchar('github', { length: 100 }),
  instagram: varchar('instagram', { length: 100 }),
  telegram: varchar('telegram', { length: 100 }),
  level: smallint('level').default(0).notNull(),
  status: varchar('status', { length: 20 }).default('pending').notNull(),
  securityScore: smallint('security_score').default(0).notNull(),
  emailVerified: boolean('email_verified').default(false).notNull(),
  phoneVerified: boolean('phone_verified').default(false).notNull(),
  twoFaEnabled: boolean('two_fa_enabled').default(false).notNull(),
  twoFaSecret: varchar('two_fa_secret', { length: 255 }),
  emailNotifications: boolean('email_notifications').default(true).notNull(),
  smsNotifications: boolean('sms_notifications').default(false).notNull(),
  pushNotifications: boolean('push_notifications').default(false).notNull(),
  isAdmin: boolean('is_admin').default(false).notNull(),
  fireblocksVaultId: varchar('fireblocks_vault_id', { length: 100 }),
  // KYC / Sumsub
  sumsubApplicantId: varchar('sumsub_applicant_id', { length: 100 }),
  kycStatus: varchar('kyc_status', { length: 20 }).default('none').notNull(),  // none | pending | approved | rejected
  kycLevel: varchar('kyc_level', { length: 100 }),
  kycReviewedAt: timestamp('kyc_reviewed_at', { withTimezone: true }),
  passwordResetToken: varchar('password_reset_token', { length: 255 }),
  passwordResetExpiresAt: timestamp('password_reset_expires_at', { withTimezone: true }),
  twoFaBackupCodes: jsonb('two_fa_backup_codes').$type<string[]>(),
  createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
  updatedAt: timestamp('updated_at', { withTimezone: true }).defaultNow().notNull(),
  lastSeenAt: timestamp('last_seen_at', { withTimezone: true }).defaultNow().notNull(),
});

export const userSessions = pgTable('user_sessions', {
  id: uuid('id').primaryKey().defaultRandom(),
  userId: uuid('user_id').notNull().references(() => users.id, { onDelete: 'cascade' }),
  tokenHash: varchar('token_hash', { length: 255 }).notNull(),
  device: varchar('device', { length: 255 }),
  ipAddress: varchar('ip_address', { length: 50 }),
  location: varchar('location', { length: 255 }),
  isCurrent: boolean('is_current').default(false).notNull(),
  createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
  lastActiveAt: timestamp('last_active_at', { withTimezone: true }).defaultNow().notNull(),
  expiresAt: timestamp('expires_at', { withTimezone: true }).notNull(),
});

export const apiKeys = pgTable('api_keys', {
  id: uuid('id').primaryKey().defaultRandom(),
  userId: uuid('user_id').notNull().references(() => users.id, { onDelete: 'cascade' }),
  keyId: varchar('key_id', { length: 50 }).unique().notNull(),
  keyHash: varchar('key_hash', { length: 255 }).notNull(),
  name: varchar('name', { length: 255 }).notNull(),
  permissions: jsonb('permissions').notNull().$type<string[]>().default([]),
  status: varchar('status', { length: 20 }).default('active').notNull(),
  createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
  lastUsedAt: timestamp('last_used_at', { withTimezone: true }),
});

export const wallets = pgTable('wallets', {
  id: uuid('id').primaryKey().defaultRandom(),
  userId: uuid('user_id').notNull().references(() => users.id, { onDelete: 'cascade' }),
  address: varchar('address', { length: 255 }).notNull(),
  walletType: varchar('wallet_type', { length: 50 }),
  chainId: smallint('chain_id'),
  isPrimary: boolean('is_primary').default(false).notNull(),
  connectedAt: timestamp('connected_at', { withTimezone: true }).defaultNow().notNull(),
});

export const auditLogs = pgTable('audit_logs', {
  id: uuid('id').primaryKey().defaultRandom(),
  userId: uuid('user_id').references(() => users.id, { onDelete: 'set null' }),
  userName: varchar('user_name', { length: 255 }),
  action: varchar('action', { length: 255 }).notNull(),
  detail: text('detail'),
  type: varchar('type', { length: 50 }),
  severity: varchar('severity', { length: 20 }),
  ipAddress: varchar('ip_address', { length: 50 }),
  metadata: jsonb('metadata'),
  createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
});

export const adminNotifications = pgTable('admin_notifications', {
  id: uuid('id').primaryKey().defaultRandom(),
  title: varchar('title', { length: 255 }).notNull(),
  body: text('body').notNull(),
  type: varchar('type', { length: 20 }).default('info').notNull(),
  isRead: boolean('is_read').default(false).notNull(),
  createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
});

export const platformSettings = pgTable('platform_settings', {
  key: varchar('key', { length: 100 }).primaryKey(),
  value: text('value').notNull(),
  updatedAt: timestamp('updated_at', { withTimezone: true }).defaultNow().notNull(),
});

export const fireblocksEvents = pgTable('fireblocks_events', {
  id: uuid('id').primaryKey().defaultRandom(),
  // Fireblocks-provided identifiers
  fireblocksEventId: varchar('fireblocks_event_id', { length: 100 }),
  txId: varchar('tx_id', { length: 100 }),
  eventType: varchar('event_type', { length: 100 }).notNull(),
  // Transaction details (populated for TRANSACTION_* events)
  txStatus: varchar('tx_status', { length: 50 }),
  assetId: varchar('asset_id', { length: 50 }),
  amount: varchar('amount', { length: 50 }),
  netAmount: varchar('net_amount', { length: 50 }),
  fee: varchar('fee', { length: 50 }),
  sourceType: varchar('source_type', { length: 50 }),
  sourceId: varchar('source_id', { length: 100 }),
  destinationType: varchar('destination_type', { length: 50 }),
  destinationId: varchar('destination_id', { length: 100 }),
  destinationAddress: varchar('destination_address', { length: 255 }),
  // Linked entities
  vaultId: varchar('vault_id', { length: 100 }),
  userId: uuid('user_id').references(() => users.id, { onDelete: 'set null' }),
  // Direction: 'deposit' | 'withdrawal' | 'internal' | 'unknown'
  direction: varchar('direction', { length: 20 }),
  // Verification
  signatureValid: boolean('signature_valid').default(false).notNull(),
  // Full raw payload for audit trail (DORA Art. 17 requirement)
  rawPayload: jsonb('raw_payload'),
  createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
});
