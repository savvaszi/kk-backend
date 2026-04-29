import postgres from 'postgres';
import { drizzle } from 'drizzle-orm/postgres-js';
import * as schema from './schema.js';

const connectionString = process.env.DATABASE_URL!;

export const sql = postgres(connectionString, { max: 10 });
export const db = drizzle(sql, { schema });

export async function initDb() {
  await sql`
    CREATE TABLE IF NOT EXISTS users (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      email VARCHAR(255) UNIQUE NOT NULL,
      username VARCHAR(100) UNIQUE NOT NULL,
      password_hash VARCHAR(255) NOT NULL,
      first_name VARCHAR(100),
      last_name VARCHAR(100),
      phone VARCHAR(50),
      bio TEXT,
      country VARCHAR(100),
      state VARCHAR(100),
      city VARCHAR(100),
      zip VARCHAR(20),
      street_address VARCHAR(255),
      twitter VARCHAR(100),
      github VARCHAR(100),
      instagram VARCHAR(100),
      telegram VARCHAR(100),
      level SMALLINT DEFAULT 0 NOT NULL,
      status VARCHAR(20) DEFAULT 'pending' NOT NULL,
      security_score SMALLINT DEFAULT 0 NOT NULL,
      email_verified BOOLEAN DEFAULT FALSE NOT NULL,
      phone_verified BOOLEAN DEFAULT FALSE NOT NULL,
      two_fa_enabled BOOLEAN DEFAULT FALSE NOT NULL,
      two_fa_secret VARCHAR(255),
      email_notifications BOOLEAN DEFAULT TRUE NOT NULL,
      sms_notifications BOOLEAN DEFAULT FALSE NOT NULL,
      push_notifications BOOLEAN DEFAULT FALSE NOT NULL,
      is_admin BOOLEAN DEFAULT FALSE NOT NULL,
      fireblocks_vault_id VARCHAR(100),
      created_at TIMESTAMPTZ DEFAULT NOW() NOT NULL,
      updated_at TIMESTAMPTZ DEFAULT NOW() NOT NULL,
      last_seen_at TIMESTAMPTZ DEFAULT NOW() NOT NULL
    )
  `;

  await sql`
    CREATE TABLE IF NOT EXISTS user_sessions (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      token_hash VARCHAR(255) NOT NULL,
      device VARCHAR(255),
      ip_address VARCHAR(50),
      location VARCHAR(255),
      is_current BOOLEAN DEFAULT FALSE NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW() NOT NULL,
      last_active_at TIMESTAMPTZ DEFAULT NOW() NOT NULL,
      expires_at TIMESTAMPTZ NOT NULL
    )
  `;

  await sql`
    CREATE TABLE IF NOT EXISTS api_keys (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      key_id VARCHAR(50) UNIQUE NOT NULL,
      key_hash VARCHAR(255) NOT NULL,
      name VARCHAR(255) NOT NULL,
      permissions JSONB DEFAULT '[]' NOT NULL,
      status VARCHAR(20) DEFAULT 'active' NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW() NOT NULL,
      last_used_at TIMESTAMPTZ
    )
  `;

  await sql`
    CREATE TABLE IF NOT EXISTS wallets (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      address VARCHAR(255) NOT NULL,
      wallet_type VARCHAR(50),
      chain_id SMALLINT,
      is_primary BOOLEAN DEFAULT FALSE NOT NULL,
      connected_at TIMESTAMPTZ DEFAULT NOW() NOT NULL
    )
  `;

  await sql`
    CREATE TABLE IF NOT EXISTS audit_logs (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      user_id UUID REFERENCES users(id) ON DELETE SET NULL,
      user_name VARCHAR(255),
      action VARCHAR(255) NOT NULL,
      detail TEXT,
      type VARCHAR(50),
      severity VARCHAR(20),
      ip_address VARCHAR(50),
      metadata JSONB,
      created_at TIMESTAMPTZ DEFAULT NOW() NOT NULL
    )
  `;

  await sql`
    CREATE TABLE IF NOT EXISTS admin_notifications (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      title VARCHAR(255) NOT NULL,
      body TEXT NOT NULL,
      type VARCHAR(20) DEFAULT 'info' NOT NULL,
      is_read BOOLEAN DEFAULT FALSE NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW() NOT NULL
    )
  `;

  await sql`
    CREATE TABLE IF NOT EXISTS platform_settings (
      key VARCHAR(100) PRIMARY KEY,
      value TEXT NOT NULL,
      updated_at TIMESTAMPTZ DEFAULT NOW() NOT NULL
    )
  `;

  await sql`
    CREATE TABLE IF NOT EXISTS fireblocks_events (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      fireblocks_event_id VARCHAR(100),
      tx_id VARCHAR(100),
      event_type VARCHAR(100) NOT NULL,
      tx_status VARCHAR(50),
      asset_id VARCHAR(50),
      amount VARCHAR(50),
      net_amount VARCHAR(50),
      fee VARCHAR(50),
      source_type VARCHAR(50),
      source_id VARCHAR(100),
      destination_type VARCHAR(50),
      destination_id VARCHAR(100),
      destination_address VARCHAR(255),
      vault_id VARCHAR(100),
      user_id UUID REFERENCES users(id) ON DELETE SET NULL,
      direction VARCHAR(20),
      signature_valid BOOLEAN DEFAULT FALSE NOT NULL,
      raw_payload JSONB,
      created_at TIMESTAMPTZ DEFAULT NOW() NOT NULL
    )
  `;

  // Safe column migrations
  await sql`ALTER TABLE users ADD COLUMN IF NOT EXISTS fireblocks_vault_id VARCHAR(100)`;
  await sql`ALTER TABLE users ADD COLUMN IF NOT EXISTS sumsub_applicant_id VARCHAR(100)`;
  await sql`ALTER TABLE users ADD COLUMN IF NOT EXISTS kyc_status VARCHAR(20) DEFAULT 'none' NOT NULL`;
  await sql`ALTER TABLE users ADD COLUMN IF NOT EXISTS kyc_level VARCHAR(100)`;
  await sql`ALTER TABLE users ADD COLUMN IF NOT EXISTS kyc_reviewed_at TIMESTAMPTZ`;
  await sql`ALTER TABLE users ADD COLUMN IF NOT EXISTS password_reset_token VARCHAR(255)`;
  await sql`ALTER TABLE users ADD COLUMN IF NOT EXISTS password_reset_expires_at TIMESTAMPTZ`;
  await sql`ALTER TABLE users ADD COLUMN IF NOT EXISTS two_fa_backup_codes JSONB`;

  // Seed default platform settings
  await sql`
    INSERT INTO platform_settings (key, value) VALUES
      ('platform_name', 'KryptoKnight'),
      ('support_email', 'support@krypto-knight.com'),
      ('maintenance_mode', 'false'),
      ('new_registrations', 'true'),
      ('min_security_score', '40'),
      ('session_timeout_mins', '60'),
      ('force_2fa_withdrawals', 'true'),
      ('auto_ban_below_threshold', 'false'),
      ('admin_alert_email', 'admin@krypto-knight.com'),
      ('security_alerts', 'true'),
      ('new_user_alerts', 'false'),
      ('api_abuse_alerts', 'true')
    ON CONFLICT (key) DO NOTHING
  `;

  // Seed admin user if ADMIN_EMAIL is set
  const adminEmail = process.env.ADMIN_EMAIL;
  const adminPassword = process.env.ADMIN_PASSWORD;
  if (adminEmail && adminPassword) {
    const { hashPassword } = await import('../lib/password.js');
    const hash = await hashPassword(adminPassword);
    await sql`
      INSERT INTO users (email, username, password_hash, first_name, status, is_admin, email_verified, security_score)
      VALUES (${adminEmail}, 'admin', ${hash}, 'Admin', 'active', TRUE, TRUE, 100)
      ON CONFLICT (email) DO NOTHING
    `;
  }

  console.log('Database initialized');
}
