/**
 * Mailer module — dynamically reads SMTP config from platform_settings DB.
 * Falls back to bundled defaults (mailbaby) when DB settings are absent.
 *
 * Call invalidateMailer() after saving SMTP settings so the next send
 * picks up the new config.
 */

import nodemailer from 'nodemailer';
import { db } from '../db/index.js';
import { platformSettings } from '../db/schema.js';

interface SmtpConfig {
  host: string;
  port: number;
  secure: boolean;
  user: string;
  pass: string;
  from: string;
  recipient: string;
}

// Default / fallback credentials — read from environment variables.
// Never hard-code credentials here; set SMTP_* vars in your deployment env.
const DEFAULTS: SmtpConfig = {
  host:      process.env.SMTP_HOST      || 'relay.mailbaby.net',
  port:      parseInt(process.env.SMTP_PORT || '587', 10),
  secure:    (process.env.SMTP_SECURE   || 'false') === 'true',
  user:      process.env.SMTP_USER      || '',
  pass:      process.env.SMTP_PASS      || '',
  from:      process.env.SMTP_FROM      || '"Krypto Knight" <support@krypto-knight.com>',
  recipient: process.env.SMTP_RECIPIENT || 'info@krypto-knight.com',
};

let _config: SmtpConfig | null = null;

/** Clear the cached config so the next send re-reads from DB. */
export function invalidateMailer() {
  _config = null;
}

async function loadConfig(): Promise<SmtpConfig> {
  if (_config) return _config;
  try {
    const rows = await db.select().from(platformSettings);
    const s = Object.fromEntries(rows.map(r => [r.key, r.value]));
    _config = {
      host:      s.smtp_host      || DEFAULTS.host,
      port:      parseInt(s.smtp_port || String(DEFAULTS.port), 10),
      secure:    (s.smtp_secure  ?? 'false') === 'true',
      user:      s.smtp_user      || DEFAULTS.user,
      pass:      s.smtp_pass      || DEFAULTS.pass,
      from:      s.smtp_from      || DEFAULTS.from,
      recipient: s.smtp_recipient || DEFAULTS.recipient,
    };
  } catch {
    _config = { ...DEFAULTS };
  }
  return _config;
}

function buildTransport(cfg: SmtpConfig) {
  return nodemailer.createTransport({
    host: cfg.host,
    port: cfg.port,
    secure: cfg.secure,
    auth: cfg.user ? { user: cfg.user, pass: cfg.pass } : undefined,
    tls: { rejectUnauthorized: false },
  });
}

/** Send an email using DB-configured SMTP settings. */
export async function sendMail(opts: {
  to: string | string[];
  subject: string;
  html: string;
  replyTo?: string;
  attachments?: any[];
}) {
  const cfg = await loadConfig();
  const t = buildTransport(cfg);
  return t.sendMail({ from: cfg.from, ...opts });
}

/** Return the configured admin recipient address. */
export async function getRecipient(): Promise<string> {
  return (await loadConfig()).recipient;
}

/**
 * Test arbitrary SMTP settings (used by the admin test endpoint).
 * Verifies the connection and sends a test email to `toEmail`.
 */
export async function testSmtp(
  cfg: Partial<SmtpConfig>,
  toEmail: string
): Promise<void> {
  const merged: SmtpConfig = { ...DEFAULTS, ...cfg };
  const t = buildTransport(merged);
  await t.verify();          // throws on bad credentials / unreachable host
  await t.sendMail({
    from: merged.from,
    to: toEmail,
    subject: 'Krypto Knight — SMTP Test',
    html: `<div style="font-family:sans-serif;padding:24px">
      <h2 style="color:#00e676">✓ SMTP Test Successful</h2>
      <p>Your SMTP configuration is working correctly.</p>
      <p style="color:#888;font-size:12px">Host: ${merged.host}:${merged.port} · Secure: ${merged.secure}</p>
    </div>`,
  });
}

// ── Legacy compat (for any remaining code that imports these names) ───────────
export const transporter = {
  sendMail: async (opts: any) => {
    const cfg = await loadConfig();
    return buildTransport(cfg).sendMail(opts);
  },
  verify: async () => {
    const cfg = await loadConfig();
    return buildTransport(cfg).verify();
  },
};
export const RECIPIENT = DEFAULTS.recipient;
export const FROM      = DEFAULTS.from;
