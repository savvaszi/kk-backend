/**
 * Sumsub API Service
 *
 * All requests to Sumsub are signed with HMAC-SHA256:
 *   signature = HMAC-SHA256( timestamp + METHOD + path + body, SUMSUB_SECRET_KEY )
 *
 * Required env vars:
 *   SUMSUB_APP_TOKEN   — from Sumsub Dashboard → Developer Space → App tokens
 *   SUMSUB_SECRET_KEY  — paired secret for the app token
 *   SUMSUB_BASE_URL    — https://api.sumsub.com  (or sandbox URL)
 *   SUMSUB_LEVEL_NAME  — your verification level name, e.g. "basic-kyc-level"
 */

import crypto from 'crypto';

const BASE_URL  = process.env.SUMSUB_BASE_URL   || 'https://api.sumsub.com';
const APP_TOKEN = process.env.SUMSUB_APP_TOKEN   || '';
const SECRET    = process.env.SUMSUB_SECRET_KEY  || '';

export const LEVEL_NAME = process.env.SUMSUB_LEVEL_NAME || 'basic-kyc-level';

export function isConfigured(): boolean {
  return !!(APP_TOKEN && SECRET);
}

// ── HMAC signing ──────────────────────────────────────────────────────────────
function sign(method: string, path: string, body: string | null): {
  ts: string; sig: string;
} {
  const ts  = Math.floor(Date.now() / 1000).toString();
  const raw = ts + method.toUpperCase() + path + (body ?? '');
  const sig = crypto.createHmac('sha256', SECRET).update(raw).digest('hex');
  return { ts, sig };
}

// ── Base fetch helper ─────────────────────────────────────────────────────────
async function sumsubFetch<T>(
  method: 'GET' | 'POST' | 'PATCH' | 'DELETE',
  path: string,
  body?: Record<string, unknown> | null,
): Promise<T> {
  const bodyStr  = body ? JSON.stringify(body) : null;
  const { ts, sig } = sign(method, path, bodyStr);

  const headers: Record<string, string> = {
    'X-App-Token':      APP_TOKEN,
    'X-App-Access-Ts':  ts,
    'X-App-Access-Sig': sig,
    'Accept':           'application/json',
  };
  if (bodyStr) headers['Content-Type'] = 'application/json';

  const res = await fetch(`${BASE_URL}${path}`, {
    method,
    headers,
    ...(bodyStr ? { body: bodyStr } : {}),
  });

  if (!res.ok) {
    const text = await res.text().catch(() => '');
    throw new Error(`Sumsub ${method} ${path} → ${res.status}: ${text}`);
  }

  return res.json() as Promise<T>;
}

// ── Create applicant ──────────────────────────────────────────────────────────
/**
 * Creates a new Sumsub applicant linked to your internal user ID.
 * Returns the Sumsub applicant ID.
 */
export async function createApplicant(
  externalUserId: string,
  levelName: string = LEVEL_NAME,
): Promise<{ id: string; externalUserId: string }> {
  const path = `/resources/applicants?levelName=${encodeURIComponent(levelName)}`;
  return sumsubFetch('POST', path, { externalUserId });
}

// ── Generate access token ─────────────────────────────────────────────────────
/**
 * Generates a short-lived token that the frontend uses to initialise the Web SDK.
 * The token is scoped to a specific user and level.
 */
export async function generateAccessToken(
  externalUserId: string,
  levelName: string = LEVEL_NAME,
  ttlInSecs = 1800,
): Promise<{ token: string; userId: string }> {
  const path = `/resources/accessTokens?userId=${encodeURIComponent(externalUserId)}&levelName=${encodeURIComponent(levelName)}&ttlInSecs=${ttlInSecs}`;
  return sumsubFetch('POST', path, null);
}

// ── Get applicant by external user ID ────────────────────────────────────────
export async function getApplicantByExternalId(
  externalUserId: string,
): Promise<Record<string, unknown> | null> {
  try {
    const path = `/resources/applicants/-;externalUserId=${encodeURIComponent(externalUserId)}/one`;
    return sumsubFetch('GET', path);
  } catch {
    return null;
  }
}

// ── Get applicant status ──────────────────────────────────────────────────────
export async function getApplicantStatus(
  applicantId: string,
): Promise<{ reviewStatus: string; reviewResult?: { reviewAnswer: string; rejectLabels?: string[] } }> {
  const path = `/resources/applicants/${applicantId}/requiredIdDocsStatus`;
  return sumsubFetch('GET', path);
}

// ── Get full applicant info ───────────────────────────────────────────────────
export async function getApplicant(applicantId: string): Promise<Record<string, unknown>> {
  return sumsubFetch('GET', `/resources/applicants/${applicantId}/one`);
}

// ── Reset applicant (for sandbox re-testing) ──────────────────────────────────
export async function resetApplicant(applicantId: string): Promise<void> {
  await sumsubFetch('POST', `/resources/applicants/${applicantId}/reset`, null);
}

// ── Verify webhook signature ──────────────────────────────────────────────────
/**
 * Sumsub signs webhooks with HMAC-SHA256 of the raw body using the secret key.
 * The signature is in the X-Payload-Digest header.
 */
export function verifyWebhookSignature(rawBody: Buffer, signature: string | undefined): boolean {
  if (!signature) return false;
  const expected = crypto
    .createHmac('sha256', SECRET)
    .update(rawBody)
    .digest('hex');
  // Constant-time comparison to prevent timing attacks
  try {
    return crypto.timingSafeEqual(Buffer.from(expected, 'hex'), Buffer.from(signature, 'hex'));
  } catch {
    return false;
  }
}
