import crypto from 'crypto';
import bcrypt from 'bcryptjs';

export function generateKeyId(): string {
  const rand = crypto.randomBytes(8).toString('hex');
  return `kk_live_${rand}`;
}

export function generateRawKey(): string {
  return crypto.randomBytes(32).toString('hex');
}

export const hashKey = (raw: string) => bcrypt.hash(raw, 10);
export const verifyKey = (raw: string, hash: string) => bcrypt.compare(raw, hash);
